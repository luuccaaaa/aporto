package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

var subdomainRegexp = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Tunnel represents a persisted tunnel definition.
type Tunnel struct {
	ID             string
	Name           string
	Subdomain      string
	SecretHash     string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	LastSeenAt     sql.NullTime
	KeyFingerprint sql.NullString
}

// Store wraps the sqlite DB.
type Store struct {
	db *sql.DB
}

// Open initialises (and migrates) the sqlite database.
func Open(ctx context.Context, path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)

	s := &Store{db: db}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate(ctx context.Context) error {
	const ddl = `
	CREATE TABLE IF NOT EXISTS tunnels (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL UNIQUE,
		subdomain TEXT NOT NULL UNIQUE,
		secret_hash TEXT NOT NULL,
		key_fingerprint TEXT UNIQUE,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		last_seen TIMESTAMP
	);
	`
	if _, err := s.db.ExecContext(ctx, ddl); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	const addColumn = `ALTER TABLE tunnels ADD COLUMN key_fingerprint TEXT;`
	if _, err := s.db.ExecContext(ctx, addColumn); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		return fmt.Errorf("migrate add key column: %w", err)
	}
	const keyIndex = `CREATE UNIQUE INDEX IF NOT EXISTS idx_tunnels_key_fingerprint ON tunnels(key_fingerprint);`
	if _, err := s.db.ExecContext(ctx, keyIndex); err != nil {
		return fmt.Errorf("create key index: %w", err)
	}
	return nil
}

// CreateTunnel registers a new tunnel with a freshly generated secret.
func (s *Store) CreateTunnel(ctx context.Context, name, requestedSubdomain string) (*Tunnel, string, error) {
	if strings.TrimSpace(name) == "" {
		return nil, "", fmt.Errorf("name is required")
	}

	subdomain := normalizeSubdomain(name, requestedSubdomain)
	if !subdomainRegexp.MatchString(subdomain) {
		return nil, "", fmt.Errorf("invalid subdomain %q", subdomain)
	}

	secret, err := generateSecret()
	if err != nil {
		return nil, "", err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return nil, "", fmt.Errorf("hash secret: %w", err)
	}

	tunnel := &Tunnel{
		ID:        uuid.NewString(),
		Name:      name,
		Subdomain: subdomain,
	}

	const insert = `
	INSERT INTO tunnels (id, name, subdomain, secret_hash)
	VALUES (?, ?, ?, ?);`

	if _, err := s.db.ExecContext(ctx, insert, tunnel.ID, tunnel.Name, tunnel.Subdomain, string(hash)); err != nil {
		return nil, "", fmt.Errorf("insert tunnel: %w", err)
	}

	return tunnel, secret, nil
}

// CreateTunnelAuto creates a tunnel, generating a unique subdomain if not provided.
func (s *Store) CreateTunnelAuto(ctx context.Context, name, requestedSubdomain string) (*Tunnel, string, error) {
	if strings.TrimSpace(requestedSubdomain) != "" {
		return s.CreateTunnel(ctx, name, requestedSubdomain)
	}
	base := normalizeSubdomain(name, requestedSubdomain)
	if base == "" {
		base = "tunnel"
	}
	for i := 0; i < 10; i++ {
		subdomain := base
		if i > 0 {
			subdomain = fmt.Sprintf("%s-%s", base, randomSuffix(4))
		}
		t, secret, err := s.CreateTunnel(ctx, name, subdomain)
		if err == nil {
			return t, secret, nil
		}
		if !isUniqueConstraint(err) {
			return nil, "", err
		}
	}
	return nil, "", fmt.Errorf("failed to allocate unique subdomain for %q", name)
}

// ListTunnels returns all tunnels sorted by creation time.
func (s *Store) ListTunnels(ctx context.Context) ([]Tunnel, error) {
	const query = `
	SELECT id, name, subdomain, secret_hash, key_fingerprint, created_at, updated_at, last_seen
	FROM tunnels
	ORDER BY created_at DESC;`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []Tunnel
	for rows.Next() {
		var t Tunnel
		if err := rows.Scan(&t.ID, &t.Name, &t.Subdomain, &t.SecretHash, &t.KeyFingerprint, &t.CreatedAt, &t.UpdatedAt, &t.LastSeenAt); err != nil {
			return nil, err
		}
		items = append(items, t)
	}
	return items, rows.Err()
}

// GetTunnel fetches a tunnel by ID.
func (s *Store) GetTunnel(ctx context.Context, id string) (*Tunnel, error) {
	const query = `
	SELECT id, name, subdomain, secret_hash, key_fingerprint, created_at, updated_at, last_seen
	FROM tunnels WHERE id = ?;`

	var t Tunnel
	if err := s.db.QueryRowContext(ctx, query, id).Scan(&t.ID, &t.Name, &t.Subdomain, &t.SecretHash, &t.KeyFingerprint, &t.CreatedAt, &t.UpdatedAt, &t.LastSeenAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &t, nil
}

// GetBySubdomain fetches a tunnel by subdomain.
func (s *Store) GetBySubdomain(ctx context.Context, subdomain string) (*Tunnel, error) {
	const query = `
	SELECT id, name, subdomain, secret_hash, key_fingerprint, created_at, updated_at, last_seen
	FROM tunnels WHERE subdomain = ?;`

	var t Tunnel
	if err := s.db.QueryRowContext(ctx, query, subdomain).Scan(&t.ID, &t.Name, &t.Subdomain, &t.SecretHash, &t.KeyFingerprint, &t.CreatedAt, &t.UpdatedAt, &t.LastSeenAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &t, nil
}

// GetByKey returns the tunnel assigned to the provided key fingerprint.
func (s *Store) GetByKey(ctx context.Context, fingerprint string) (*Tunnel, error) {
	const query = `
	SELECT id, name, subdomain, secret_hash, key_fingerprint, created_at, updated_at, last_seen
	FROM tunnels WHERE key_fingerprint = ?;`

	var t Tunnel
	if err := s.db.QueryRowContext(ctx, query, fingerprint).Scan(&t.ID, &t.Name, &t.Subdomain, &t.SecretHash, &t.KeyFingerprint, &t.CreatedAt, &t.UpdatedAt, &t.LastSeenAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &t, nil
}

// AssignKey links an existing tunnel to a fingerprint.
func (s *Store) AssignKey(ctx context.Context, tunnelID, fingerprint string) error {
	const stmt = `
	UPDATE tunnels
	SET key_fingerprint = ?, updated_at = CURRENT_TIMESTAMP
	WHERE id = ?;`
	_, err := s.db.ExecContext(ctx, stmt, fingerprint, tunnelID)
	return err
}

// UpdateSubdomain updates the tunnel subdomain (after ensuring uniqueness elsewhere).
func (s *Store) UpdateSubdomain(ctx context.Context, tunnelID, subdomain string) error {
	const stmt = `
	UPDATE tunnels
	SET subdomain = ?, updated_at = CURRENT_TIMESTAMP
	WHERE id = ?;`
	_, err := s.db.ExecContext(ctx, stmt, subdomain, tunnelID)
	return err
}

// DeleteTunnel removes the tunnel entirely.
func (s *Store) DeleteTunnel(ctx context.Context, id string) error {
	const stmt = `DELETE FROM tunnels WHERE id = ?;`
	_, err := s.db.ExecContext(ctx, stmt, id)
	return err
}

// VerifyTunnelSecret returns the tunnel if the provided secret matches.
func (s *Store) VerifyTunnelSecret(ctx context.Context, id, secret string) (*Tunnel, error) {
	t, err := s.GetTunnel(ctx, id)
	if err != nil || t == nil {
		return nil, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(t.SecretHash), []byte(secret)); err != nil {
		return nil, nil
	}
	return t, nil
}

// Touch marks the tunnel as active.
func (s *Store) Touch(ctx context.Context, id string, ts time.Time) error {
	const stmt = `
	UPDATE tunnels
	SET last_seen = ?, updated_at = CURRENT_TIMESTAMP
	WHERE id = ?;`
	_, err := s.db.ExecContext(ctx, stmt, ts.UTC(), id)
	return err
}

// RotateSecret issues a new secret for the tunnel.
func (s *Store) RotateSecret(ctx context.Context, id string) (string, error) {
	secret, err := generateSecret()
	if err != nil {
		return "", err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash secret: %w", err)
	}
	const stmt = `
	UPDATE tunnels
	SET secret_hash = ?, updated_at = CURRENT_TIMESTAMP
	WHERE id = ?;`
	if _, err := s.db.ExecContext(ctx, stmt, string(hash), id); err != nil {
		return "", err
	}
	return secret, nil
}

func normalizeSubdomain(name, requested string) string {
	if requested != "" {
		return strings.ToLower(requested)
	}
	slug := strings.ToLower(name)
	slug = strings.ReplaceAll(slug, " ", "-")
	slug = regexp.MustCompile(`[^a-z0-9-]`).ReplaceAllString(slug, "")
	if slug == "" {
		slug = "tunnel"
	}
	return slug
}

func generateSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func randomSuffix(n int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "xxxx"
	}
	for i := 0; i < n; i++ {
		buf[i] = charset[int(buf[i])%len(charset)]
	}
	return string(buf)
}

func isUniqueConstraint(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
}
