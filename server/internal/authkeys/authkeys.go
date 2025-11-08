package authkeys

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// AuthorizedKey represents a trusted developer key allowed to use the API.
type AuthorizedKey struct {
	PublicKey   ed25519.PublicKey
	Fingerprint string
	Comment     string
	Raw         string
}

// Store keeps the parsed authorized keys.
type Store struct {
	keys map[string]*AuthorizedKey
}

// Load parses an authorized-keys style file (base64 public key + optional comment).
func Load(path string) (*Store, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open authorized keys: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	keys := make(map[string]*AuthorizedKey)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		raw := fields[0]
		b, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("line %d: decode key: %w", lineNum, err)
		}
		if len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("line %d: expected %d-byte key, got %d", lineNum, ed25519.PublicKeySize, len(b))
		}
		comment := ""
		if len(fields) > 1 {
			comment = strings.Join(fields[1:], " ")
		}
		fp := fingerprint(b)
		keys[fp] = &AuthorizedKey{
			PublicKey:   append(ed25519.PublicKey(nil), b...),
			Fingerprint: fp,
			Comment:     comment,
			Raw:         raw,
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan authorized keys: %w", err)
	}
	return &Store{keys: keys}, nil
}

// Lookup returns the key matching the provided public key bytes.
func (s *Store) Lookup(pub []byte) (*AuthorizedKey, bool) {
	if s == nil {
		return nil, false
	}
	fp := fingerprint(pub)
	k, ok := s.keys[fp]
	return k, ok
}

func fingerprint(pub []byte) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}
