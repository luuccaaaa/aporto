package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"
	"github.com/rs/zerolog"

	"github.com/luuccaaaa/aporto/server/internal/authkeys"
	"github.com/luuccaaaa/aporto/server/internal/broker"
	"github.com/luuccaaaa/aporto/server/internal/store"
)

// API exposes the control plane HTTP handlers.
type API struct {
	store      *store.Store
	broker     *broker.Broker
	adminToken string
	domain     string
	keys       *authkeys.Store
	log        zerolog.Logger
	upgrader   websocket.Upgrader
}

func New(store *store.Store, broker *broker.Broker, adminToken, domain string, keys *authkeys.Store, log zerolog.Logger) *API {
	return &API{
		store:      store,
		broker:     broker,
		adminToken: adminToken,
		domain:     domain,
		keys:       keys,
		log:        log,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}
}

// Router builds the HTTP routes for the control plane.
func (a *API) Router() http.Handler {
	r := chi.NewRouter()

	// Admin-scoped routes.
	r.Group(func(r chi.Router) {
		r.Use(a.requireAdmin)
		r.Get("/v1/tunnels", a.handleListTunnels)
		r.Post("/v1/tunnels", a.handleCreateTunnel)
	})

	r.Get("/v1/tls/allow", a.handleAllowDomain)

	r.Post("/v1/dev/login", a.handleDeveloperLogin)
	r.Post("/v1/dev/ping", a.handleDeveloperPing)

	// CLI tunnel websocket
	r.Get("/v1/tunnels/{tunnelID}/connect", a.handleConnectTunnel)
	return r
}

func (a *API) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractBearer(r.Header.Get("Authorization"))
		if token == "" || subtleConstantTimeCompare(token, a.adminToken) == false {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *API) handleListTunnels(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	items, err := a.store.ListTunnels(ctx)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	type tunnelDTO struct {
		ID        string    `json:"id"`
		Name      string    `json:"name"`
		Subdomain string    `json:"subdomain"`
		Hostname  string    `json:"hostname"`
		CreatedAt time.Time `json:"created_at"`
		LastSeen  time.Time `json:"last_seen,omitempty"`
	}

	resp := make([]tunnelDTO, 0, len(items))
	for _, t := range items {
		dto := tunnelDTO{
			ID:        t.ID,
			Name:      t.Name,
			Subdomain: t.Subdomain,
			Hostname:  t.Subdomain + "." + a.domain,
			CreatedAt: t.CreatedAt,
		}
		if t.LastSeenAt.Valid {
			dto.LastSeen = t.LastSeenAt.Time
		}
		resp = append(resp, dto)
	}
	a.writeJSON(w, http.StatusOK, resp)
}

func (a *API) handleCreateTunnel(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name      string `json:"name"`
		Subdomain string `json:"subdomain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	t, secret, err := a.store.CreateTunnel(ctx, req.Name, strings.ToLower(req.Subdomain))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	resp := map[string]any{
		"id":        t.ID,
		"name":      t.Name,
		"subdomain": t.Subdomain,
		"hostname":  t.Subdomain + "." + a.domain,
		"secret":    secret,
	}
	a.writeJSON(w, http.StatusCreated, resp)
}

func (a *API) handleDeveloperLogin(w http.ResponseWriter, r *http.Request) {
	body, key, err := a.readSignedBody(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	var req struct {
		Name      string `json:"name"`
		Subdomain string `json:"subdomain"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	name := strings.TrimSpace(req.Name)
	if name == "" {
		base := key.Comment
		if base == "" {
			base = "tunnel"
		}
		name = fmt.Sprintf("%s-%s", base, key.Fingerprint[:6])
	}
	subdomain := strings.ToLower(strings.TrimSpace(req.Subdomain))

	tun, secret, err := a.ensureTunnelForKey(ctx, key, name, subdomain)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{
		"id":          tun.ID,
		"name":        tun.Name,
		"subdomain":   tun.Subdomain,
		"hostname":    tun.Subdomain + "." + a.domain,
		"secret":      secret,
		"fingerprint": key.Fingerprint,
	})
}

func (a *API) handleDeveloperPing(w http.ResponseWriter, r *http.Request) {
	_, key, err := a.readSignedBody(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	ctx := r.Context()
	tun, err := a.store.GetByKey(ctx, key.Fingerprint)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	type tunnelInfo struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		Subdomain string `json:"subdomain"`
		Hostname  string `json:"hostname"`
		Active    bool   `json:"active"`
	}
	var info *tunnelInfo
	if tun != nil {
		active := false
		if sess, ok := a.broker.Get(tun.Subdomain); ok && sess.TunnelID() == tun.ID {
			active = true
		}
		info = &tunnelInfo{
			ID:        tun.ID,
			Name:      tun.Name,
			Subdomain: tun.Subdomain,
			Hostname:  tun.Subdomain + "." + a.domain,
			Active:    active,
		}
	}
	a.writeJSON(w, http.StatusOK, map[string]any{
		"fingerprint": key.Fingerprint,
		"tunnel":      info,
	})
}

func (a *API) handleConnectTunnel(w http.ResponseWriter, r *http.Request) {
	tunnelID := chi.URLParam(r, "tunnelID")
	secret := extractBearer(r.Header.Get("Authorization"))
	if tunnelID == "" || secret == "" {
		http.Error(w, "missing credentials", http.StatusUnauthorized)
		return
	}

	ctx := r.Context()
	tunnel, err := a.store.VerifyTunnelSecret(ctx, tunnelID, secret)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	if tunnel == nil {
		http.Error(w, "invalid secret", http.StatusUnauthorized)
		return
	}

	if sess, ok := a.broker.Get(tunnel.Subdomain); ok {
		select {
		case <-sess.Closed():
			// previous session already tearing down; allow new connection.
		default:
			http.Error(w, "tunnel already connected", http.StatusConflict)
			return
		}
	}

	conn, err := a.upgrader.Upgrade(w, r, nil)
	if err != nil {
		a.log.Error().Err(err).Msg("websocket upgrade failed")
		return
	}
	a.log.Info().Str("tunnel_id", tunnel.ID).Msg("tunnel connected")

	if err := a.store.Touch(ctx, tunnel.ID, time.Now()); err != nil {
		a.log.Warn().Err(err).Str("tunnel_id", tunnel.ID).Msg("failed to record tunnel heartbeat")
	}

	session := a.broker.Attach(tunnel, conn, a.log)

	go func(id string) {
		<-session.Closed()
		_ = a.store.Touch(context.Background(), id, time.Now())
	}(tunnel.ID)

	_ = session.WaitClosed(context.Background())
}

// handleAllowDomain is used by Caddy's on-demand TLS "ask" hook to ensure
// certificates are only minted for known tunnel subdomains.
func (a *API) handleAllowDomain(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("domain")))
	if host == "" {
		http.Error(w, "domain is required", http.StatusBadRequest)
		return
	}
	if strings.HasSuffix(host, ".") {
		host = strings.TrimSuffix(host, ".")
	}
	if h, _, found := strings.Cut(host, ":"); found {
		host = h
	}

	baseDomain := strings.ToLower(a.domain)
	suffix := "." + baseDomain
	if !strings.HasSuffix(host, suffix) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	subdomain := strings.TrimSuffix(host, suffix)
	if subdomain == "" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	tunnel, err := a.store.GetBySubdomain(r.Context(), subdomain)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	if tunnel == nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

const (
	headerPublicKey = "X-Aporto-Public-Key"
	headerSignature = "X-Aporto-Signature"
)

func (a *API) readSignedBody(r *http.Request) ([]byte, *authkeys.AuthorizedKey, error) {
	if a.keys == nil {
		return nil, nil, fmt.Errorf("developer auth not configured")
	}
	pubB64 := r.Header.Get(headerPublicKey)
	sigB64 := r.Header.Get(headerSignature)
	if pubB64 == "" || sigB64 == "" {
		return nil, nil, fmt.Errorf("missing key headers")
	}

	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid public key encoding")
	}
	key, ok := a.keys.Lookup(pub)
	if !ok {
		return nil, nil, fmt.Errorf("unknown developer key")
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid signature encoding")
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, nil, fmt.Errorf("invalid signature size")
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, nil, fmt.Errorf("read body: %w", err)
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	if !ed25519.Verify(key.PublicKey, body, sig) {
		return nil, nil, fmt.Errorf("signature verification failed")
	}
	return body, key, nil
}

func (a *API) ensureTunnelForKey(ctx context.Context, key *authkeys.AuthorizedKey, name, requestedSubdomain string) (*store.Tunnel, string, error) {
	t, err := a.store.GetByKey(ctx, key.Fingerprint)
	if err != nil {
		return nil, "", err
	}
	if t == nil {
		if requestedSubdomain != "" {
			if err := a.reclaimSubdomain(ctx, requestedSubdomain, "", key.Fingerprint); err != nil {
				return nil, "", err
			}
			t, secret, err := a.store.CreateTunnel(ctx, name, requestedSubdomain)
			if err != nil {
				return nil, "", err
			}
			if err := a.store.AssignKey(ctx, t.ID, key.Fingerprint); err != nil {
				return nil, "", err
			}
			return t, secret, nil
		}
		t, secret, err := a.store.CreateTunnelAuto(ctx, name, requestedSubdomain)
		if err != nil {
			return nil, "", err
		}
		if err := a.store.AssignKey(ctx, t.ID, key.Fingerprint); err != nil {
			return nil, "", err
		}
		return t, secret, nil
	}

	if requestedSubdomain != "" && requestedSubdomain != t.Subdomain {
		if a.isTunnelActive(t.ID, t.Subdomain) {
			return nil, "", fmt.Errorf("tunnel %q is currently active; stop it before requesting a new hostname", t.Subdomain)
		}
		if err := a.reclaimSubdomain(ctx, requestedSubdomain, t.ID, key.Fingerprint); err != nil {
			return nil, "", err
		}
		if err := a.store.UpdateSubdomain(ctx, t.ID, requestedSubdomain); err != nil {
			return nil, "", err
		}
		t.Subdomain = requestedSubdomain
	}

	if a.isTunnelActive(t.ID, t.Subdomain) {
		return nil, "", fmt.Errorf("tunnel %q is currently active; stop it before starting another session", t.Subdomain)
	}

	secret, err := a.store.RotateSecret(ctx, t.ID)
	if err != nil {
		return nil, "", err
	}
	return t, secret, nil
}

func (a *API) reclaimSubdomain(ctx context.Context, subdomain, claimantID, claimantFingerprint string) error {
	existing, err := a.store.GetBySubdomain(ctx, subdomain)
	if err != nil {
		return err
	}
	if existing == nil || existing.ID == claimantID {
		return nil
	}
	if existing.KeyFingerprint.Valid && existing.KeyFingerprint.String != "" {
		if existing.KeyFingerprint.String == claimantFingerprint {
			return nil
		}
		return fmt.Errorf("subdomain %q already claimed", subdomain)
	}
	if sess, ok := a.broker.Get(subdomain); ok && sess.TunnelID() != claimantID {
		return fmt.Errorf("subdomain %q currently active", subdomain)
	}
	return fmt.Errorf("subdomain %q already reserved", subdomain)
}

func (a *API) isTunnelActive(tunnelID, subdomain string) bool {
	if subdomain == "" {
		return false
	}
	if sess, ok := a.broker.Get(subdomain); ok && sess.TunnelID() == tunnelID {
		return true
	}
	return false
}

func (a *API) writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func extractBearer(header string) string {
	if header == "" {
		return ""
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 {
		return ""
	}
	if !strings.EqualFold(parts[0], "bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func subtleConstantTimeCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
