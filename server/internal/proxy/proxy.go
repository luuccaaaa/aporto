package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/luuccaaaa/aporto/pkg/protocol"
	"github.com/rs/zerolog"

	"github.com/luuccaaaa/aporto/server/internal/broker"
)

const maxRequestBody = 2 << 20 // 2 MiB cap for now

// HTTPProxy routes inbound requests to active tunnels via the broker.
type HTTPProxy struct {
	domain string
	log    zerolog.Logger
	broker *broker.Broker
}

func New(domain string, b *broker.Broker, log zerolog.Logger) *HTTPProxy {
	return &HTTPProxy{
		domain: strings.ToLower(domain),
		log:    log,
		broker: b,
	}
}

func (p *HTTPProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := normalizeHost(r.Host)
	subdomain, err := p.extractSubdomain(r.Host)
	if err != nil {
		http.Error(w, "invalid host", http.StatusBadRequest)
		return
	}

	if p.handleGateConfirmation(w, r, host) {
		return
	}
	if p.shouldShowWarning(r) {
		p.serveWarningPage(w, r, host)
		return
	}

	session, ok := p.broker.Get(subdomain)
	if !ok {
		http.Error(w, "tunnel offline", http.StatusBadGateway)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBody))
	if err != nil {
		http.Error(w, "read body failed", http.StatusBadRequest)
		return
	}

	headers := copyHeader(r.Header)
	headers["Host"] = []string{r.Host}

	req := &protocol.ProxyRequest{
		StreamID: uuid.NewString(),
		Method:   r.Method,
		URL:      r.URL.String(),
		Headers:  headers,
		Body:     body,
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	resp, err := session.RoundTrip(ctx, req)
	if err != nil {
		http.Error(w, fmt.Sprintf("tunnel error: %v", err), http.StatusBadGateway)
		return
	}

	for k, vals := range resp.Headers {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	if resp.Status == 0 {
		resp.Status = http.StatusOK
	}
	w.WriteHeader(resp.Status)
	_, _ = w.Write(resp.Body)
}

func (p *HTTPProxy) extractSubdomain(host string) (string, error) {
	if host == "" {
		return "", fmt.Errorf("missing host header")
	}
	host = strings.ToLower(host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == p.domain {
		return "", fmt.Errorf("root domain not routed")
	}
	if !strings.HasSuffix(host, "."+p.domain) {
		return "", fmt.Errorf("host outside managed domain")
	}
	sub := strings.TrimSuffix(host, "."+p.domain)
	if sub == "" {
		return "", fmt.Errorf("empty subdomain")
	}
	return sub, nil
}

func copyHeader(h http.Header) map[string][]string {
	out := make(map[string][]string, len(h))
	for k, vals := range h {
		dst := make([]string, len(vals))
		copy(dst, vals)
		out[k] = dst
	}
	return out
}

func normalizeHost(host string) string {
	host = strings.ToLower(host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return host
}
