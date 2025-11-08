package tunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/luuccaaaa/aporto/pkg/protocol"
	"github.com/rs/zerolog"

	"github.com/luuccaaaa/aporto/cli/internal/config"
)

const (
	maxResponseBody = 4 << 20 // 4 MiB
	requestTimeout  = 30 * time.Second
)

// Runner maintains the websocket tunnel and proxies HTTP traffic to the local target.
type Runner struct {
	cfg        *config.Config
	log        zerolog.Logger
	localBase  *url.URL
	dialer     *websocket.Dialer
	httpClient *http.Client
	reqLogger  RequestLogger
}

// RequestLogger captures inbound HTTP requests handled via the tunnel.
type RequestLogger func(method, path string, status int, duration time.Duration)

// NewRunner builds a tunnel runner using the provided config.
func NewRunner(cfg *config.Config, logger zerolog.Logger, recorder RequestLogger) (*Runner, error) {
	localBase, err := url.Parse(cfg.LocalAddr)
	if err != nil {
		return nil, fmt.Errorf("parse local_addr: %w", err)
	}
	if localBase.Scheme == "" {
		return nil, fmt.Errorf("local_addr must include scheme (http/https)")
	}

	var tlsConfig *tls.Config
	if cfg.InsecureTLS {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec
		}
	}

	dialer := websocket.Dialer{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: tlsConfig,
	}

	httpTransport := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: tlsConfig,
	}

	return &Runner{
		cfg:       cfg,
		log:       logger,
		localBase: localBase,
		dialer:    &dialer,
		reqLogger: recorder,
		httpClient: &http.Client{
			Transport: httpTransport,
			Timeout:   requestTimeout,
		},
	}, nil
}

// Run keeps the tunnel alive until the context is canceled.
func (r *Runner) Run(ctx context.Context) error {
	backoff := time.Second
	for {
		if err := r.runOnce(ctx); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			r.log.Warn().Err(err).Msg("tunnel disconnected, attempting reconnect")
		} else {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (r *Runner) runOnce(ctx context.Context) error {
	wsURL, err := r.websocketURL()
	if err != nil {
		return err
	}

	header := http.Header{
		"Authorization": []string{"Bearer " + r.cfg.TunnelSecret},
	}

	conn, resp, err := r.dialer.DialContext(ctx, wsURL, header)
	if err != nil {
		if resp != nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			msg := strings.TrimSpace(string(body))
			switch resp.StatusCode {
			case http.StatusUnauthorized:
				if msg == "" {
					msg = "invalid tunnel secret"
				}
				return fmt.Errorf("tunnel auth failed: %s", msg)
			case http.StatusConflict:
				if msg == "" {
					msg = "tunnel already connected elsewhere"
				}
				return fmt.Errorf("tunnel already running: %s", msg)
			default:
				if msg == "" {
					msg = resp.Status
				}
				return fmt.Errorf("dial tunnel failed (%d): %s", resp.StatusCode, msg)
			}
		}
		return fmt.Errorf("dial tunnel: %w", err)
	}
	if resp != nil {
		resp.Body.Close()
	}
	defer conn.Close()

	r.log.Info().Str("tunnel_id", r.cfg.TunnelID).Msg("tunnel connected")

	sess := &session{conn: conn}
	errCh := make(chan error, 1)

	go func() {
		errCh <- r.readLoop(ctx, sess)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

func (r *Runner) readLoop(ctx context.Context, sess *session) error {
	var wg sync.WaitGroup
	defer func() {
		wg.Wait()
	}()

	for {
		var env protocol.Envelope
		if err := sess.conn.ReadJSON(&env); err != nil {
			return fmt.Errorf("read tunnel frame: %w", err)
		}

		switch env.Kind {
		case "request":
			req := env.Request
			if req == nil {
				continue
			}
			wg.Add(1)
			go func(pr *protocol.ProxyRequest) {
				defer wg.Done()
				r.handleRequest(ctx, sess, pr)
			}(req)
		case "ping":
			resp := protocol.Envelope{
				Kind: "pong",
				Health: &protocol.Healthbeat{
					UnixMilli: protocol.NowMillis(),
				},
			}
			if err := sess.send(resp); err != nil {
				r.log.Warn().Err(err).Msg("failed to send pong")
			}
		default:
			r.log.Debug().Str("kind", env.Kind).Msg("ignored tunnel envelope")
		}
	}
}

func (r *Runner) handleRequest(ctx context.Context, sess *session, req *protocol.ProxyRequest) {
	start := time.Now()
	resp, err := r.proxyToLocal(ctx, req)
	if err != nil {
		r.log.Error().
			Err(err).
			Str("stream_id", req.StreamID).
			Msg("local proxy failed")
		resp = &protocol.ProxyResponse{
			StreamID: req.StreamID,
			Status:   http.StatusBadGateway,
			Headers: map[string][]string{
				"Content-Type": {"text/plain"},
			},
			Body: []byte("aporto tunnel error: " + err.Error()),
		}
	}

	if r.reqLogger != nil {
		status := resp.Status
		if err != nil {
			status = http.StatusBadGateway
		}
		r.reqLogger(req.Method, req.URL, status, time.Since(start))
	}
	if err := sess.send(protocol.Envelope{Kind: "response", Response: resp}); err != nil {
		r.log.Error().Err(err).Msg("failed to push response upstream")
	}
}

func (r *Runner) proxyToLocal(ctx context.Context, req *protocol.ProxyRequest) (*protocol.ProxyResponse, error) {
	relURL, err := url.Parse(req.URL)
	if err != nil {
		return nil, fmt.Errorf("parse request url: %w", err)
	}
	target := r.localBase.ResolveReference(relURL)

	bodyReader := bytes.NewReader(req.Body)
	localReq, err := http.NewRequestWithContext(ctx, req.Method, target.String(), bodyReader)
	if err != nil {
		return nil, fmt.Errorf("build local request: %w", err)
	}

	copyHeaders(localReq, req.Headers)

	resp, err := r.httpClient.Do(localReq)
	if err != nil {
		return nil, fmt.Errorf("call local service: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return nil, fmt.Errorf("read local response: %w", err)
	}

	return &protocol.ProxyResponse{
		StreamID: req.StreamID,
		Status:   resp.StatusCode,
		Headers:  filterHeaders(resp.Header),
		Body:     data,
	}, nil
}

func (r *Runner) websocketURL() (string, error) {
	base, err := url.Parse(r.cfg.APIURL)
	if err != nil {
		return "", fmt.Errorf("parse api_url: %w", err)
	}
	switch base.Scheme {
	case "http":
		base.Scheme = "ws"
	case "https":
		base.Scheme = "wss"
	case "":
		return "", fmt.Errorf("api_url must include scheme")
	default:
		return "", fmt.Errorf("unsupported api_url scheme %q", base.Scheme)
	}
	base.Path = path.Join(base.Path, "/v1/tunnels", r.cfg.TunnelID, "connect")
	return base.String(), nil
}

type session struct {
	conn   *websocket.Conn
	sendMu sync.Mutex
}

func (s *session) send(env protocol.Envelope) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	return s.conn.WriteJSON(env)
}

func copyHeaders(dst *http.Request, headers map[string][]string) {
	for k, vals := range headers {
		if strings.EqualFold(k, "host") {
			continue
		}
		for _, v := range vals {
			dst.Header.Add(k, v)
		}
	}
	dst.Host = dst.URL.Host
}

var hopHeaders = map[string]struct{}{
	"connection":          {},
	"keep-alive":          {},
	"proxy-authenticate":  {},
	"proxy-authorization": {},
	"te":                  {},
	"trailers":            {},
	"transfer-encoding":   {},
	"upgrade":             {},
}

func filterHeaders(h http.Header) map[string][]string {
	out := make(map[string][]string, len(h))
	for k, vals := range h {
		if _, skip := hopHeaders[strings.ToLower(k)]; skip {
			continue
		}
		cp := make([]string, len(vals))
		copy(cp, vals)
		out[k] = cp
	}
	return out
}
