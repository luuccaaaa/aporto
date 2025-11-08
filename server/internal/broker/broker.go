package broker

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/gorilla/websocket"
	"github.com/luuccaaaa/aporto/pkg/protocol"
	"github.com/rs/zerolog"

	"github.com/luuccaaaa/aporto/server/internal/store"
)

// Broker tracks active tunnel sessions keyed by subdomain.
type Broker struct {
	log      zerolog.Logger
	mu       sync.RWMutex
	sessions map[string]*Session
}

// New broker.
func New(log zerolog.Logger) *Broker {
	return &Broker{
		log:      log,
		sessions: make(map[string]*Session),
	}
}

// Attach stores the websocket session for the given tunnel, replacing the previous session.
func (b *Broker) Attach(tun *store.Tunnel, conn *websocket.Conn, log zerolog.Logger) *Session {
	s := newSession(tun, conn, log)

	b.mu.Lock()
	if prev, ok := b.sessions[tun.Subdomain]; ok {
		prev.Close(errors.New("replaced by new session"))
	}
	b.sessions[tun.Subdomain] = s
	b.mu.Unlock()

	go func() {
		s.readLoop()
		b.Remove(tun.Subdomain, s)
	}()
	return s
}

// Get returns the active session for the given subdomain.
func (b *Broker) Get(subdomain string) (*Session, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	s, ok := b.sessions[subdomain]
	return s, ok
}

// Remove tears down a session when it closes.
func (b *Broker) Remove(subdomain string, s *Session) {
	b.mu.Lock()
	defer b.mu.Unlock()
	cur, ok := b.sessions[subdomain]
	if !ok || cur != s {
		return
	}
	delete(b.sessions, subdomain)
}

// Session represents a live websocket to a CLI client.
type Session struct {
	tunnel  *store.Tunnel
	conn    *websocket.Conn
	log     zerolog.Logger
	closed  chan struct{}
	closeMu sync.Once

	mu      sync.Mutex
	pending map[string]chan *protocol.ProxyResponse
	writeMu sync.Mutex
}

func newSession(tun *store.Tunnel, conn *websocket.Conn, log zerolog.Logger) *Session {
	return &Session{
		tunnel:  tun,
		conn:    conn,
		log:     log.With().Str("tunnel_id", tun.ID).Str("subdomain", tun.Subdomain).Logger(),
		closed:  make(chan struct{}),
		pending: make(map[string]chan *protocol.ProxyResponse),
	}
}

// Close tears down the websocket and notifies waiters.
func (s *Session) Close(err error) {
	s.closeMu.Do(func() {
		if err != nil {
			s.log.Warn().Err(err).Msg("tunnel session closed")
		}
		close(s.closed)
		s.conn.Close()
		s.mu.Lock()
		for stream, ch := range s.pending {
			close(ch)
			delete(s.pending, stream)
		}
		s.mu.Unlock()
	})
}

// RoundTrip transmits a proxy request to the CLI and waits for its response.
func (s *Session) RoundTrip(ctx context.Context, req *protocol.ProxyRequest) (*protocol.ProxyResponse, error) {
	respCh := make(chan *protocol.ProxyResponse, 1)

	s.mu.Lock()
	s.pending[req.StreamID] = respCh
	s.mu.Unlock()

	env := protocol.Envelope{Kind: "request", Request: req}
	if err := s.send(env); err != nil {
		s.removePending(req.StreamID)
		return nil, fmt.Errorf("write request: %w", err)
	}

	select {
	case resp := <-respCh:
		if resp == nil {
			return nil, errors.New("session closed")
		}
		return resp, nil
	case <-ctx.Done():
		s.removePending(req.StreamID)
		return nil, ctx.Err()
	case <-s.closed:
		s.removePending(req.StreamID)
		return nil, errors.New("session closed")
	}
}

func (s *Session) removePending(streamID string) {
	s.mu.Lock()
	if ch, ok := s.pending[streamID]; ok {
		close(ch)
		delete(s.pending, streamID)
	}
	s.mu.Unlock()
}

func (s *Session) readLoop() {
	defer s.Close(nil)
	for {
		var env protocol.Envelope
		if err := s.conn.ReadJSON(&env); err != nil {
			s.log.Error().Err(err).Msg("reading tunnel socket failed")
			return
		}
		switch env.Kind {
		case "response":
			if env.Response == nil {
				continue
			}
			s.dispatchResponse(env.Response)
		case "pong":
			// no-op for now; could update metrics.
		default:
			s.log.Warn().Str("kind", env.Kind).Msg("received unhandled tunnel envelope")
		}
	}
}

func (s *Session) dispatchResponse(resp *protocol.ProxyResponse) {
	s.mu.Lock()
	ch, ok := s.pending[resp.StreamID]
	if ok {
		delete(s.pending, resp.StreamID)
	}
	s.mu.Unlock()

	if ok {
		ch <- resp
		close(ch)
	}
}

// Ping sends a heartbeat to the client.
func (s *Session) Ping() error {
	env := protocol.Envelope{
		Kind: "ping",
		Health: &protocol.Healthbeat{
			UnixMilli: protocol.NowMillis(),
		},
	}
	return s.send(env)
}

// WaitClosed blocks until the session closes.
func (s *Session) WaitClosed(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.closed:
		return nil
	}
}

// TunnelID returns the underlying tunnel identifier.
func (s *Session) TunnelID() string {
	return s.tunnel.ID
}

// Closed returns a channel that closes when the session ends.
func (s *Session) Closed() <-chan struct{} {
	return s.closed
}

// Tunnel returns the associated tunnel metadata.
func (s *Session) Tunnel() *store.Tunnel {
	return s.tunnel
}

func (s *Session) send(env protocol.Envelope) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.conn.WriteJSON(env)
}

// Sweep sends pings and closes sessions that fail immediately.
func (b *Broker) Sweep() {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, s := range b.sessions {
		select {
		case <-s.closed:
			// already closed
		default:
			if err := s.Ping(); err != nil {
				s.Close(err)
			}
		}
	}
}
