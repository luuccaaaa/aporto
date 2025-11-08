package protocol

import "time"

// FrameType denotes what kind of payload is transported over the tunnel.
type FrameType uint8

const (
	FrameTypeUnknown FrameType = iota
	FrameTypeRequest
	FrameTypeChunk
	FrameTypeResponse
	FrameTypePing
	FrameTypePong
	FrameTypeClose
)

// HandshakeRequest is sent by the CLI when opening a tunnel websocket.
type HandshakeRequest struct {
	Version   string `json:"version"`
	TunnelID  string `json:"tunnel_id"`
	AuthToken string `json:"auth_token"`
}

// HandshakeResponse is returned by the server acknowledging the tunnel.
type HandshakeResponse struct {
	Accepted bool   `json:"accepted"`
	Message  string `json:"message"`
}

// Frame encapsulates a logical HTTP exchange stream.
type Frame struct {
	Type     FrameType `json:"type"`
	StreamID string    `json:"stream_id"`
	Payload  []byte    `json:"payload"`
}

// Envelope is the top-level message passed over the websocket.
type Envelope struct {
	Kind     string         `json:"kind"`
	Request  *ProxyRequest  `json:"request,omitempty"`
	Response *ProxyResponse `json:"response,omitempty"`
	Health   *Healthbeat    `json:"health,omitempty"`
	Error    string         `json:"error,omitempty"`
	Meta     map[string]any `json:"meta,omitempty"`
}

// ProxyRequest represents a single inbound HTTP request the server received.
type ProxyRequest struct {
	StreamID string              `json:"stream_id"`
	Method   string              `json:"method"`
	URL      string              `json:"url"`
	Headers  map[string][]string `json:"headers"`
	Body     []byte              `json:"body"`
}

// ProxyResponse corresponds to a completed HTTP response produced by the CLI.
type ProxyResponse struct {
	StreamID string              `json:"stream_id"`
	Status   int                 `json:"status"`
	Headers  map[string][]string `json:"headers"`
	Body     []byte              `json:"body"`
}

// Healthbeat is exchanged periodically to detect broken tunnels.
type Healthbeat struct {
	UnixMilli int64 `json:"unix_milli"`
}

// NowMillis returns the current unix timestamp in milliseconds.
func NowMillis() int64 { // small helper to make tests deterministic when mocked
	return time.Now().UTC().UnixMilli()
}
