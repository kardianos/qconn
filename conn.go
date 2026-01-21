package qconn

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"

	"github.com/fxamacker/cbor/v2"
	"github.com/quic-go/quic-go"
)

// ErrMessageTooLarge is returned when a message exceeds the size limit.
var ErrMessageTooLarge = errors.New("message too large")

// clientConn represents a connected client.
type clientConn struct {
	connFP   FP
	hostname string // Machine name
	state    ConnState
	devices  []DeviceInfo

	quicConn *quic.Conn
	stream   *quic.Stream
	enc      *cbor.Encoder
	limitedR *limitedReader
	dec      *cbor.Decoder

	sendMu sync.Mutex
}

// limitedReader wraps an io.Reader and limits the number of bytes that can be read
// per message. It returns ErrMessageTooLarge if the limit is exceeded.
// It is safe for concurrent use (allows limit updates during reads).
type limitedReader struct {
	mu        sync.Mutex
	r         io.Reader
	limit     int64
	remaining int64
}

func newLimitedReader(r io.Reader, limit int64) *limitedReader {
	return &limitedReader{r: r, limit: limit, remaining: limit}
}

func (l *limitedReader) Read(p []byte) (n int, err error) {
	l.mu.Lock()
	if l.remaining <= 0 {
		l.mu.Unlock()
		return 0, ErrMessageTooLarge
	}
	toRead := int64(len(p))
	if toRead > l.remaining {
		toRead = l.remaining
	}
	l.mu.Unlock()

	// Read with potentially reduced buffer size.
	n, err = l.r.Read(p[:toRead])

	l.mu.Lock()
	l.remaining -= int64(n)
	l.mu.Unlock()
	return n, err
}

// Reset resets the reader for the next message.
func (l *limitedReader) Reset() {
	l.mu.Lock()
	l.remaining = l.limit
	l.mu.Unlock()
}

// SetLimit updates the limit and resets the remaining count.
func (l *limitedReader) SetLimit(limit int64) {
	l.mu.Lock()
	l.limit = limit
	l.remaining = limit
	l.mu.Unlock()
}

// target returns the Target for this connection's machine.
func (c *clientConn) target() Target {
	return Target{Machine: c.hostname}
}

func (c *clientConn) deliver(ctx context.Context, from Target, msg *Message) error {
	msg.From = from
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	return c.enc.Encode(msg)
}

// serverHandler processes server-side messages and has access to the connection.
// This is internal; external code uses Handler which doesn't expose connection details.
type serverHandler func(ctx context.Context, conn *clientConn, msg *Message, w io.Writer, ack Ack) error

// systemTarget handles messages addressed to the server.
type systemTarget struct {
	server   *Server
	handlers map[ConnState]map[string]serverHandler
}

func (st *systemTarget) deliver(ctx context.Context, fromFP FP, msg *Message) error {
	st.server.mu.RLock()
	conn := st.server.conns[fromFP]
	st.server.mu.RUnlock()

	if conn == nil {
		return ErrNotConnected
	}

	handlers := st.handlers[conn.state]
	if handlers == nil {
		return st.server.sendError(ctx, conn, msg.ID, ErrInvalidState.Error())
	}

	// Check if the request is allowed (zero FP represents system).
	// Skip Allow check for StateProvisioning - security is enforced by handler map,
	// and provisioning clients have no record or temp auth yet.
	if conn.state != StateProvisioning {
		allowed, err := st.server.clients.Allow(ActionRequest, fromFP, FP{}, msg.Type, msg.Role)
		if err != nil {
			return st.server.sendError(ctx, conn, msg.ID, err.Error())
		}
		if !allowed {
			return st.server.sendError(ctx, conn, msg.ID, "request not allowed")
		}
	}

	handler := handlers[msg.Type]
	if handler == nil {
		return st.server.sendError(ctx, conn, msg.ID, ErrUnknownType.Error())
	}

	// System handlers don't need ack, provide no-op.
	var ack Ack = func(context.Context) error { return nil }

	var buf bytes.Buffer
	err := handler(ctx, conn, msg, &buf, ack)

	resp := &Message{
		ID:     msg.ID,
		Action: ActionResponse,
		Target: conn.target(),
	}
	if err != nil {
		resp.Error = err.Error()
	} else if buf.Len() > 0 {
		resp.Payload = buf.Bytes()
	}

	return st.server.dispatchToConn(ctx, System(), conn, resp)
}

// Ack sends an acknowledgment signaling that the request was received
// and the caller should extend its timeout.
type Ack func(context.Context) error

// Handler processes a message and writes the response payload to w.
// Returns an error to be sent as the response error, or nil for success.
// The Message contains the request details including Type and Payload.
// The From field in Message indicates the sender.
type Handler func(ctx context.Context, msg *Message, w io.Writer, ack Ack) error
