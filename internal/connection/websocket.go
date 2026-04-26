package connection

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/bisskar/arktis-agent/internal/config"
	"github.com/bisskar/arktis-agent/internal/executor"
	"github.com/bisskar/arktis-agent/internal/protocol"
	"github.com/bisskar/arktis-agent/internal/session"
	"github.com/gorilla/websocket"
)

const (
	heartbeatInterval = 15 * time.Second
	maxBackoff        = 60 * time.Second
	writeWait         = 10 * time.Second

	// sendBufSize bounds how many messages can be queued for the
	// writer goroutine before Send starts returning ErrSendBufferFull.
	// A misbehaving / chatty PTY then visibly drops frames instead of
	// silently starving every other session sharing the connection.
	sendBufSize = 64
)

// ErrSendBufferFull is returned by Send when the writer goroutine cannot
// keep up with producers. Callers (PTY readloop, exec result) should log
// the back-pressure and continue rather than retry in a tight loop.
var ErrSendBufferFull = errors.New("send buffer full")

// errNotConnected indicates Send was called before the WebSocket and its
// writer goroutine were ready, or after they wound down.
var errNotConnected = errors.New("not connected")

// Client manages the WebSocket connection to the backend.
type Client struct {
	config  *config.Config
	state   *config.State
	manager *session.Manager

	mu   sync.Mutex
	conn *websocket.Conn  // active connection or nil
	out  chan interface{} // active send queue or nil; drained by writer goroutine
}

// NewClient creates a new WebSocket client.
func NewClient(cfg *config.Config, state *config.State, mgr *session.Manager) *Client {
	return &Client{
		config:  cfg,
		state:   state,
		manager: mgr,
	}
}

// Run starts the main loop with automatic reconnection.
// It blocks until the context is cancelled.
func (c *Client) Run(ctx context.Context) error {
	backoff := time.Second

	for {
		select {
		case <-ctx.Done():
			c.closeConn()
			return nil
		default:
		}

		err := c.connect(ctx)
		if err != nil {
			log.Printf("Connection failed: %v", err)
		} else {
			// Connection was successful at some point — reset backoff.
			backoff = time.Second
		}

		// Check if we should exit.
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		log.Printf("Reconnecting in %s...", backoff)

		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return nil
		}

		// Exponential backoff: 1s, 2s, 4s, 8s, ..., 60s max.
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// connect performs a single connection attempt: dial, register, read loop.
func (c *Client) connect(ctx context.Context) error {
	header := http.Header{}
	header.Set("Authorization", "Bearer "+c.config.Key)

	log.Printf("Connecting to %s...", c.config.BackendURL)

	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}
	conn, _, err := dialer.DialContext(ctx, c.config.BackendURL, header)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}

	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()

	log.Println("WebSocket connected, sending registration...")

	// Pre-handshake (register + ack) is done synchronously on the
	// connection: the writer goroutine isn't running yet, so we don't
	// need to coordinate with it. After the ack we install the queue
	// and switch all Send calls to non-blocking enqueue.
	hostname, _ := os.Hostname()
	reg := protocol.RegisterMessage{
		Type:         "register",
		HostID:       c.state.HostID,
		Hostname:     hostname,
		Platform:     executor.DetectPlatform(),
		OsFamily:     executor.DetectOsFamily(),
		OsVersion:    executor.DetectOsVersion(),
		AgentVersion: getVersion(),
	}
	if err := writeJSON(conn, reg); err != nil {
		c.closeConn()
		return fmt.Errorf("send register: %w", err)
	}

	// Wait for ack.
	if err := conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		c.closeConn()
		return fmt.Errorf("set ack read deadline: %w", err)
	}
	_, raw, err := conn.ReadMessage()
	if err != nil {
		c.closeConn()
		return fmt.Errorf("read ack: %w", err)
	}
	// Clear deadline; failure here is benign — we'd just time out earlier
	// on the next read — and the connection is healthy at this point.
	_ = conn.SetReadDeadline(time.Time{})

	var base protocol.BaseMessage
	if err := json.Unmarshal(raw, &base); err != nil {
		c.closeConn()
		return fmt.Errorf("parse ack: %w", err)
	}

	if base.Type != "ack" {
		c.closeConn()
		return fmt.Errorf("expected ack, got %q", base.Type)
	}

	var ack protocol.AckMessage
	if err := json.Unmarshal(raw, &ack); err != nil {
		c.closeConn()
		return fmt.Errorf("parse ack payload: %w", err)
	}

	// Persist host_id. The backend MUST return one — without it we have no
	// stable identity for subsequent messages, so reject the ack and let
	// the reconnect loop try again.
	if ack.HostID == "" {
		c.closeConn()
		return fmt.Errorf("ack missing host_id")
	}

	switch {
	case c.state.HostID == "":
		c.state.HostID = ack.HostID
		c.state.RegisteredAt = time.Now().UTC().Format(time.RFC3339)
		if err := config.SaveState(c.config.StateDir, c.state); err != nil {
			log.Printf("Warning: failed to save state: %v", err)
		} else {
			log.Printf("Registered with host_id=%s", ack.HostID)
		}
	case ack.HostID != c.state.HostID:
		// Backend reassigned us — surface this prominently so an operator
		// can spot a rename / re-enrollment instead of silently rotating.
		log.Printf("Warning: backend changed host_id from %s to %s; updating state",
			c.state.HostID, ack.HostID)
		c.state.HostID = ack.HostID
		c.state.RegisteredAt = time.Now().UTC().Format(time.RFC3339)
		if err := config.SaveState(c.config.StateDir, c.state); err != nil {
			log.Printf("Warning: failed to save state: %v", err)
		}
	default:
		log.Printf("Re-connected with host_id=%s", c.state.HostID)
	}

	// Install the per-connection send queue and start the writer goroutine.
	// All post-handshake Send() calls go through this queue so a chatty PTY
	// can no longer hold a single mutex and starve heartbeats / other sessions.
	out := make(chan interface{}, sendBufSize)
	c.mu.Lock()
	c.out = out
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		if c.out == out {
			c.out = nil
		}
		c.mu.Unlock()
		close(out)
	}()

	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		c.writeLoop(ctx, conn, out)
	}()
	defer func() { <-writerDone }()

	// Start heartbeat goroutine. Both the per-connection done channel and
	// the cancel func are scoped to this call frame: deferred close/cancel
	// guarantees the heartbeat goroutine winds down before connect()
	// returns, so a stale goroutine from a previous connection can never
	// leak into the next one.
	hbCtx, hbCancel := context.WithCancel(ctx)
	defer hbCancel()
	hbDone := make(chan struct{})
	defer close(hbDone)
	go c.heartbeatLoop(hbCtx, hbDone)

	// Close the websocket when the context is cancelled. This unblocks
	// conn.ReadMessage() in the read loop so graceful shutdown doesn't
	// have to wait up to ~15s for the next heartbeat frame.
	closeOnCancelDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			c.closeConn()
		case <-closeOnCancelDone:
		}
	}()
	defer close(closeOnCancelDone)

	// Read loop blocks until error or context cancellation.
	c.readLoop(ctx, conn)

	return nil
}

// writeLoop drains the send queue, serializing all post-handshake writes
// to the WebSocket. Exits when the queue is closed (connect() returning)
// or when WriteJSON fails (which also tears down the connection).
func (c *Client) writeLoop(ctx context.Context, conn *websocket.Conn, out <-chan interface{}) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-out:
			if !ok {
				return
			}
			if err := writeJSON(conn, msg); err != nil {
				log.Printf("WebSocket write error: %v", err)
				// Tear the connection down so readLoop returns and we
				// trigger a reconnect rather than silently losing more
				// messages.
				c.closeConn()
				return
			}
		}
	}
}

// readLoop reads and dispatches messages from the backend.
func (c *Client) readLoop(ctx context.Context, conn *websocket.Conn) {
	defer c.closeConn()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		_, raw, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("WebSocket read error: %v", err)
			} else {
				log.Printf("WebSocket closed: %v", err)
			}
			return
		}

		var base protocol.BaseMessage
		if err := json.Unmarshal(raw, &base); err != nil {
			log.Printf("Failed to parse message type: %v", err)
			continue
		}

		switch base.Type {
		case "exec":
			var msg protocol.ExecMessage
			if err := json.Unmarshal(raw, &msg); err != nil {
				log.Printf("Failed to parse exec message: %v", err)
				continue
			}
			go c.manager.HandleExec(ctx, &msg, c)

		case "pty_open":
			var msg protocol.PtyOpenMessage
			if err := json.Unmarshal(raw, &msg); err != nil {
				log.Printf("Failed to parse pty_open message: %v", err)
				continue
			}
			go c.manager.HandlePtyOpen(&msg, c)

		case "pty_input":
			var msg protocol.PtyInputMessage
			if err := json.Unmarshal(raw, &msg); err != nil {
				log.Printf("Failed to parse pty_input message: %v", err)
				continue
			}
			c.manager.HandlePtyInput(&msg)

		case "pty_resize":
			var msg protocol.PtyResizeMessage
			if err := json.Unmarshal(raw, &msg); err != nil {
				log.Printf("Failed to parse pty_resize message: %v", err)
				continue
			}
			c.manager.HandlePtyResize(&msg)

		case "pty_close":
			var msg protocol.PtyCloseMessage
			if err := json.Unmarshal(raw, &msg); err != nil {
				log.Printf("Failed to parse pty_close message: %v", err)
				continue
			}
			c.manager.HandlePtyClose(&msg)

		case "heartbeat_ack":
			// No-op; connection is healthy.
			log.Println("Heartbeat acknowledged")

		default:
			log.Printf("Unknown message type: %q", base.Type)
		}
	}
}

// heartbeatLoop sends heartbeat messages at regular intervals.
// done is closed by the connect() call frame to terminate the loop on
// disconnect; ctx covers root-shutdown.
func (c *Client) heartbeatLoop(ctx context.Context, done <-chan struct{}) {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-ticker.C:
			if err := c.Send(protocol.HeartbeatMessage{Type: "heartbeat"}); err != nil {
				log.Printf("Failed to enqueue heartbeat: %v", err)
				// Don't return on a backpressure-only failure — we'll
				// try again next tick. A genuine teardown is signalled
				// through ctx / done.
				if !errors.Is(err, ErrSendBufferFull) {
					return
				}
			}
		}
	}
}

// Send enqueues msg onto the writer goroutine's queue. It is non-blocking:
// if the queue is full it returns ErrSendBufferFull immediately so a
// misbehaving sender (e.g. a chatty PTY) can never starve other senders
// or hold a write mutex across slow network frames.
func (c *Client) Send(msg interface{}) error {
	c.mu.Lock()
	out := c.out
	c.mu.Unlock()
	if out == nil {
		return errNotConnected
	}
	select {
	case out <- msg:
		return nil
	default:
		return ErrSendBufferFull
	}
}

// closeConn safely closes the WebSocket connection. The per-connection
// heartbeat / writer goroutines are wound down by connect()'s deferred
// close(hbDone) and queue close — closeConn may be called multiple times
// (read-loop exit, ctx-cancel goroutine) and must remain idempotent.
func (c *Client) closeConn() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		// Close errors here are unactionable: the connection is being torn
		// down, and any error means it was already broken from the other
		// side. The reconnect loop handles the recovery path.
		_ = c.conn.Close()
		c.conn = nil
	}
}

// writeJSON is the single point where we set the write deadline + marshal.
// Used both by the synchronous register path and by the post-handshake
// writer goroutine.
func writeJSON(conn *websocket.Conn, msg interface{}) error {
	if err := conn.SetWriteDeadline(time.Now().Add(writeWait)); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
	}
	return conn.WriteJSON(msg)
}

// getVersion returns the agent version (set via ldflags in main).
// We access it through a package-level variable that main sets.
var agentVersion = "dev"

func getVersion() string {
	return agentVersion
}

// SetVersion allows main to inject the version from ldflags.
func SetVersion(v string) {
	agentVersion = v
}
