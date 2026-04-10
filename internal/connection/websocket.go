package connection

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/bisskar/sentinel-agent/internal/config"
	"github.com/bisskar/sentinel-agent/internal/executor"
	"github.com/bisskar/sentinel-agent/internal/session"
	"github.com/gorilla/websocket"
)

const (
	heartbeatInterval = 15 * time.Second
	maxBackoff        = 60 * time.Second
	writeWait         = 10 * time.Second
)

// Client manages the WebSocket connection to the backend.
type Client struct {
	config  *config.Config
	state   *config.State
	conn    *websocket.Conn
	manager *session.Manager
	mu      sync.Mutex
	done    chan struct{}
}

// NewClient creates a new WebSocket client.
func NewClient(cfg *config.Config, state *config.State, mgr *session.Manager) *Client {
	return &Client{
		config:  cfg,
		state:   state,
		manager: mgr,
		done:    make(chan struct{}, 1),
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
	c.done = make(chan struct{}, 1)
	c.mu.Unlock()

	log.Println("WebSocket connected, sending registration...")

	// Send register message.
	hostname, _ := os.Hostname()
	reg := RegisterMessage{
		Type:         "register",
		HostID:       c.state.HostID,
		Hostname:     hostname,
		Platform:     executor.DetectPlatform(),
		OsFamily:     executor.DetectOsFamily(),
		OsVersion:    executor.DetectOsVersion(),
		AgentVersion: getVersion(),
	}
	if err := c.Send(reg); err != nil {
		c.closeConn()
		return fmt.Errorf("send register: %w", err)
	}

	// Wait for ack.
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	_, raw, err := conn.ReadMessage()
	if err != nil {
		c.closeConn()
		return fmt.Errorf("read ack: %w", err)
	}
	conn.SetReadDeadline(time.Time{}) // Clear deadline.

	var base BaseMessage
	if err := json.Unmarshal(raw, &base); err != nil {
		c.closeConn()
		return fmt.Errorf("parse ack: %w", err)
	}

	if base.Type != "ack" {
		c.closeConn()
		return fmt.Errorf("expected ack, got %q", base.Type)
	}

	var ack AckMessage
	if err := json.Unmarshal(raw, &ack); err != nil {
		c.closeConn()
		return fmt.Errorf("parse ack payload: %w", err)
	}

	// Persist host_id.
	if ack.HostID != "" && ack.HostID != c.state.HostID {
		c.state.HostID = ack.HostID
		c.state.RegisteredAt = time.Now().UTC().Format(time.RFC3339)
		if err := config.SaveState(c.config.StateDir, c.state); err != nil {
			log.Printf("Warning: failed to save state: %v", err)
		} else {
			log.Printf("Registered with host_id=%s", ack.HostID)
		}
	} else {
		log.Printf("Re-connected with host_id=%s", c.state.HostID)
	}

	// Connection established — reset backoff is handled by the caller observing success.
	// We signal success by running the read loop (which blocks until disconnect).

	// Start heartbeat goroutine.
	hbCtx, hbCancel := context.WithCancel(ctx)
	defer hbCancel()
	go c.heartbeatLoop(hbCtx)

	// Read loop blocks until error or context cancellation.
	c.readLoop(ctx)

	return nil
}

// readLoop reads and dispatches messages from the backend.
func (c *Client) readLoop(ctx context.Context) {
	defer c.closeConn()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		_, raw, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("WebSocket read error: %v", err)
			} else {
				log.Printf("WebSocket closed: %v", err)
			}
			return
		}

		var base BaseMessage
		if err := json.Unmarshal(raw, &base); err != nil {
			log.Printf("Failed to parse message type: %v", err)
			continue
		}

		switch base.Type {
		case "exec":
			var msg session.ExecMessage
			if err := json.Unmarshal(raw, &msg); err != nil {
				log.Printf("Failed to parse exec message: %v", err)
				continue
			}
			go c.manager.HandleExec(&msg, c)

		case "pty_open":
			var msg session.PtyOpenMessage
			if err := json.Unmarshal(raw, &msg); err != nil {
				log.Printf("Failed to parse pty_open message: %v", err)
				continue
			}
			go c.manager.HandlePtyOpen(&msg, c)

		case "pty_input":
			var msg session.PtyInputMessage
			if err := json.Unmarshal(raw, &msg); err != nil {
				log.Printf("Failed to parse pty_input message: %v", err)
				continue
			}
			c.manager.HandlePtyInput(&msg)

		case "pty_resize":
			var msg session.PtyResizeMessage
			if err := json.Unmarshal(raw, &msg); err != nil {
				log.Printf("Failed to parse pty_resize message: %v", err)
				continue
			}
			c.manager.HandlePtyResize(&msg)

		case "pty_close":
			var msg session.PtyCloseMessage
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
func (c *Client) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			return
		case <-ticker.C:
			if err := c.Send(HeartbeatMessage{Type: "heartbeat"}); err != nil {
				log.Printf("Failed to send heartbeat: %v", err)
				return
			}
		}
	}
}

// Send marshals msg to JSON and writes it to the WebSocket. Thread-safe.
func (c *Client) Send(msg interface{}) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return fmt.Errorf("not connected")
	}

	c.conn.SetWriteDeadline(time.Now().Add(writeWait))
	return c.conn.WriteJSON(msg)
}

// closeConn safely closes the WebSocket connection.
func (c *Client) closeConn() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}

	// Signal done to heartbeat loop (non-blocking).
	select {
	case c.done <- struct{}{}:
	default:
	}
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
