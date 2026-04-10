package session

import (
	"context"
	"encoding/base64"
	"log"
	"sync"

	"github.com/bisskar/sentinel-agent/internal/executor"
)

// Sender is the interface for sending messages back to the backend.
// This avoids a circular import with the connection package.
type Sender interface {
	Send(msg interface{}) error
}

// ExecMessage mirrors connection.ExecMessage to avoid circular imports.
type ExecMessage struct {
	Type              string `json:"type"`
	RequestID         string `json:"request_id"`
	Command           string `json:"command"`
	ExecutorName      string `json:"executor_name"`
	ElevationRequired bool   `json:"elevation_required"`
	TimeoutSeconds    int    `json:"timeout_seconds"`
}

// PtyOpenMessage mirrors connection.PtyOpenMessage.
type PtyOpenMessage struct {
	Type      string `json:"type"`
	SessionID string `json:"session_id"`
	TermType  string `json:"term_type"`
	Cols      int    `json:"cols"`
	Rows      int    `json:"rows"`
}

// PtyInputMessage mirrors connection.PtyInputMessage.
type PtyInputMessage struct {
	Type      string `json:"type"`
	SessionID string `json:"session_id"`
	Data      string `json:"data"`
}

// PtyResizeMessage mirrors connection.PtyResizeMessage.
type PtyResizeMessage struct {
	Type      string `json:"type"`
	SessionID string `json:"session_id"`
	Cols      int    `json:"cols"`
	Rows      int    `json:"rows"`
}

// PtyCloseMessage mirrors connection.PtyCloseMessage.
type PtyCloseMessage struct {
	Type      string `json:"type"`
	SessionID string `json:"session_id"`
}

// ExecResultMessage mirrors connection.ExecResultMessage.
type ExecResultMessage struct {
	Type            string  `json:"type"`
	RequestID       string  `json:"request_id"`
	Stdout          string  `json:"stdout"`
	Stderr          string  `json:"stderr"`
	ExitCode        int     `json:"exit_code"`
	DurationSeconds float64 `json:"duration_seconds"`
}

// PtyOutputMessage mirrors connection.PtyOutputMessage.
type PtyOutputMessage struct {
	Type      string `json:"type"`
	SessionID string `json:"session_id"`
	Data      string `json:"data"`
}

// PtyClosedMessage mirrors connection.PtyClosedMessage.
type PtyClosedMessage struct {
	Type      string `json:"type"`
	SessionID string `json:"session_id"`
	Reason    string `json:"reason"`
}

// Manager tracks concurrent command executions and PTY sessions.
type Manager struct {
	ptySessions sync.Map // sessionID -> *executor.PtySession
}

// NewManager creates a new session manager.
func NewManager() *Manager {
	return &Manager{}
}

// HandleExec executes the command directly (no encoding) and sends the result back.
// Commands are run in plain text so detection rules can see them in process events.
// Intended to be called in a goroutine.
func (m *Manager) HandleExec(msg *ExecMessage, sender Sender) {
	log.Printf("Executing command (request_id=%s, executor=%s)", msg.RequestID, msg.ExecutorName)

	stdout, stderr, exitCode, duration, err := executor.ExecuteCommand(
		context.Background(),
		msg.Command,
		msg.ExecutorName,
		msg.ElevationRequired,
		msg.TimeoutSeconds,
	)
	if err != nil {
		log.Printf("Command execution error (request_id=%s): %v", msg.RequestID, err)
	}

	result := ExecResultMessage{
		Type:            "exec_result",
		RequestID:       msg.RequestID,
		Stdout:          stdout,
		Stderr:          stderr,
		ExitCode:        exitCode,
		DurationSeconds: duration,
	}

	if err := sender.Send(result); err != nil {
		log.Printf("Failed to send exec result (request_id=%s): %v", msg.RequestID, err)
	}
}

// HandlePtyOpen creates a new PTY session and starts reading output.
// Intended to be called in a goroutine.
func (m *Manager) HandlePtyOpen(msg *PtyOpenMessage, sender Sender) {
	log.Printf("Opening PTY session %s (term=%s, %dx%d)", msg.SessionID, msg.TermType, msg.Cols, msg.Rows)

	session, err := executor.NewPtySession(msg.SessionID, msg.TermType, msg.Cols, msg.Rows)
	if err != nil {
		log.Printf("Failed to open PTY session %s: %v", msg.SessionID, err)
		sender.Send(PtyClosedMessage{
			Type:      "pty_closed",
			SessionID: msg.SessionID,
			Reason:    err.Error(),
		})
		return
	}

	m.ptySessions.Store(msg.SessionID, session)

	// Read loop sends PTY output back to the backend.
	session.ReadLoop(func(data []byte) {
		sender.Send(PtyOutputMessage{
			Type:      "pty_output",
			SessionID: msg.SessionID,
			Data:      string(data), // Already base64-encoded by ReadLoop.
		})
	})

	// ReadLoop returned — session ended.
	m.ptySessions.Delete(msg.SessionID)
	session.Close()

	sender.Send(PtyClosedMessage{
		Type:      "pty_closed",
		SessionID: msg.SessionID,
		Reason:    "session ended",
	})

	log.Printf("PTY session %s closed", msg.SessionID)
}

// HandlePtyInput decodes base64 input and writes it to the PTY.
func (m *Manager) HandlePtyInput(msg *PtyInputMessage) {
	val, ok := m.ptySessions.Load(msg.SessionID)
	if !ok {
		log.Printf("PTY input for unknown session %s", msg.SessionID)
		return
	}

	session := val.(*executor.PtySession)
	data, err := base64.StdEncoding.DecodeString(msg.Data)
	if err != nil {
		log.Printf("Failed to decode PTY input for session %s: %v", msg.SessionID, err)
		return
	}

	if _, err := session.Write(data); err != nil {
		log.Printf("Failed to write to PTY session %s: %v", msg.SessionID, err)
	}
}

// HandlePtyResize changes the window size of a PTY session.
func (m *Manager) HandlePtyResize(msg *PtyResizeMessage) {
	val, ok := m.ptySessions.Load(msg.SessionID)
	if !ok {
		log.Printf("PTY resize for unknown session %s", msg.SessionID)
		return
	}

	session := val.(*executor.PtySession)
	if err := session.Resize(msg.Cols, msg.Rows); err != nil {
		log.Printf("Failed to resize PTY session %s: %v", msg.SessionID, err)
	}
}

// HandlePtyClose closes a PTY session and removes it from the manager.
func (m *Manager) HandlePtyClose(msg *PtyCloseMessage) {
	val, ok := m.ptySessions.Load(msg.SessionID)
	if !ok {
		log.Printf("PTY close for unknown session %s", msg.SessionID)
		return
	}

	session := val.(*executor.PtySession)
	session.Close()
	m.ptySessions.Delete(msg.SessionID)
	log.Printf("PTY session %s closed by backend", msg.SessionID)
}

// CloseAll terminates all active PTY sessions. Used during graceful shutdown.
func (m *Manager) CloseAll() {
	m.ptySessions.Range(func(key, val interface{}) bool {
		session := val.(*executor.PtySession)
		session.Close()
		m.ptySessions.Delete(key)
		log.Printf("Closed PTY session %s during shutdown", key)
		return true
	})
}
