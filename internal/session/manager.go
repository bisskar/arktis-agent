package session

import (
	"context"
	"encoding/base64"
	"log"
	"sync"

	"github.com/bisskar/arktis-agent/internal/audit"
	"github.com/bisskar/arktis-agent/internal/executor"
	"github.com/bisskar/arktis-agent/internal/protocol"
)

// Sender is the interface for sending messages back to the backend.
// The connection package's *Client satisfies it.
type Sender interface {
	Send(msg interface{}) error
}

// Default capacity caps. Operators can override via Config.
const (
	defaultMaxExec = 8
	defaultMaxPty  = 4
)

// Config bundles operator-tunable knobs that flow from main into the
// Manager. ScriptsDir is required; everything else falls back to safe
// defaults documented above.
type Config struct {
	ScriptsDir     string
	MaxExec        int
	MaxPty         int
	AllowElevation bool
	Audit          *audit.Logger // nil-safe; methods no-op when unset
}

// Manager tracks concurrent command executions and PTY sessions and
// enforces the agent's local policy: capacity limits (#16), duplicate
// session_id rejection (#12), and the elevation opt-in gate (#6).
type Manager struct {
	scriptsDir     string
	allowElevation bool
	execSem        chan struct{}
	ptySem         chan struct{}
	audit          *audit.Logger

	ptySessions sync.Map // sessionID -> *executor.PtySession
}

// NewManager creates a new session manager.
func NewManager(cfg Config) *Manager {
	if cfg.MaxExec <= 0 {
		cfg.MaxExec = defaultMaxExec
	}
	if cfg.MaxPty <= 0 {
		cfg.MaxPty = defaultMaxPty
	}
	return &Manager{
		scriptsDir:     cfg.ScriptsDir,
		allowElevation: cfg.AllowElevation,
		execSem:        make(chan struct{}, cfg.MaxExec),
		ptySem:         make(chan struct{}, cfg.MaxPty),
		audit:          cfg.Audit,
	}
}

// HandleExec executes the command directly (no encoding) and sends the
// result back. Commands are run in plain text so detection rules can see
// them in process events. Intended to be called in a goroutine.
//
// ctx is the agent's root context — cancelling it (e.g. on SIGTERM) will
// kill the child process so we don't block shutdown waiting for a long
// command to finish.
func (m *Manager) HandleExec(ctx context.Context, msg *protocol.ExecMessage, sender Sender) {
	if !validID(msg.RequestID) {
		log.Printf("Rejecting exec with invalid request_id %q", msg.RequestID)
		return
	}

	// Capacity gate: refuse rather than queue when at the configured limit.
	select {
	case m.execSem <- struct{}{}:
		defer func() { <-m.execSem }()
	default:
		log.Printf("Rejecting exec request_id=%q: agent at exec capacity", msg.RequestID)
		sender.Send(protocol.ExecResultMessage{
			Type:       "exec_result",
			RequestID:  msg.RequestID,
			Stderr:     "agent at exec capacity, retry later",
			StderrSafe: "agent at exec capacity, retry later",
			ExitCode:   503,
		})
		return
	}

	// Elevation gate: refuse unless the operator explicitly opted in.
	if msg.ElevationRequired && !m.allowElevation {
		log.Printf("Rejecting elevated exec request_id=%q: --allow-elevation not set", msg.RequestID)
		const reason = "elevation refused: agent started without --allow-elevation"
		sender.Send(protocol.ExecResultMessage{
			Type:       "exec_result",
			RequestID:  msg.RequestID,
			Stderr:     reason,
			StderrSafe: reason,
			ExitCode:   126,
		})
		return
	}
	if msg.ElevationRequired {
		log.Printf("Running elevated command (request_id=%q, executor=%q)", msg.RequestID, msg.ExecutorName)
	} else {
		log.Printf("Executing command (request_id=%q, executor=%q)", msg.RequestID, msg.ExecutorName)
	}

	m.audit.LogExecRequest(audit.ExecRequest{
		RequestID:         msg.RequestID,
		Executor:          msg.ExecutorName,
		ElevationRequired: msg.ElevationRequired,
		TimeoutSeconds:    msg.TimeoutSeconds,
		Command:           msg.Command,
	})

	res, err := executor.ExecuteCommand(executor.ExecRequest{
		Ctx:                ctx,
		ScriptsDir:         m.scriptsDir,
		Command:            msg.Command,
		ExecutorName:       msg.ExecutorName,
		ElevationRequired:  msg.ElevationRequired,
		TimeoutSeconds:     msg.TimeoutSeconds,
		SilencePreferences: msg.SilencePreferences,
	})
	if err != nil {
		log.Printf("Command execution error (request_id=%q): %v", msg.RequestID, err)
	}

	out := protocol.ExecResultMessage{
		Type:            "exec_result",
		RequestID:       msg.RequestID,
		Stdout:          res.Stdout,
		Stderr:          res.Stderr,
		StdoutSafe:      sanitizeOutput(res.Stdout),
		StderrSafe:      sanitizeOutput(res.Stderr),
		StdoutTruncated: res.StdoutTruncated,
		StderrTruncated: res.StderrTruncated,
		ExitCode:        res.ExitCode,
		DurationSeconds: res.DurationSeconds,
	}

	m.audit.LogExecResult(audit.ExecResult{
		RequestID:       msg.RequestID,
		ExitCode:        res.ExitCode,
		DurationSeconds: res.DurationSeconds,
		StdoutBytes:     len(res.Stdout),
		StderrBytes:     len(res.Stderr),
		StdoutTruncated: res.StdoutTruncated,
		StderrTruncated: res.StderrTruncated,
	})

	if err := sender.Send(out); err != nil {
		log.Printf("Failed to send exec result (request_id=%q): %v", msg.RequestID, err)
	}
}

// ptyPlaceholder marks a session_id slot as reserved while NewPtySession
// is running, so a duplicate pty_open arriving in the meantime sees the
// slot is taken (#12) without dereferencing a nil session.
type ptyPlaceholder struct{}

// HandlePtyOpen creates a new PTY session and starts reading output.
// Intended to be called in a goroutine.
func (m *Manager) HandlePtyOpen(msg *protocol.PtyOpenMessage, sender Sender) {
	if !validID(msg.SessionID) {
		log.Printf("Rejecting pty_open with invalid session_id %q", msg.SessionID)
		sender.Send(protocol.PtyClosedMessage{
			Type:      "pty_closed",
			SessionID: msg.SessionID,
			Reason:    "invalid session_id",
		})
		return
	}

	// Capacity gate.
	select {
	case m.ptySem <- struct{}{}:
		defer func() { <-m.ptySem }()
	default:
		log.Printf("Rejecting pty_open session_id=%q: agent at pty capacity", msg.SessionID)
		sender.Send(protocol.PtyClosedMessage{
			Type:      "pty_closed",
			SessionID: msg.SessionID,
			Reason:    "agent at pty capacity",
		})
		return
	}

	// Reserve the slot atomically; a duplicate session_id sees the
	// placeholder and is rejected without orphaning a real session.
	placeholder := ptyPlaceholder{}
	if _, loaded := m.ptySessions.LoadOrStore(msg.SessionID, placeholder); loaded {
		log.Printf("Rejecting pty_open session_id=%q: duplicate", msg.SessionID)
		sender.Send(protocol.PtyClosedMessage{
			Type:      "pty_closed",
			SessionID: msg.SessionID,
			Reason:    "duplicate session_id",
		})
		return
	}

	log.Printf("Opening PTY session_id=%q (term=%q, %dx%d)", msg.SessionID, msg.TermType, msg.Cols, msg.Rows)
	m.audit.LogPtyOpen(audit.PtyOpen{
		SessionID: msg.SessionID,
		TermType:  msg.TermType,
		Cols:      msg.Cols,
		Rows:      msg.Rows,
	})

	session, err := executor.NewPtySession(msg.SessionID, msg.TermType, msg.Cols, msg.Rows)
	if err != nil {
		log.Printf("Failed to open PTY session_id=%q: %v", msg.SessionID, err)
		// Drop the placeholder we reserved.
		m.ptySessions.CompareAndDelete(msg.SessionID, placeholder)
		sender.Send(protocol.PtyClosedMessage{
			Type:      "pty_closed",
			SessionID: msg.SessionID,
			Reason:    err.Error(),
		})
		return
	}

	// Replace the placeholder with the real session pointer.
	m.ptySessions.Store(msg.SessionID, session)

	// Read loop sends PTY output back to the backend. ErrSendBufferFull
	// from the writer goroutine is treated as a per-frame drop (logged
	// once per session, not per frame) so a chatty PTY doesn't spam.
	dropLogged := false
	session.ReadLoop(func(data []byte) {
		err := sender.Send(protocol.PtyOutputMessage{
			Type:      "pty_output",
			SessionID: msg.SessionID,
			Data:      string(data), // Already base64-encoded by ReadLoop.
		})
		if err != nil && !dropLogged {
			log.Printf("Dropping PTY output for session_id=%q (writer at capacity): %v", msg.SessionID, err)
			dropLogged = true
		}
	})

	// ReadLoop returned — session ended. Compare-and-delete so a later
	// pty_open with the same session_id (which would have been rejected
	// above as a duplicate) doesn't get its entry removed by us.
	m.ptySessions.CompareAndDelete(msg.SessionID, session)
	if err := session.Close(); err != nil {
		log.Printf("PTY close error for session_id=%q: %v", msg.SessionID, err)
	}

	sender.Send(protocol.PtyClosedMessage{
		Type:      "pty_closed",
		SessionID: msg.SessionID,
		Reason:    "session ended",
	})

	m.audit.LogPtyClose(audit.PtyClose{SessionID: msg.SessionID, Reason: "session ended"})
	log.Printf("PTY session_id=%q closed", msg.SessionID)
}

// HandlePtyInput decodes base64 input and writes it to the PTY.
func (m *Manager) HandlePtyInput(msg *protocol.PtyInputMessage) {
	if !validID(msg.SessionID) {
		log.Printf("Rejecting pty_input with invalid session_id %q", msg.SessionID)
		return
	}

	val, ok := m.ptySessions.Load(msg.SessionID)
	if !ok {
		log.Printf("PTY input for unknown session_id=%q", msg.SessionID)
		return
	}
	session, ok := val.(*executor.PtySession)
	if !ok {
		// Placeholder still in place — session not ready yet.
		log.Printf("PTY input for not-yet-ready session_id=%q", msg.SessionID)
		return
	}

	data, err := base64.StdEncoding.DecodeString(msg.Data)
	if err != nil {
		log.Printf("Failed to decode PTY input for session_id=%q: %v", msg.SessionID, err)
		return
	}

	if _, err := session.Write(data); err != nil {
		log.Printf("Failed to write to PTY session_id=%q: %v", msg.SessionID, err)
	}
}

// HandlePtyResize changes the window size of a PTY session.
func (m *Manager) HandlePtyResize(msg *protocol.PtyResizeMessage) {
	if !validID(msg.SessionID) {
		log.Printf("Rejecting pty_resize with invalid session_id %q", msg.SessionID)
		return
	}

	val, ok := m.ptySessions.Load(msg.SessionID)
	if !ok {
		log.Printf("PTY resize for unknown session_id=%q", msg.SessionID)
		return
	}
	session, ok := val.(*executor.PtySession)
	if !ok {
		log.Printf("PTY resize for not-yet-ready session_id=%q", msg.SessionID)
		return
	}

	if err := session.Resize(msg.Cols, msg.Rows); err != nil {
		log.Printf("Failed to resize PTY session_id=%q: %v", msg.SessionID, err)
	}
}

// HandlePtyClose closes a PTY session and removes it from the manager.
func (m *Manager) HandlePtyClose(msg *protocol.PtyCloseMessage) {
	if !validID(msg.SessionID) {
		log.Printf("Rejecting pty_close with invalid session_id %q", msg.SessionID)
		return
	}

	val, ok := m.ptySessions.Load(msg.SessionID)
	if !ok {
		log.Printf("PTY close for unknown session_id=%q", msg.SessionID)
		return
	}
	session, ok := val.(*executor.PtySession)
	if !ok {
		// Placeholder — let HandlePtyOpen finish setup and then exit normally.
		log.Printf("PTY close for not-yet-ready session_id=%q", msg.SessionID)
		return
	}

	if err := session.Close(); err != nil {
		log.Printf("PTY close error for session_id=%q: %v", msg.SessionID, err)
	}
	m.ptySessions.CompareAndDelete(msg.SessionID, session)
	log.Printf("PTY session_id=%q closed by backend", msg.SessionID)
}

// CloseAll terminates all active PTY sessions. Used during graceful shutdown.
func (m *Manager) CloseAll() {
	m.ptySessions.Range(func(key, val interface{}) bool {
		session, ok := val.(*executor.PtySession)
		if ok {
			if err := session.Close(); err != nil {
				log.Printf("PTY close error for session_id=%q during shutdown: %v", key, err)
			}
			log.Printf("Closed PTY session_id=%q during shutdown", key)
		}
		m.ptySessions.Delete(key)
		return true
	})
}
