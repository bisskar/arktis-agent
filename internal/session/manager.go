package session

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"log"
	"sync"
	"time"

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
	defaultMaxExec  = 8
	defaultMaxPty   = 4
	replayCacheSize = 1024
	replayWindow    = 10 * time.Minute
)

// Config bundles operator-tunable knobs that flow from main into the
// Manager. ScriptsDir is required; everything else falls back to safe
// defaults documented above.
type Config struct {
	ScriptsDir     string
	ReplayDir      string // dir to persist replay state under (typically StateDir); empty disables persistence
	MaxExec        int
	MaxPty         int
	AllowElevation bool
	Audit          *audit.Logger // nil-safe; methods no-op when unset

	// SigningPubkey, when set, enables Ed25519 verification of every
	// inbound exec / pty_open. RequireSignature controls whether
	// unsigned messages are rejected (true) or allowed-with-warning
	// (false, the default).
	SigningPubkey    ed25519.PublicKey
	RequireSignature bool
}

// Manager tracks concurrent command executions and PTY sessions and
// enforces the agent's local policy: capacity limits (#16), duplicate
// session_id rejection (#12), the elevation opt-in gate (#6), replay
// protection (#15), and (optional) per-message Ed25519 verification (#9).
type Manager struct {
	scriptsDir       string
	replayDir        string
	allowElevation   bool
	execSem          chan struct{}
	ptySem           chan struct{}
	audit            *audit.Logger
	execReplay       *Tracker
	ptyReplay        *Tracker
	signingPubkey    ed25519.PublicKey
	requireSignature bool
	now              func() time.Time // injectable for tests

	ptySessions sync.Map // sessionID -> *executor.PtySession
}

// NewManager creates a new session manager. If cfg.ReplayDir is set,
// the replay seen-set is rehydrated from disk and saved on shutdown so
// a process restart does not re-open the replay window.
func NewManager(cfg Config) *Manager {
	if cfg.MaxExec <= 0 {
		cfg.MaxExec = defaultMaxExec
	}
	if cfg.MaxPty <= 0 {
		cfg.MaxPty = defaultMaxPty
	}
	m := &Manager{
		scriptsDir:       cfg.ScriptsDir,
		replayDir:        cfg.ReplayDir,
		allowElevation:   cfg.AllowElevation,
		execSem:          make(chan struct{}, cfg.MaxExec),
		ptySem:           make(chan struct{}, cfg.MaxPty),
		audit:            cfg.Audit,
		execReplay:       NewTracker(replayCacheSize, replayWindow),
		ptyReplay:        NewTracker(replayCacheSize, replayWindow),
		signingPubkey:    cfg.SigningPubkey,
		requireSignature: cfg.RequireSignature,
		now:              time.Now,
	}
	if cfg.ReplayDir != "" {
		if err := m.execReplay.Load(execReplayPath(cfg.ReplayDir)); err != nil {
			log.Printf("Warning: failed to load exec replay state: %v", err)
		}
		if err := m.ptyReplay.Load(ptyReplayPath(cfg.ReplayDir)); err != nil {
			log.Printf("Warning: failed to load pty replay state: %v", err)
		}
	}
	return m
}

func execReplayPath(dir string) string { return dir + "/replay-exec.json" }
func ptyReplayPath(dir string) string  { return dir + "/replay-pty.json" }

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

	// Signature gate (#9). Enforced only when --signing-pubkey-file is
	// configured. Unsigned messages are rejected when --require-message-
	// signature is set, otherwise allowed with a warning.
	if err := verifySig(m.signingPubkey, protocol.SigInputExec(msg), msg.Signature, msg.SignedAt, m.now()); err != nil {
		if errors.Is(err, errMissingSignature) && !m.requireSignature {
			if m.signingPubkey != nil {
				log.Printf("Warning: unsigned exec request_id=%q (--require-message-signature not set)", msg.RequestID)
			}
			// fall through and run
		} else {
			log.Printf("Rejecting exec request_id=%q: %v", msg.RequestID, err)
			const reason = "signature verification failed"
			_ = sender.Send(protocol.ExecResultMessage{
				Type:       "exec_result",
				RequestID:  msg.RequestID,
				Stderr:     reason,
				StderrSafe: reason,
				ExitCode:   401,
			})
			return
		}
	}

	// Replay gate: a captured exec frame can be replayed indefinitely
	// without per-message signing (#9). Until then, reject any
	// request_id seen within replayWindow with a structured 409.
	if m.execReplay.Seen(msg.RequestID) {
		log.Printf("Rejecting replayed exec request_id=%q", msg.RequestID)
		const reason = "replayed request_id"
		_ = sender.Send(protocol.ExecResultMessage{
			Type:       "exec_result",
			RequestID:  msg.RequestID,
			Stderr:     reason,
			StderrSafe: reason,
			ExitCode:   409,
		})
		return
	}

	// Capacity gate: refuse rather than queue when at the configured limit.
	select {
	case m.execSem <- struct{}{}:
		defer func() { <-m.execSem }()
	default:
		log.Printf("Rejecting exec request_id=%q: agent at exec capacity", msg.RequestID)
		_ = sender.Send(protocol.ExecResultMessage{
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
		_ = sender.Send(protocol.ExecResultMessage{
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
		_ = sender.Send(protocol.PtyClosedMessage{
			Type:      "pty_closed",
			SessionID: msg.SessionID,
			Reason:    "invalid session_id",
		})
		return
	}

	if err := verifySig(m.signingPubkey, protocol.SigInputPtyOpen(msg), msg.Signature, msg.SignedAt, m.now()); err != nil {
		if errors.Is(err, errMissingSignature) && !m.requireSignature {
			if m.signingPubkey != nil {
				log.Printf("Warning: unsigned pty_open session_id=%q", msg.SessionID)
			}
		} else {
			log.Printf("Rejecting pty_open session_id=%q: %v", msg.SessionID, err)
			_ = sender.Send(protocol.PtyClosedMessage{
				Type:      "pty_closed",
				SessionID: msg.SessionID,
				Reason:    "signature verification failed",
			})
			return
		}
	}

	// Replay gate: same rationale as HandleExec.
	if m.ptyReplay.Seen(msg.SessionID) {
		log.Printf("Rejecting replayed pty_open session_id=%q", msg.SessionID)
		_ = sender.Send(protocol.PtyClosedMessage{
			Type:      "pty_closed",
			SessionID: msg.SessionID,
			Reason:    "replayed session_id",
		})
		return
	}

	// Capacity gate.
	select {
	case m.ptySem <- struct{}{}:
		defer func() { <-m.ptySem }()
	default:
		log.Printf("Rejecting pty_open session_id=%q: agent at pty capacity", msg.SessionID)
		_ = sender.Send(protocol.PtyClosedMessage{
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
		_ = sender.Send(protocol.PtyClosedMessage{
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
		_ = sender.Send(protocol.PtyClosedMessage{
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

	_ = sender.Send(protocol.PtyClosedMessage{
		Type:      "pty_closed",
		SessionID: msg.SessionID,
		Reason:    "session ended",
	})

	m.audit.LogPtyClose(audit.PtyClose{SessionID: msg.SessionID, Reason: "session ended"})
	log.Printf("PTY session_id=%q closed", msg.SessionID)
}

// maxPtyInputBase64 caps the base64-encoded PTY input we'll decode in
// one frame. The wire-level cap (maxFrameBytes in connection) already
// bounds the entire JSON frame, but keeping a tighter pty_input ceiling
// here protects the session-level decode buffer specifically.
const maxPtyInputBase64 = 1 * 1024 * 1024 // 1 MiB encoded ~= 768 KiB raw

// HandlePtyInput decodes base64 input and writes it to the PTY.
func (m *Manager) HandlePtyInput(msg *protocol.PtyInputMessage) {
	if !validID(msg.SessionID) {
		log.Printf("Rejecting pty_input with invalid session_id %q", msg.SessionID)
		return
	}
	if len(msg.Data) > maxPtyInputBase64 {
		log.Printf("Rejecting oversize pty_input for session_id=%q (%d bytes)", msg.SessionID, len(msg.Data))
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

// CloseAll terminates all active PTY sessions and persists the replay
// seen-set. Used during graceful shutdown.
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

	if m.replayDir != "" {
		if err := m.execReplay.Save(execReplayPath(m.replayDir)); err != nil {
			log.Printf("Warning: failed to save exec replay state: %v", err)
		}
		if err := m.ptyReplay.Save(ptyReplayPath(m.replayDir)); err != nil {
			log.Printf("Warning: failed to save pty replay state: %v", err)
		}
	}
}
