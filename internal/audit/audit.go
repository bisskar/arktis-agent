// Package audit writes one JSON line per exec / pty event to an
// operator-configured append-only file. The format is intentionally
// flat so operators can grep, jq, or ship it to a SIEM without a parser.
//
// Records are flushed under a mutex so concurrent handlers cannot
// interleave bytes within a single line, and the file is opened with
// O_APPEND so concurrent writers from the kernel are also line-atomic
// up to PIPE_BUF.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Logger writes JSON-line audit records. Logger is safe for concurrent use.
//
// If Path is empty the constructor returns a Logger whose methods are
// no-ops, which lets call sites omit `if a != nil` checks.
type Logger struct {
	mu             sync.Mutex
	w              io.Writer // nil = disabled
	closer         io.Closer // closed by Close; nil for stub loggers
	includeCommand bool
}

// Open returns a Logger that writes to path with mode 0600 (O_APPEND|O_CREAT).
// An empty path returns a no-op Logger.
//
// path is intentionally operator-controlled — it comes from the
// --audit-log CLI flag (or ARKTIS_AUDIT_LOG) and the operator chooses
// where the agent's audit trail lives. gosec's G304 file-inclusion
// rule does not apply here.
func Open(path string, includeCommand bool) (*Logger, error) {
	if path == "" {
		return &Logger{}, nil
	}
	// #nosec G304 -- path is the operator-supplied audit log location.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log %s: %w", path, err)
	}
	return &Logger{w: f, closer: f, includeCommand: includeCommand}, nil
}

// Close flushes and closes the underlying file. Safe to call on a no-op
// Logger.
func (l *Logger) Close() error {
	if l == nil || l.closer == nil {
		return nil
	}
	return l.closer.Close()
}

// ExecRequest records that the agent received an exec command.
type ExecRequest struct {
	RequestID         string
	Executor          string
	ElevationRequired bool
	TimeoutSeconds    int
	Command           string // hashed unless Logger.includeCommand
}

// ExecResult records the outcome of an exec command.
type ExecResult struct {
	RequestID       string
	ExitCode        int
	DurationSeconds float64
	StdoutBytes     int
	StderrBytes     int
	StdoutTruncated bool
	StderrTruncated bool
}

// PtyOpen records the start of an interactive PTY session.
type PtyOpen struct {
	SessionID string
	TermType  string
	Cols      int
	Rows      int
}

// PtyClose records the end of an interactive PTY session.
type PtyClose struct {
	SessionID string
	Reason    string
}

// LogExecRequest writes an "exec_request" record.
func (l *Logger) LogExecRequest(r ExecRequest) {
	if l == nil || l.w == nil {
		return
	}
	rec := map[string]interface{}{
		"event":              "exec_request",
		"request_id":         r.RequestID,
		"executor":           r.Executor,
		"elevation_required": r.ElevationRequired,
		"timeout_seconds":    r.TimeoutSeconds,
	}
	if l.includeCommand {
		rec["command"] = r.Command
	} else {
		rec["command_sha256"] = hashCmd(r.Command)
		rec["command_bytes"] = len(r.Command)
	}
	l.write(rec)
}

// LogExecResult writes an "exec_result" record.
func (l *Logger) LogExecResult(r ExecResult) {
	if l == nil || l.w == nil {
		return
	}
	l.write(map[string]interface{}{
		"event":            "exec_result",
		"request_id":       r.RequestID,
		"exit_code":        r.ExitCode,
		"duration_seconds": r.DurationSeconds,
		"stdout_bytes":     r.StdoutBytes,
		"stderr_bytes":     r.StderrBytes,
		"stdout_truncated": r.StdoutTruncated,
		"stderr_truncated": r.StderrTruncated,
	})
}

// LogPtyOpen writes a "pty_open" record.
func (l *Logger) LogPtyOpen(r PtyOpen) {
	if l == nil || l.w == nil {
		return
	}
	l.write(map[string]interface{}{
		"event":      "pty_open",
		"session_id": r.SessionID,
		"term_type":  r.TermType,
		"cols":       r.Cols,
		"rows":       r.Rows,
	})
}

// LogPtyClose writes a "pty_close" record.
func (l *Logger) LogPtyClose(r PtyClose) {
	if l == nil || l.w == nil {
		return
	}
	l.write(map[string]interface{}{
		"event":      "pty_close",
		"session_id": r.SessionID,
		"reason":     r.Reason,
	})
}

func (l *Logger) write(rec map[string]interface{}) {
	rec["ts"] = time.Now().UTC().Format(time.RFC3339Nano)
	line, err := json.Marshal(rec)
	if err != nil {
		// Marshalling a map with primitives shouldn't fail; drop on error.
		return
	}
	line = append(line, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	// Best-effort write — the audit file might be on a noexec/full disk.
	// We don't surface the error here because the caller is the request
	// handler; logging would create a feedback loop with the audit log.
	_, _ = l.w.Write(line)
}

func hashCmd(cmd string) string {
	sum := sha256.Sum256([]byte(cmd))
	return hex.EncodeToString(sum[:])
}
