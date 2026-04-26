// Package protocol defines the wire-format messages exchanged between
// the arktis-agent and its backend over the WebSocket connection.
//
// It is a leaf package with no dependencies on other internal packages,
// which lets both connection (the transport) and session (the handlers)
// share a single set of struct definitions instead of mirroring them and
// risking silent drift when fields are added or renamed.
package protocol

// ---------------------------------------------------------------------------
// Outbound messages (agent -> backend)
// ---------------------------------------------------------------------------

// RegisterMessage is sent on every WebSocket connect to identify the agent.
type RegisterMessage struct {
	Type         string `json:"type"`              // "register"
	HostID       string `json:"host_id,omitempty"` // empty on first connect
	Hostname     string `json:"hostname"`
	Platform     string `json:"platform"` // "windows" or "linux"
	OsFamily     string `json:"os_family"`
	OsVersion    string `json:"os_version"`
	AgentVersion string `json:"agent_version"`
}

// HeartbeatMessage keeps the connection alive.
type HeartbeatMessage struct {
	Type string `json:"type"` // "heartbeat"
}

// ExecResultMessage reports the outcome of a command execution.
//
// stdout/stderr carry the process bytes verbatim (after the 1 MiB cap)
// for terminal-aware consumers. stdout_safe/stderr_safe are the same
// content with C0 control chars escaped, suitable for plain-text logs
// and SIEM ingestion that would otherwise be vulnerable to log/terminal
// injection from third-party command output.
type ExecResultMessage struct {
	Type            string  `json:"type"` // "exec_result"
	RequestID       string  `json:"request_id"`
	Stdout          string  `json:"stdout"`
	Stderr          string  `json:"stderr"`
	StdoutSafe      string  `json:"stdout_safe"`
	StderrSafe      string  `json:"stderr_safe"`
	StdoutTruncated bool    `json:"stdout_truncated"`
	StderrTruncated bool    `json:"stderr_truncated"`
	ExitCode        int     `json:"exit_code"`
	DurationSeconds float64 `json:"duration_seconds"`
}

// PtyOutputMessage carries PTY output back to the backend.
type PtyOutputMessage struct {
	Type      string `json:"type"` // "pty_output"
	SessionID string `json:"session_id"`
	Data      string `json:"data"` // base64-encoded
}

// PtyClosedMessage notifies the backend that a PTY session ended.
type PtyClosedMessage struct {
	Type      string `json:"type"` // "pty_closed"
	SessionID string `json:"session_id"`
	Reason    string `json:"reason"`
}

// ---------------------------------------------------------------------------
// Inbound messages (backend -> agent)
// ---------------------------------------------------------------------------

// AckMessage confirms registration and assigns a host_id.
type AckMessage struct {
	Type   string `json:"type"` // "ack"
	HostID string `json:"host_id"`
}

// ExecMessage requests command execution on the host.
//
// SilencePreferences is opt-in per-test PowerShell preference suppression
// ($ProgressPreference / $WarningPreference / $InformationPreference set
// to SilentlyContinue, $ErrorActionPreference forced to Continue). Default
// is false so PowerShell errors fail loudly rather than masking real
// failures as "no output, exit 0".
//
// Signature / SignedAt provide optional per-message authentication. When
// the agent is started with --signing-pubkey-file, it verifies the
// Ed25519 signature over the canonical bytes returned by SigInputExec.
// Backends that don't sign yet leave both fields empty.
type ExecMessage struct {
	Type               string `json:"type"` // "exec"
	RequestID          string `json:"request_id"`
	Command            string `json:"command"`
	ExecutorName       string `json:"executor_name"` // powershell, bash, sh, command_prompt
	ElevationRequired  bool   `json:"elevation_required"`
	TimeoutSeconds     int    `json:"timeout_seconds"`
	SilencePreferences bool   `json:"silence_preferences,omitempty"`
	SignedAt           string `json:"signed_at,omitempty"` // RFC3339 timestamp
	Signature          string `json:"signature,omitempty"` // base64 Ed25519 signature
}

// PtyOpenMessage requests a new interactive terminal session.
//
// See ExecMessage for the meaning of Signature / SignedAt.
type PtyOpenMessage struct {
	Type      string `json:"type"` // "pty_open"
	SessionID string `json:"session_id"`
	TermType  string `json:"term_type"`
	Cols      int    `json:"cols"`
	Rows      int    `json:"rows"`
	SignedAt  string `json:"signed_at,omitempty"` // RFC3339 timestamp
	Signature string `json:"signature,omitempty"` // base64 Ed25519 signature
}

// PtyInputMessage carries user keystrokes to the PTY.
type PtyInputMessage struct {
	Type      string `json:"type"` // "pty_input"
	SessionID string `json:"session_id"`
	Data      string `json:"data"` // base64-encoded
}

// PtyResizeMessage requests a terminal size change.
type PtyResizeMessage struct {
	Type      string `json:"type"` // "pty_resize"
	SessionID string `json:"session_id"`
	Cols      int    `json:"cols"`
	Rows      int    `json:"rows"`
}

// PtyCloseMessage requests closing an interactive terminal session.
type PtyCloseMessage struct {
	Type      string `json:"type"` // "pty_close"
	SessionID string `json:"session_id"`
}

// ---------------------------------------------------------------------------
// Generic envelope for initial type dispatch
// ---------------------------------------------------------------------------

// BaseMessage is used to peek at the "type" field before full deserialization.
type BaseMessage struct {
	Type string `json:"type"`
}
