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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
//
// When ChainKeyPath is set, every record carries an HMAC-SHA256 "mac"
// field over (previous_mac || record_without_mac). Tampering with any
// past line therefore breaks the chain at that line: a verifier walks
// from the genesis MAC and recomputes each one. The key is generated
// at first run and persisted with mode 0600 so the chain survives
// restarts; rotating the file restarts the chain.
type Logger struct {
	mu             sync.Mutex
	w              io.Writer // nil = disabled
	closer         io.Closer // closed by Close; nil for stub loggers
	includeCommand bool
	chainKey       []byte // nil when chaining disabled
	prevMAC        []byte // 32 bytes when chainKey is set; otherwise nil
}

// Options bundles construction parameters for Open.
type Options struct {
	Path           string // audit file; empty => no-op Logger
	IncludeCommand bool   // log full command body (default: SHA-256 only)
	ChainKeyPath   string // file storing the HMAC chain key; empty => no chain
}

// Open returns a Logger that writes to opts.Path with mode 0600
// (O_APPEND|O_CREAT). An empty Path returns a no-op Logger.
//
// Path and ChainKeyPath are intentionally operator-controlled — they
// come from CLI flags (or env vars) and the operator chooses where
// the agent's audit trail and chain key live. gosec's G304
// file-inclusion rule does not apply here.
func Open(opts Options) (*Logger, error) {
	if opts.Path == "" {
		return &Logger{}, nil
	}
	// #nosec G304 -- path is the operator-supplied audit log location.
	f, err := os.OpenFile(opts.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log %s: %w", opts.Path, err)
	}
	l := &Logger{w: f, closer: f, includeCommand: opts.IncludeCommand}
	if opts.ChainKeyPath != "" {
		key, err := loadOrCreateChainKey(opts.ChainKeyPath)
		if err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("load chain key: %w", err)
		}
		l.chainKey = key
		l.prevMAC = make([]byte, sha256.Size) // genesis MAC is all-zero
	}
	return l, nil
}

// loadOrCreateChainKey reads a 32-byte HMAC key from path, or generates
// one and writes it (mode 0600) on first run. The key MUST be kept
// secret — anyone with read access can forge chain MACs.
func loadOrCreateChainKey(path string) ([]byte, error) {
	// #nosec G304 -- operator-supplied chain key path.
	if raw, err := os.ReadFile(path); err == nil {
		if len(raw) != sha256.Size {
			return nil, fmt.Errorf("chain key %s has unexpected size %d (want %d)",
				path, len(raw), sha256.Size)
		}
		return raw, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	key := make([]byte, sha256.Size)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate chain key: %w", err)
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return nil, fmt.Errorf("write chain key %s: %w", path, err)
	}
	return key, nil
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

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.chainKey != nil {
		// Marshal once without the mac field to get the canonical bytes
		// the verifier will reproduce, then re-marshal with the mac
		// embedded. Go's json.Marshal sorts map keys, so producer and
		// verifier observe the same byte sequence.
		base, err := json.Marshal(rec)
		if err != nil {
			return
		}
		mac := hmac.New(sha256.New, l.chainKey)
		_, _ = mac.Write(l.prevMAC)
		_, _ = mac.Write(base)
		sum := mac.Sum(nil)
		rec["mac"] = hex.EncodeToString(sum)
		l.prevMAC = sum
	}

	line, err := json.Marshal(rec)
	if err != nil {
		return
	}
	line = append(line, '\n')
	_, _ = l.w.Write(line)
}

// genesisMAC is exposed for verifier tooling: the first record in a
// chain is HMAC'd against this all-zero seed.
var genesisMAC = make([]byte, sha256.Size)

// errChainBroken is returned by Verify on the first chain mismatch.
var errChainBroken = errors.New("audit chain mismatch")

// Verify reads a JSONL audit log at path and recomputes every record's
// chain MAC against key. Returns the line number (1-based) of the first
// mismatch, or 0 if the entire chain is intact. Lines that don't carry
// a "mac" field are skipped (treated as pre-chain).
//
// This is exposed for operator/forensic tooling — the agent itself
// only writes; verification happens out-of-band.
func Verify(path string, key []byte) (int, error) {
	// #nosec G304 -- operator-supplied audit log path.
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	prev := genesisMAC
	lineNo := 0
	for _, lineBytes := range splitLines(raw) {
		lineNo++
		var rec map[string]interface{}
		if err := json.Unmarshal(lineBytes, &rec); err != nil {
			return lineNo, fmt.Errorf("line %d: parse: %w", lineNo, err)
		}
		macHex, ok := rec["mac"].(string)
		if !ok {
			continue // not a chained line
		}
		got, err := hex.DecodeString(macHex)
		if err != nil {
			return lineNo, fmt.Errorf("line %d: mac decode: %w", lineNo, err)
		}
		delete(rec, "mac")
		base, err := json.Marshal(rec)
		if err != nil {
			return lineNo, fmt.Errorf("line %d: re-marshal: %w", lineNo, err)
		}
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write(prev)
		_, _ = mac.Write(base)
		want := mac.Sum(nil)
		if !hmac.Equal(got, want) {
			return lineNo, errChainBroken
		}
		prev = got
	}
	return 0, nil
}

func splitLines(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, c := range b {
		if c == '\n' {
			if i > start {
				out = append(out, b[start:i])
			}
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, b[start:])
	}
	return out
}

func hashCmd(cmd string) string {
	sum := sha256.Sum256([]byte(cmd))
	return hex.EncodeToString(sum[:])
}
