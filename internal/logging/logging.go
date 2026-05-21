// Package logging owns the agent's log destination policy. The default
// path is OS-specific and predictable so support can ask "paste the last
// 30 lines of agent.log" without a treasure hunt, and rotation keeps the
// disk footprint bounded.
package logging

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

const (
	// MaxSizeBytes is the per-file rotation threshold (5 MiB).
	MaxSizeBytes int64 = 5 * 1024 * 1024
	// MaxFiles is the number of rotated files retained (current + 4 archives).
	MaxFiles = 5
)

// DefaultPath returns the canonical log-file path for the current OS.
// Operators that want a different location pass --log-file.
func DefaultPath() string {
	switch runtime.GOOS {
	case "windows":
		// %ProgramData% is writable by elevated-install processes and is
		// not user-roaming; the right home for a service log on Windows.
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		return filepath.Join(pd, "arktis-agent", "agent.log")
	case "darwin":
		return filepath.Join("/Library/Logs/arktis-agent", "agent.log")
	default:
		// Linux + every other Unix.
		return filepath.Join("/var/log/arktis-agent", "agent.log")
	}
}

// Setup teas the stdlib `log` package's output through a rotating
// file plus the original writer (typically stderr) so journalctl /
// PowerShell sees the same lines that land on disk.
//
// `path` is the rotated log file; pass "" to skip file logging entirely
// (useful for --diagnose runs that should stay quiet on disk). On
// permission / disk failures, Setup logs a one-line warning to `also`
// and continues with `also` only — the agent must not refuse to start
// just because its log directory isn't writable yet.
func Setup(path string, also io.Writer) (io.Closer, error) {
	if also == nil {
		also = os.Stderr
	}
	if path == "" {
		log.SetOutput(also)
		return noopCloser{}, nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		fmt.Fprintf(also, "logging: cannot create %s: %v (continuing with stderr-only)\n",
			filepath.Dir(path), err)
		log.SetOutput(also)
		return noopCloser{}, nil
	}

	r, err := openRotator(path)
	if err != nil {
		fmt.Fprintf(also, "logging: cannot open %s: %v (continuing with stderr-only)\n", path, err)
		log.SetOutput(also)
		return noopCloser{}, nil
	}

	log.SetOutput(io.MultiWriter(r, also))
	return r, nil
}

// noopCloser is returned when no rotator was opened so callers can
// unconditionally `defer closer.Close()` in main.
type noopCloser struct{}

func (noopCloser) Close() error { return nil }

// rotator is a tiny size-based log rotator. We deliberately avoid pulling
// in lumberjack so the agent stays at its current zero-deps-beyond-WS
// footprint; agent.log is the only file we rotate.
type rotator struct {
	mu   sync.Mutex
	path string
	f    *os.File
	size int64
}

func openRotator(path string) (*rotator, error) {
	// #nosec G304 -- path is operator-configurable via --log-file.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &rotator{path: path, f: f, size: info.Size()}, nil
}

// Write writes p to the rotated file, rotating when the size threshold
// is reached. Returns the number of bytes written from p. A rotation
// failure falls back to writing through the current file so the line is
// not lost (we'd rather have a slightly-too-large file than swallow
// log output).
func (r *rotator) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.f == nil {
		return 0, fmt.Errorf("rotator closed")
	}
	if r.size+int64(len(p)) > MaxSizeBytes {
		if err := r.rotateLocked(); err != nil {
			// Don't drop the message — write to the current file even
			// over-quota; operators see the over-quota state via file size.
			fmt.Fprintf(os.Stderr, "logging: rotation failed for %s: %v\n", r.path, err)
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

// rotateLocked moves agent.log.N → agent.log.N+1 (deleting the oldest)
// and re-opens a fresh agent.log. Caller must hold r.mu.
func (r *rotator) rotateLocked() error {
	if err := r.f.Close(); err != nil {
		// Best-effort: continue with the rename anyway. A failed close
		// usually means the FD is already gone; the file itself is on
		// disk.
		fmt.Fprintf(os.Stderr, "logging: close before rotate: %v\n", err)
	}
	r.f = nil

	// Shift archives: .N-1 → .N, .N-2 → .N-1, …, .1 → .2; remove the
	// over-cap one. MaxFiles=5 means we keep agent.log + agent.log.1
	// through agent.log.4.
	oldest := fmt.Sprintf("%s.%d", r.path, MaxFiles-1)
	_ = os.Remove(oldest) // ignore — may not exist yet
	for i := MaxFiles - 2; i >= 1; i-- {
		from := fmt.Sprintf("%s.%d", r.path, i)
		to := fmt.Sprintf("%s.%d", r.path, i+1)
		_ = os.Rename(from, to) // ignore — earlier archives may be absent
	}
	if err := os.Rename(r.path, r.path+".1"); err != nil {
		// We've closed the FD; we still need a fresh file to write
		// going forward. Truncation is the fallback.
		fmt.Fprintf(os.Stderr, "logging: rename %s → %s.1 failed: %v (truncating instead)\n",
			r.path, r.path, err)
	}

	// #nosec G304 -- r.path is operator-configurable via --log-file.
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("reopen %s: %w", r.path, err)
	}
	r.f = f
	r.size = 0
	return nil
}

// Close closes the underlying file. Safe to call multiple times.
func (r *rotator) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}
