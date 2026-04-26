//go:build linux

package executor

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/creack/pty"
)

// linuxShellAllowlist is the fixed set of shells the agent will fall back
// to when $SHELL is unset or fails validation. Anything outside this list
// can still be requested via $SHELL but only if it passes validateShell.
var linuxShellAllowlist = []string{"/bin/bash", "/bin/sh", "/bin/zsh"}

// resolveLinuxShell picks the shell used for interactive PTY sessions.
// $SHELL is honoured only if it points at an absolute, existing, regular
// file owned by root and not world-writable. Otherwise we fall back to a
// fixed allowlist so an attacker who can flip env vars on the agent's
// process token (systemd unit, scheduled task) can't pivot the agent
// into running an arbitrary binary as root.
func resolveLinuxShell() string {
	if v := os.Getenv("SHELL"); v != "" {
		if path, ok := validateShell(v); ok {
			return path
		}
		// #nosec G706 -- $SHELL is operator-supplied env input, not network; %q quotes it.
		log.Printf("Warning: $SHELL %q failed validation; falling back to shell allowlist", v)
	}
	for _, c := range linuxShellAllowlist {
		if path, ok := validateShell(c); ok {
			return path
		}
	}
	return "/bin/sh"
}

// validateShell enforces the safety properties documented on
// resolveLinuxShell. The returned path is filepath.Clean'd.
func validateShell(p string) (string, bool) {
	clean := filepath.Clean(p)
	if !filepath.IsAbs(clean) {
		return "", false
	}
	fi, err := os.Stat(clean)
	if err != nil {
		return "", false
	}
	if !fi.Mode().IsRegular() {
		return "", false
	}
	if fi.Mode().Perm()&0o002 != 0 {
		return "", false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 {
		return "", false
	}
	return clean, true
}

// PtySession wraps an interactive PTY shell session on Linux.
type PtySession struct {
	sessionID string
	cmd       *exec.Cmd
	pty       *os.File
	done      chan struct{}
	once      sync.Once
}

// NewPtySession creates and starts a new PTY session with the user's shell.
func NewPtySession(sessionID string, termType string, cols int, rows int) (*PtySession, error) {
	shell := resolveLinuxShell()

	cmd := exec.Command(shell)
	cmd.Env = append(minimalEnv(), "TERM="+sanitizeTerm(termType))

	ptmx, err := pty.Start(cmd)
	if err != nil {
		return nil, fmt.Errorf("start pty: %w", err)
	}

	colsU, rowsU := sanitizePtySize(cols, rows)
	// Initial winsize is best-effort; the shell will pick up SIGWINCH if it fails.
	_ = pty.Setsize(ptmx, &pty.Winsize{Cols: colsU, Rows: rowsU})

	return &PtySession{
		sessionID: sessionID,
		cmd:       cmd,
		pty:       ptmx,
		done:      make(chan struct{}),
	}, nil
}

// Write sends input data to the PTY.
func (p *PtySession) Write(data []byte) (int, error) {
	return p.pty.Write(data)
}

// Resize changes the PTY window size.
func (p *PtySession) Resize(cols int, rows int) error {
	colsU, rowsU := sanitizePtySize(cols, rows)
	return pty.Setsize(p.pty, &pty.Winsize{Cols: colsU, Rows: rowsU})
}

// Close terminates the PTY session.
func (p *PtySession) Close() error {
	var firstErr error
	p.once.Do(func() {
		close(p.done)
		if p.pty != nil {
			if err := p.pty.Close(); err != nil {
				firstErr = err
			}
		}
		if p.cmd != nil && p.cmd.Process != nil {
			if err := p.cmd.Process.Kill(); err != nil && firstErr == nil {
				firstErr = err
			}
			// Wait reaps the process; an error here typically just
			// means the child already exited from Kill, so we don't
			// surface it.
			_ = p.cmd.Wait()
		}
	})
	return firstErr
}

// ReadLoop reads PTY output in a loop, calling send with base64-encoded chunks.
// It blocks until the PTY is closed or an error occurs.
func (p *PtySession) ReadLoop(send func(data []byte)) {
	buf := make([]byte, 4096)
	for {
		select {
		case <-p.done:
			return
		default:
		}

		n, err := p.pty.Read(buf)
		if n > 0 {
			encoded := base64.StdEncoding.EncodeToString(buf[:n])
			send([]byte(encoded))
		}
		if err != nil {
			log.Printf("PTY read ended for session %s: %v", p.sessionID, err)
			return
		}
	}
}
