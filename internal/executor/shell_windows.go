//go:build windows

package executor

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/UserExistsError/conpty"
)

// PtySession wraps an interactive ConPTY shell session on Windows.
type PtySession struct {
	sessionID string
	cpty      *conpty.ConPty
	done      chan struct{}
	once      sync.Once
}

// NewPtySession creates and starts a new PTY session using ConPTY.
//
// On Windows 10 1809+ / Server 2019+, ConPTY is the modern pseudo-console
// API. Earlier Windows versions are not supported.
//
// Shell resolution order:
//  1. %COMSPEC% env var (typically cmd.exe)
//  2. powershell.exe (via PATH)
//  3. cmd.exe fallback
func NewPtySession(sessionID string, termType string, cols int, rows int) (*PtySession, error) {
	shell := resolveWindowsShell()

	if cols <= 0 {
		cols = 80
	}
	if rows <= 0 {
		rows = 24
	}

	cpty, err := conpty.Start(shell,
		conpty.ConPtyDimensions(cols, rows),
	)
	if err != nil {
		return nil, fmt.Errorf("start conpty with %q: %w", shell, err)
	}

	return &PtySession{
		sessionID: sessionID,
		cpty:      cpty,
		done:      make(chan struct{}),
	}, nil
}

// resolveWindowsShell picks the best available shell on the host.
func resolveWindowsShell() string {
	if comspec := os.Getenv("COMSPEC"); comspec != "" {
		if _, err := os.Stat(comspec); err == nil {
			return comspec
		}
	}
	// Prefer powershell for a more useful interactive experience.
	candidates := []string{
		`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		`C:\Windows\System32\cmd.exe`,
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return "cmd.exe"
}

// Write sends input data to the ConPTY.
func (p *PtySession) Write(data []byte) (int, error) {
	return p.cpty.Write(data)
}

// Resize changes the ConPTY window size.
func (p *PtySession) Resize(cols int, rows int) error {
	if cols <= 0 || rows <= 0 {
		return nil
	}
	return p.cpty.Resize(cols, rows)
}

// Close terminates the ConPTY session.
func (p *PtySession) Close() error {
	var err error
	p.once.Do(func() {
		close(p.done)
		if p.cpty != nil {
			err = p.cpty.Close()
		}
	})
	return err
}

// ReadLoop reads ConPTY output in a loop, calling send with base64-encoded
// chunks. It blocks until the PTY is closed or an error occurs.
func (p *PtySession) ReadLoop(send func(data []byte)) {
	buf := make([]byte, 4096)
	for {
		select {
		case <-p.done:
			return
		default:
		}

		n, err := p.cpty.Read(buf)
		if n > 0 {
			encoded := base64.StdEncoding.EncodeToString(buf[:n])
			send([]byte(encoded))
		}
		if err != nil {
			log.Printf("ConPTY read ended for session %s: %v", p.sessionID, err)
			return
		}
	}
}
