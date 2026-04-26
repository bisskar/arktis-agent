//go:build linux

package executor

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"os/exec"
	"sync"

	"github.com/creack/pty"
)

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
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/bash"
	}

	cmd := exec.Command(shell)
	cmd.Env = append(os.Environ(), "TERM="+termType)

	ptmx, err := pty.Start(cmd)
	if err != nil {
		return nil, fmt.Errorf("start pty: %w", err)
	}

	colsU, rowsU := sanitizePtySize(cols, rows)
	pty.Setsize(ptmx, &pty.Winsize{Cols: colsU, Rows: rowsU})

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
	var err error
	p.once.Do(func() {
		close(p.done)
		if p.pty != nil {
			p.pty.Close()
		}
		if p.cmd != nil && p.cmd.Process != nil {
			p.cmd.Process.Kill()
			p.cmd.Wait()
		}
	})
	return err
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
