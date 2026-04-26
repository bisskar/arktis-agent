//go:build windows

package executor

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"path/filepath"
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
// See resolveWindowsShell for the shell-resolution order.
func NewPtySession(sessionID string, termType string, cols int, rows int) (*PtySession, error) {
	shell := resolveWindowsShell()

	colsU, rowsU := sanitizePtySize(cols, rows)

	cpty, err := conpty.Start(shell,
		conpty.ConPtyDimensions(int(colsU), int(rowsU)),
		conpty.ConPtyEnv(minimalEnv()),
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
//
// Resolution order (first existing absolute path wins):
//  1. ARKTIS_PTY_SHELL — operator override; must be an absolute path.
//  2. %ProgramFiles%\PowerShell\7\pwsh.exe — PowerShell 7+.
//  3. %ProgramW6432%\PowerShell\7\pwsh.exe — PS7 from a 32-bit process.
//  4. %SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe — Windows PS 5.1.
//  5. %ComSpec% — only if absolute and exists.
//  6. %SystemRoot%\System32\cmd.exe — last-resort absolute path.
//
// We deliberately never return a bare "cmd.exe" string: relying on PATH at
// CreateProcess time would let any directory earlier on PATH (e.g. a
// writable user dir) hijack the agent's shell.
func resolveWindowsShell() string {
	candidates := windowsShellCandidates()
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if !filepath.IsAbs(c) {
			continue
		}
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c
		}
	}
	// Final guaranteed-absolute fallback. ConPTY may still fail here, but
	// at least we won't be PATH-hijackable.
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		systemRoot = `C:\Windows`
	}
	fallback := filepath.Join(systemRoot, `System32`, `cmd.exe`)
	log.Printf("Warning: no preferred shell found, using fallback %s", fallback)
	return fallback
}

func windowsShellCandidates() []string {
	systemRoot := os.Getenv("SystemRoot")
	programFiles := os.Getenv("ProgramFiles")
	programW6432 := os.Getenv("ProgramW6432")

	var c []string
	if v := os.Getenv("ARKTIS_PTY_SHELL"); v != "" {
		c = append(c, v)
	}
	if programFiles != "" {
		c = append(c, filepath.Join(programFiles, "PowerShell", "7", "pwsh.exe"))
	}
	if programW6432 != "" && programW6432 != programFiles {
		c = append(c, filepath.Join(programW6432, "PowerShell", "7", "pwsh.exe"))
	}
	if systemRoot != "" {
		c = append(c, filepath.Join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"))
	}
	if comspec := os.Getenv("ComSpec"); comspec != "" && filepath.IsAbs(comspec) {
		c = append(c, comspec)
	}
	if systemRoot != "" {
		c = append(c, filepath.Join(systemRoot, "System32", "cmd.exe"))
	}
	return c
}

// Write sends input data to the ConPTY.
func (p *PtySession) Write(data []byte) (int, error) {
	return p.cpty.Write(data)
}

// Resize changes the ConPTY window size.
func (p *PtySession) Resize(cols int, rows int) error {
	colsU, rowsU := sanitizePtySize(cols, rows)
	return p.cpty.Resize(int(colsU), int(rowsU))
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
