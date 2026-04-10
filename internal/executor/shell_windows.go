//go:build windows

package executor

import (
	"fmt"
	"os"
	"os/exec"
	"sync"
)

// PtySession is a placeholder on Windows.
// Full ConPTY support can be added in a future version.
type PtySession struct {
	sessionID string
	cmd       *exec.Cmd
	pty       *os.File
	done      chan struct{}
	once      sync.Once
}

// NewPtySession returns an error on Windows — interactive PTY is not yet
// supported. Use command execution instead.
func NewPtySession(sessionID string, termType string, cols int, rows int) (*PtySession, error) {
	return nil, fmt.Errorf("interactive PTY is not yet supported on Windows — use command execution instead")
}

// Write is a no-op stub for Windows.
func (p *PtySession) Write(data []byte) (int, error) {
	return 0, fmt.Errorf("PTY not supported on Windows")
}

// Resize is a no-op stub for Windows.
func (p *PtySession) Resize(cols int, rows int) error {
	return fmt.Errorf("PTY not supported on Windows")
}

// Close is a no-op stub for Windows.
func (p *PtySession) Close() error {
	return nil
}

// ReadLoop is a no-op stub for Windows.
func (p *PtySession) ReadLoop(send func(data []byte)) {
	// No-op on Windows.
}
