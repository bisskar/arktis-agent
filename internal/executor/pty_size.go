package executor

// PTY winsize defaults used when a backend message omits or supplies
// out-of-range dimensions. The upper bound is uint16's max (65535),
// which is what the underlying TIOCSWINSZ / ConPty APIs accept.
const (
	defaultPtyCols = 80
	defaultPtyRows = 24
	maxPtyDim      = 65535
)

// sanitizePtySize clamps untrusted cols/rows from the backend into the
// uint16 range expected by pty.Setsize / conpty.Resize. Non-positive
// values fall back to sensible defaults so that an `int` -> `uint16`
// conversion can never wrap to an enormous (or zero) terminal size.
func sanitizePtySize(cols, rows int) (uint16, uint16) {
	if cols <= 0 {
		cols = defaultPtyCols
	} else if cols > maxPtyDim {
		cols = maxPtyDim
	}
	if rows <= 0 {
		rows = defaultPtyRows
	} else if rows > maxPtyDim {
		rows = maxPtyDim
	}
	return uint16(cols), uint16(rows)
}
