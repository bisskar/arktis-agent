package protocol

import (
	"fmt"
	"strconv"
)

// SigVersion is the version tag prepended to every signing input so a
// future format change can be distinguished from the current one
// without ambiguity.
const SigVersion = "arktis-agent-msg-v1"

// SigInputExec returns the canonical bytes a backend signs (and the
// agent verifies) for an ExecMessage. The fields are joined with newlines
// in a fixed order; any drift between sender and verifier surfaces as a
// signature mismatch.
func SigInputExec(m *ExecMessage) []byte {
	return []byte(fmt.Sprintf(
		"%s\nexec\n%s\n%s\n%s\n%s\n%s",
		SigVersion,
		m.SignedAt,
		m.RequestID,
		m.ExecutorName,
		strconv.FormatBool(m.ElevationRequired),
		m.Command,
	))
}

// SigInputPtyOpen returns the canonical bytes a backend signs (and the
// agent verifies) for a PtyOpenMessage.
func SigInputPtyOpen(m *PtyOpenMessage) []byte {
	return []byte(fmt.Sprintf(
		"%s\npty_open\n%s\n%s\n%s\n%d\n%d",
		SigVersion,
		m.SignedAt,
		m.SessionID,
		m.TermType,
		m.Cols,
		m.Rows,
	))
}
