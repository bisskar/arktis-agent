package session

import (
	"regexp"
	"strings"
)

// idRe constrains untrusted ids (session_id, request_id) to a small,
// log-safe charset and length. Anything outside this set is rejected at
// the message-handler boundary so it never lands in a sync.Map key, in
// log output, or in a downstream message.
var idRe = regexp.MustCompile(`^[A-Za-z0-9_\-]{1,64}$`)

// validID reports whether s is a safe session_id / request_id.
func validID(s string) bool {
	return idRe.MatchString(s)
}

// sanitizeOutput returns s with C0 control chars (and DEL) escaped as
// `\xNN`, except for newline and tab which are kept verbatim. Used to
// build the *_safe fields on ExecResultMessage so a backend that writes
// stdout into plain-text logs / SIEM cannot have its log lines mangled
// by ANSI escapes, CRs, BEL, or NUL bytes from the executed command.
func sanitizeOutput(s string) string {
	if !needsSanitize(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\n' || c == '\t':
			b.WriteByte(c)
		case c < 0x20 || c == 0x7f:
			b.WriteString(hexEscape(c))
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func needsSanitize(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 0x20 && c != '\n' && c != '\t') || c == 0x7f {
			return true
		}
	}
	return false
}

func hexEscape(c byte) string {
	const hex = "0123456789abcdef"
	return `\x` + string([]byte{hex[c>>4], hex[c&0x0f]})
}
