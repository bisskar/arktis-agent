package executor

import (
	"log"
	"regexp"
)

const defaultTerm = "xterm-256color"

// termTypeRe restricts TERM values to characters that real terminfo entries
// use (alphanumerics, dot, hyphen, underscore) and a sensible upper length.
// Untrusted input that doesn't match is replaced with a safe default to
// keep injection (e.g. embedded newlines) out of the spawned shell's env.
var termTypeRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// sanitizeTerm validates termType from the backend; on mismatch it logs a
// warning and returns defaultTerm. An empty value is treated as "no
// preference" and also resolves to the default.
func sanitizeTerm(termType string) string {
	if termType == "" {
		return defaultTerm
	}
	if !termTypeRe.MatchString(termType) {
		log.Printf("Warning: invalid term_type %q; falling back to %s", termType, defaultTerm)
		return defaultTerm
	}
	return termType
}
