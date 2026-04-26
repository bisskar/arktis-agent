package session

import (
	"strings"
	"testing"
)

func TestValidID(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   string
		want bool
		why  string
	}{
		{"abc", true, "alphanum"},
		{"ABC123", true, "mixed case + digits"},
		{"some_id-42", true, "underscore + hyphen allowed"},
		{strings.Repeat("a", 64), true, "max length 64 ok"},
		{"", false, "empty rejected"},
		{strings.Repeat("a", 65), false, "65 chars rejected"},
		{"abc.def", false, "dot not allowed"},
		{"abc def", false, "space not allowed"},
		{"abc/def", false, "slash not allowed"},
		{"abc\ndef", false, "newline not allowed (CRLF injection probe)"},
		{"abc\x00def", false, "NUL not allowed"},
		{"../etc/passwd", false, "path traversal probe"},
		{"\r\nFAKE", false, "CRLF prefix"},
	}

	for _, c := range cases {
		if got := validID(c.in); got != c.want {
			t.Errorf("validID(%q) = %v, want %v (%s)", c.in, got, c.want, c.why)
		}
	}
}

func TestSanitizeOutput(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"clean ascii", "clean ascii"},
		{"line1\nline2", "line1\nline2"},
		{"col1\tcol2", "col1\tcol2"},
		{"hello\x00world", `hello\x00world`},
		{"\x1b]0;evil\x07", `\x1b]0;evil\x07`},
		{"\rOVERWRITE", `\x0dOVERWRITE`},
		{"text\x7fwith DEL", `text\x7fwith DEL`},
		{"\r\nFAKE LINE\r\n", `\x0d` + "\nFAKE LINE" + `\x0d` + "\n"},
	}
	for _, c := range cases {
		if got := sanitizeOutput(c.in); got != c.want {
			t.Errorf("sanitizeOutput(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSanitizeOutputIdempotent(t *testing.T) {
	t.Parallel()

	in := "step1\x1b[31m red \x1b[0m line\nstep2 \x07 bell"
	once := sanitizeOutput(in)
	twice := sanitizeOutput(once)
	if once != twice {
		t.Errorf("sanitizeOutput not idempotent: once=%q twice=%q", once, twice)
	}
}
