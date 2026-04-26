package executor

import (
	"strings"
	"testing"
)

func TestSanitizeTerm(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in, want string
		why      string
	}{
		{"", defaultTerm, "empty falls back to default"},
		{"xterm", "xterm", "plain term ok"},
		{"xterm-256color", "xterm-256color", "with hyphen ok"},
		{"screen.linux", "screen.linux", "with dot ok"},
		{"foo_bar", "foo_bar", "with underscore ok"},
		{strings.Repeat("a", 64), strings.Repeat("a", 64), "max length 64 ok"},
		{strings.Repeat("a", 65), defaultTerm, "65 chars falls back"},
		{"xterm space", defaultTerm, "space rejected"},
		{"xterm\necho", defaultTerm, "newline injection rejected"},
		{"xterm\x00", defaultTerm, "NUL rejected"},
		{"$(rm -rf /)", defaultTerm, "shell metacharacters rejected"},
	}
	for _, c := range cases {
		if got := sanitizeTerm(c.in); got != c.want {
			t.Errorf("sanitizeTerm(%q) = %q, want %q (%s)", c.in, got, c.want, c.why)
		}
	}
}
