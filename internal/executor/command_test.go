package executor

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTruncate(t *testing.T) {
	t.Parallel()

	t.Run("under cap", func(t *testing.T) {
		t.Parallel()
		got, truncated := truncate("hello", 100)
		if truncated {
			t.Errorf("did not expect truncation")
		}
		if got != "hello" {
			t.Errorf("got %q", got)
		}
	})

	t.Run("at cap", func(t *testing.T) {
		t.Parallel()
		s := strings.Repeat("a", 10)
		got, truncated := truncate(s, 10)
		if truncated {
			t.Errorf("did not expect truncation at exact cap")
		}
		if got != s {
			t.Errorf("got %q", got)
		}
	})

	t.Run("over cap", func(t *testing.T) {
		t.Parallel()
		s := strings.Repeat("a", 50)
		got, truncated := truncate(s, 10)
		if !truncated {
			t.Errorf("expected truncation flag")
		}
		if !strings.HasPrefix(got, strings.Repeat("a", 10)) {
			t.Errorf("expected prefix preserved: %q", got)
		}
		if !strings.Contains(got, "[OUTPUT TRUNCATED at 1MB]") {
			t.Errorf("expected truncation marker, got %q", got)
		}
	})

	// Slicing a multi-byte rune mid-byte produces invalid UTF-8 which
	// the JSON encoder later replaces with U+FFFD. truncate must back
	// up to the previous rune boundary so the result stays valid.
	t.Run("rune boundary preserved", func(t *testing.T) {
		t.Parallel()
		// Each rune is 3 bytes in UTF-8.
		s := strings.Repeat("世", 20) // 60 bytes
		// Cut mid-rune: byte index 10 is in the middle of the 4th rune.
		got, truncated := truncate(s, 10)
		if !truncated {
			t.Fatalf("expected truncation")
		}
		// The prefix portion of `got` (before the truncation marker) must
		// be valid UTF-8.
		marker := "\n[OUTPUT TRUNCATED at 1MB]"
		prefix := strings.TrimSuffix(got, marker)
		if !utf8.ValidString(prefix) {
			t.Errorf("truncated prefix is not valid UTF-8: %q", prefix)
		}
		// The prefix length must be at most maxBytes and a multiple of 3.
		if len(prefix) > 10 {
			t.Errorf("prefix exceeds cap: %d bytes", len(prefix))
		}
		if len(prefix)%3 != 0 {
			t.Errorf("prefix should land on rune boundary; got %d bytes", len(prefix))
		}
	})
}
