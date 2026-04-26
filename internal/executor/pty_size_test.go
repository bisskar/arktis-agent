package executor

import "testing"

func TestSanitizePtySize(t *testing.T) {
	t.Parallel()

	cases := []struct {
		cols, rows         int
		wantCols, wantRows uint16
		why                string
	}{
		{80, 24, 80, 24, "normal"},
		{0, 0, defaultPtyCols, defaultPtyRows, "zero falls back to defaults"},
		{-1, -1, defaultPtyCols, defaultPtyRows, "negative falls back"},
		{1, 1, 1, 1, "minimum 1x1 preserved"},
		{maxPtyDim, maxPtyDim, maxPtyDim, maxPtyDim, "uint16 max preserved"},
		{maxPtyDim + 1, maxPtyDim + 1, maxPtyDim, maxPtyDim, "above uint16 max clamped"},
		{1_000_000, 999, maxPtyDim, 999, "huge cols clamped, rows preserved"},
	}

	for _, c := range cases {
		gotC, gotR := sanitizePtySize(c.cols, c.rows)
		if gotC != c.wantCols || gotR != c.wantRows {
			t.Errorf("sanitizePtySize(%d,%d) = (%d,%d), want (%d,%d) (%s)",
				c.cols, c.rows, gotC, gotR, c.wantCols, c.wantRows, c.why)
		}
	}
}
