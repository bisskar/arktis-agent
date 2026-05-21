package logging

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestDefaultPathPerOS locks in the predictable-path contract from #227.
// Support asks "paste the last 30 lines of agent.log" — this is the file
// they're going to point at.
func TestDefaultPathPerOS(t *testing.T) {
	t.Parallel()
	got := DefaultPath()
	switch runtime.GOOS {
	case "windows":
		if !strings.Contains(got, `arktis-agent\agent.log`) {
			t.Errorf("windows default path %q does not contain expected suffix", got)
		}
	case "darwin":
		if got != "/Library/Logs/arktis-agent/agent.log" {
			t.Errorf("darwin default path: got %q", got)
		}
	default:
		if got != "/var/log/arktis-agent/agent.log" {
			t.Errorf("linux default path: got %q", got)
		}
	}
}

// TestRotatorRotatesAtThreshold writes past MaxSizeBytes and asserts the
// archive file appears + the live file is truncated. This is the
// behaviour the issue calls out: rolling 5 MB × 5 files.
func TestRotatorRotatesAtThreshold(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.log")

	r, err := openRotator(path)
	if err != nil {
		t.Fatalf("openRotator: %v", err)
	}
	defer r.Close()

	// Write MaxSizeBytes worth + a small tail so the next write triggers
	// rotation. Use a small chunk to keep the test fast — Go test
	// shouldn't allocate 5 MiB of stack-buffer for a unit test.
	chunk := bytes.Repeat([]byte("x"), 1024)
	written := int64(0)
	for written < MaxSizeBytes {
		n, err := r.Write(chunk)
		if err != nil {
			t.Fatalf("Write at %d: %v", written, err)
		}
		written += int64(n)
	}
	// One more write triggers rotation.
	if _, err := r.Write([]byte("trigger\n")); err != nil {
		t.Fatalf("trigger write: %v", err)
	}

	if _, err := os.Stat(path + ".1"); err != nil {
		t.Errorf("expected archive %s.1 to exist after rotation: %v", path, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat live file: %v", err)
	}
	if info.Size() > MaxSizeBytes {
		t.Errorf("live file %d bytes exceeds MaxSizeBytes %d after rotation", info.Size(), MaxSizeBytes)
	}
}

// TestRotatorKeepsMaxFiles writes enough to cycle through several
// rotations and asserts no more than MaxFiles total files (current + 4
// archives) remain.
func TestRotatorKeepsMaxFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.log")

	r, err := openRotator(path)
	if err != nil {
		t.Fatalf("openRotator: %v", err)
	}
	defer r.Close()

	// Use a small block so we trigger ≥ MaxFiles rotations quickly.
	chunk := bytes.Repeat([]byte("y"), 1024)
	for i := 0; i < int(MaxSizeBytes/1024)*(MaxFiles+2); i++ {
		if _, err := r.Write(chunk); err != nil {
			t.Fatalf("Write iter %d: %v", i, err)
		}
	}

	// Count remaining files.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	count := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "agent.log") {
			count++
		}
	}
	if count > MaxFiles {
		t.Errorf("found %d agent.log* files; MaxFiles=%d", count, MaxFiles)
	}
}

// TestSetupWithDashSkipsFileLogging — the `--log-file -` escape hatch
// from main: callers that want stderr-only (e.g. inside `--diagnose`)
// shouldn't have file I/O happen behind their back.
func TestSetupWithEmptyPathSkipsFile(t *testing.T) {
	t.Parallel()
	closer, err := Setup("", nil)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if closer == nil {
		t.Fatal("Setup returned nil closer")
	}
	if err := closer.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}
