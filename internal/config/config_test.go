package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSaveStateProtectsExistingFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows permissions are ACL-based")
	}

	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("seed state directory mode: %v", err)
	}
	path := filepath.Join(dir, stateFileName)
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatalf("seed state file: %v", err)
	}

	want := &State{HostID: "host-1", HostProof: "secret-proof"}
	if err := SaveState(dir, want); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat state file: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("state file mode = %#o, want 0600", got)
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat state directory: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("state directory mode = %#o, want 0700", got)
	}

	got, err := LoadState(dir)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if got.HostID != want.HostID || got.HostProof != want.HostProof {
		t.Fatalf("loaded state = %#v, want %#v", got, want)
	}
}
