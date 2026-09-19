package config

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// An upgrade may encounter a world-readable state file already held open by
// another user. Restricting its mode does not revoke that reader's descriptor.
func TestSaveStateDoesNotExposeProofToExistingReader(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("open-file replacement semantics differ on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, stateFileName)
	oldData := []byte(`{"host_id":"host-1"}`)
	if err := os.WriteFile(path, oldData, 0o644); err != nil {
		t.Fatal(err)
	}
	reader, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	if err := SaveState(dir, &State{HostID: "host-1", HostProof: "new-secret"}); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(oldData) {
		t.Fatal("existing reader observed replacement state")
	}
	state, err := LoadState(dir)
	if err != nil || state.HostProof != "new-secret" {
		t.Fatalf("replacement state missing proof: %v", err)
	}
	assertNoTemporaryStateFiles(t, dir)
}

func TestSaveStateCleansUpFailedReplacement(t *testing.T) {
	dir := t.TempDir()
	// A directory at the destination forces rename to fail after the protected
	// temporary file has been written, exercising cleanup of secret material.
	if err := os.Mkdir(filepath.Join(dir, stateFileName), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := SaveState(dir, &State{HostProof: "new-secret"}); err == nil {
		t.Fatal("SaveState succeeded with a directory at the destination")
	}
	assertNoTemporaryStateFiles(t, dir)
}

func assertNoTemporaryStateFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != stateFileName {
		t.Fatalf("unexpected files remain after SaveState: %v", entries)
	}
}

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
