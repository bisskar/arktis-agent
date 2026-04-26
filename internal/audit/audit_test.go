package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func readLines(t *testing.T, path string) []map[string]interface{} {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	var out []map[string]interface{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		var rec map[string]interface{}
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Fatalf("bad JSON line %q: %v", sc.Text(), err)
		}
		out = append(out, rec)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	return out
}

func TestLoggerNoOpWhenPathEmpty(t *testing.T) {
	t.Parallel()
	l, err := Open(Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	// Should not panic / error even though there's no file.
	l.LogExecRequest(ExecRequest{RequestID: "r1", Command: "x"})
	l.LogExecResult(ExecResult{RequestID: "r1"})
	l.LogPtyOpen(PtyOpen{SessionID: "s1"})
	l.LogPtyClose(PtyClose{SessionID: "s1"})
	if err := l.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestLoggerHashesCommandByDefault(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	l, err := Open(Options{Path: path})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	l.LogExecRequest(ExecRequest{RequestID: "req-1", Executor: "bash", Command: "secret stuff"})
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lines := readLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("expected 1 record, got %d", len(lines))
	}
	rec := lines[0]
	if rec["event"] != "exec_request" {
		t.Errorf("event = %v", rec["event"])
	}
	if rec["request_id"] != "req-1" {
		t.Errorf("request_id = %v", rec["request_id"])
	}
	if _, present := rec["command"]; present {
		t.Errorf("command should be hashed, not logged in cleartext")
	}
	if _, present := rec["command_sha256"]; !present {
		t.Errorf("command_sha256 missing")
	}
	if rec["command_bytes"].(float64) != float64(len("secret stuff")) {
		t.Errorf("command_bytes = %v", rec["command_bytes"])
	}
}

func TestLoggerIncludesCommandWhenAsked(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	l, err := Open(Options{Path: path, IncludeCommand: true})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	l.LogExecRequest(ExecRequest{RequestID: "r2", Command: "echo hi"})
	_ = l.Close()

	lines := readLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("expected 1 record, got %d", len(lines))
	}
	if lines[0]["command"] != "echo hi" {
		t.Errorf("command = %v", lines[0]["command"])
	}
}

func TestLoggerFilePermissions(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	l, err := Open(Options{Path: path})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer l.Close()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("audit log perm = %#o, want 0600", st.Mode().Perm())
	}
}

func TestLoggerChainSurvivesIntactVerification(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	keyPath := filepath.Join(dir, "audit.key")

	l, err := Open(Options{Path: path, IncludeCommand: true, ChainKeyPath: keyPath})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for i := 0; i < 5; i++ {
		l.LogExecRequest(ExecRequest{RequestID: "r" + strconv.Itoa(i), Command: "x"})
		l.LogExecResult(ExecResult{RequestID: "r" + strconv.Itoa(i), ExitCode: 0})
	}
	_ = l.Close()

	key, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if bad, err := Verify(path, key); err != nil || bad != 0 {
		t.Errorf("Verify reported bad=%d err=%v on intact chain", bad, err)
	}

	// Tamper with line 3.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	lines := strings.SplitAfter(string(raw), "\n")
	lines[2] = strings.Replace(lines[2], `"x"`, `"hacked"`, 1)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "")), 0o600); err != nil {
		t.Fatalf("rewrite log: %v", err)
	}
	bad, err := Verify(path, key)
	if bad != 3 || err == nil {
		t.Errorf("Verify on tampered log: bad=%d err=%v (want bad=3, err=chain mismatch)", bad, err)
	}
}

func TestLoggerConcurrentLinesAreAtomic(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	l, err := Open(Options{Path: path, IncludeCommand: true})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	const n = 200
	cmd := strings.Repeat("X", 1024) // big enough that interleaving would break JSON
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			l.LogExecRequest(ExecRequest{RequestID: "r", Command: cmd})
		}(i)
	}
	wg.Wait()
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lines := readLines(t, path)
	if len(lines) != n {
		t.Errorf("expected %d records, got %d (likely interleaving)", n, len(lines))
	}
}
