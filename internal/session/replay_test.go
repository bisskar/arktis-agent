package session

import (
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestTrackerRejectsDuplicates(t *testing.T) {
	t.Parallel()
	tr := NewTracker(8, time.Minute)
	if tr.Seen("a") {
		t.Errorf("first call should not be a duplicate")
	}
	if !tr.Seen("a") {
		t.Errorf("second call with same id should be a duplicate")
	}
}

func TestTrackerExpiresOnTTL(t *testing.T) {
	t.Parallel()
	tr := NewTracker(8, 100*time.Millisecond)
	now := time.Now()
	tr.now = func() time.Time { return now }

	if tr.Seen("a") {
		t.Fatalf("first call duplicate?")
	}
	// Advance past TTL.
	now = now.Add(200 * time.Millisecond)
	if tr.Seen("a") {
		t.Errorf("expired id should not count as replay")
	}
}

func TestTrackerEvictsAtCapacity(t *testing.T) {
	t.Parallel()
	tr := NewTracker(2, time.Minute)
	tr.Seen("a")
	tr.Seen("b")
	tr.Seen("c") // should evict "a"
	if tr.Seen("a") {
		t.Errorf("a should have been evicted; replay check fired anyway")
	}
}

func TestTrackerConcurrent(t *testing.T) {
	t.Parallel()
	tr := NewTracker(1024, time.Minute)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := "id-" + strconv.Itoa(i)
			if tr.Seen(id) {
				t.Errorf("unexpected duplicate for %s", id)
			}
		}(i)
	}
	wg.Wait()
}

func TestTrackerPersistRoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := dir + "/replay.json"

	a := NewTracker(64, time.Minute)
	a.Seen("alpha")
	a.Seen("beta")
	if err := a.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	b := NewTracker(64, time.Minute)
	if err := b.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !b.Seen("alpha") {
		t.Errorf("alpha should be remembered after reload")
	}
	if !b.Seen("beta") {
		t.Errorf("beta should be remembered after reload")
	}
}

func TestTrackerLoadMissingFileIsOK(t *testing.T) {
	t.Parallel()
	tr := NewTracker(8, time.Minute)
	if err := tr.Load(t.TempDir() + "/no-such.json"); err != nil {
		t.Errorf("missing file should not error: %v", err)
	}
}

func TestTrackerLoadDropsExpiredEntries(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := dir + "/replay.json"

	a := NewTracker(64, 100*time.Millisecond)
	now := time.Now()
	a.now = func() time.Time { return now }
	a.Seen("recent")
	// Inject an entry that is already past the TTL when we save.
	a.mu.Lock()
	a.seen["stale"] = now.Add(-time.Hour)
	a.mu.Unlock()
	if err := a.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	b := NewTracker(64, 100*time.Millisecond)
	b.now = func() time.Time { return now }
	if err := b.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if b.Seen("stale") {
		t.Errorf("stale entry should have been dropped during Save/Load")
	}
}
