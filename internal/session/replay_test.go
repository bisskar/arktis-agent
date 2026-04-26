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
