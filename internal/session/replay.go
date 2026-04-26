package session

import (
	"sync"
	"time"
)

// Tracker remembers IDs seen within a sliding window so a captured
// exec/pty message cannot be replayed against the agent. It is bounded
// in both size (cap) and age (ttl): an ID falls out as soon as either
// limit is reached. Safe for concurrent use.
//
// We don't persist the seen-set across process restarts; a restart
// re-opens the replay window for at most ttl. This is acceptable
// because (a) the host_id changes if the state dir is wiped and
// (b) the backend can refuse stale messages once message-signing
// (#9) lands.
type Tracker struct {
	mu   sync.Mutex
	seen map[string]time.Time
	cap  int
	ttl  time.Duration
	now  func() time.Time // injectable for tests
}

// NewTracker constructs a Tracker with the given capacity and time-to-live.
func NewTracker(cap int, ttl time.Duration) *Tracker {
	return &Tracker{
		seen: make(map[string]time.Time, cap),
		cap:  cap,
		ttl:  ttl,
		now:  time.Now,
	}
}

// Seen records id and reports whether it was already known within ttl.
// A return of true means "this is a replay; reject it".
func (t *Tracker) Seen(id string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := t.now()
	cutoff := now.Add(-t.ttl)

	// Lazy GC: drop anything older than cutoff.
	for k, ts := range t.seen {
		if ts.Before(cutoff) {
			delete(t.seen, k)
		}
	}

	if _, dup := t.seen[id]; dup {
		return true
	}

	// Evict the oldest if we're at capacity.
	if len(t.seen) >= t.cap {
		var oldestKey string
		var oldestTs time.Time
		first := true
		for k, ts := range t.seen {
			if first || ts.Before(oldestTs) {
				oldestKey, oldestTs, first = k, ts, false
			}
		}
		delete(t.seen, oldestKey)
	}

	t.seen[id] = now
	return false
}
