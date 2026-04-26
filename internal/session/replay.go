package session

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Tracker remembers IDs seen within a sliding window so a captured
// exec/pty message cannot be replayed against the agent. It is bounded
// in both size (cap) and age (ttl): an ID falls out as soon as either
// limit is reached. Safe for concurrent use.
//
// The seen-set can be persisted to disk via Save/Load so a process
// restart does not re-open the replay window. The on-disk format is
// JSON; entries older than ttl are dropped on Load.
type Tracker struct {
	mu   sync.Mutex
	seen map[string]time.Time
	cap  int
	ttl  time.Duration
	now  func() time.Time // injectable for tests
}

// trackerEntry is the on-disk representation of one seen ID.
type trackerEntry struct {
	ID string    `json:"id"`
	TS time.Time `json:"ts"`
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

// Save serialises the current seen-set to path (mode 0600). Entries
// past ttl are dropped before writing so the file never grows beyond
// what's actually reachable. A best-effort write — callers log the
// error themselves so audit/log channels can record it.
func (t *Tracker) Save(path string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	cutoff := t.now().Add(-t.ttl)
	entries := make([]trackerEntry, 0, len(t.seen))
	for id, ts := range t.seen {
		if ts.Before(cutoff) {
			continue
		}
		entries = append(entries, trackerEntry{ID: id, TS: ts})
	}

	data, err := json.Marshal(entries)
	if err != nil {
		return fmt.Errorf("marshal replay state: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write replay state: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename replay state: %w", err)
	}
	return nil
}

// Load reads the seen-set from path. Entries older than ttl are
// dropped. A missing file is not an error — it's the first-boot case.
func (t *Tracker) Load(path string) error {
	// #nosec G304 -- caller-supplied path under the agent's state dir.
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read replay state: %w", err)
	}
	var entries []trackerEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		// Corrupt file shouldn't block startup; just start fresh.
		return fmt.Errorf("parse replay state: %w", err)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	cutoff := t.now().Add(-t.ttl)
	for _, e := range entries {
		if e.TS.Before(cutoff) {
			continue
		}
		t.seen[e.ID] = e.TS
	}
	return nil
}
