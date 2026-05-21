package main

import "testing"

// TestSynthesizeURLProdDefaultsTo443 locks in the headline behaviour
// from #227: corporate egress is guaranteed to allow 443 outbound, so a
// production install should only need --host to produce a working dial.
func TestSynthesizeURLProdDefaultsTo443(t *testing.T) {
	t.Parallel()
	got := synthesizeURL("agent.example.com", false)
	want := "wss://agent.example.com:443/api/v1/agent/ws"
	if got != want {
		t.Errorf("prod URL: got %q, want %q", got, want)
	}
}

// TestSynthesizeURLDevPort8000 keeps the legacy local-stack shape so
// existing `--dev` operators don't have to relearn the URL.
func TestSynthesizeURLDevPort8000(t *testing.T) {
	t.Parallel()
	got := synthesizeURL("localhost", true)
	want := "ws://localhost:8000/api/v1/agent/ws"
	if got != want {
		t.Errorf("dev URL: got %q, want %q", got, want)
	}
}

// TestSynthesizeURLEmptyHost returns "" so main's downstream emptiness
// check fires; we deliberately do NOT inject a fallback host because
// guessing a hostname is the kind of "helpful default" that silently
// connects to the wrong backend.
func TestSynthesizeURLEmptyHost(t *testing.T) {
	t.Parallel()
	if got := synthesizeURL("", false); got != "" {
		t.Errorf("empty host: got %q, want \"\"", got)
	}
	if got := synthesizeURL("", true); got != "" {
		t.Errorf("empty host (dev): got %q, want \"\"", got)
	}
}
