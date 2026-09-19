package diagnose

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bisskar/arktis-agent/internal/protocol"
	"github.com/gorilla/websocket"
)

func TestAuthCheckAdvertisesHostProofCapability(t *testing.T) {
	registrations := make(chan protocol.RegisterMessage, 1)
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		defer conn.Close()

		var registration protocol.RegisterMessage
		if err := conn.ReadJSON(&registration); err != nil {
			t.Errorf("read registration: %v", err)
			return
		}
		registrations <- registration
		if err := conn.WriteJSON(protocol.AckMessage{Type: "ack", HostID: "diagnosed"}); err != nil {
			t.Errorf("write ack: %v", err)
		}
	}))
	defer backend.Close()

	conn, _, err := websocket.DefaultDialer.Dial(
		"ws"+strings.TrimPrefix(backend.URL, "http"),
		nil,
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := authCheck(conn, "registration-key"); err != nil {
		t.Fatalf("authCheck: %v", err)
	}
	if registration := <-registrations; !registration.HostProofCapable {
		t.Fatal("diagnostic registration did not advertise host_proof_capable")
	}
}

// TestRunRejectsInvalidURL ensures the diagnose path bails before doing
// any I/O when the URL is malformed. The verdict line must name the
// step that failed so support reading "VERDICT: UNHEALTHY (url)" knows
// it isn't a network problem.
func TestRunRejectsInvalidURL(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	res := Run(context.Background(), Options{
		URL: "not a url",
		Out: &buf,
		Now: func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) },
	})
	if res.Healthy {
		t.Errorf("expected unhealthy result")
	}
	if !strings.Contains(buf.String(), "VERDICT: UNHEALTHY") {
		t.Errorf("expected VERDICT line; got:\n%s", buf.String())
	}
}

// TestRunRejectsWSWithoutInsecure: a plaintext ws:// URL must NOT
// pass the diagnose run unless --insecure is set, matching the live
// agent's gating. Otherwise an operator could think they have a
// healthy production setup when they actually have a plaintext one.
func TestRunRejectsWSWithoutInsecure(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	res := Run(context.Background(), Options{
		URL: "ws://example.invalid/agent/ws",
		Out: &buf,
		Now: func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) },
	})
	if res.Healthy {
		t.Errorf("expected unhealthy result for ws:// without --insecure")
	}
	if !strings.Contains(buf.String(), "ws:// URL requires --insecure") {
		t.Errorf("expected explicit ws:// reason; got:\n%s", buf.String())
	}
}

// TestRunUnsupportedScheme — `http://` typos are common.
func TestRunUnsupportedScheme(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	res := Run(context.Background(), Options{
		URL: "http://example.com/agent/ws",
		Out: &buf,
	})
	if res.Healthy {
		t.Errorf("expected unhealthy result for http:// URL")
	}
	if !strings.Contains(buf.String(), "unsupported scheme") {
		t.Errorf("expected 'unsupported scheme' reason; got:\n%s", buf.String())
	}
}

// TestRunFailsOnUnresolvableHost asserts the DNS step prints [FAIL]
// rather than masking a resolution error inside a later TCP/TLS step.
// The unresolvable hostname uses the reserved `.invalid` TLD so this
// test never hits a real DNS lookup that could flake.
func TestRunFailsOnUnresolvableHost(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var buf bytes.Buffer
	res := Run(ctx, Options{
		URL: "wss://does-not-exist.invalid:443/agent/ws",
		Out: &buf,
	})
	if res.Healthy {
		t.Errorf("expected unhealthy result for unresolvable host")
	}
	if !strings.Contains(buf.String(), "[FAIL]  DNS") {
		t.Errorf("expected [FAIL] DNS line; got:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "VERDICT: UNHEALTHY (dns)") {
		t.Errorf("expected dns verdict; got:\n%s", buf.String())
	}
}

// TestRoundDurationLabels — small helper, but the wording lands in the
// expiry warning that operators read, so it's worth pinning.
func TestRoundDurationLabels(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   time.Duration
		want string
	}{
		{-time.Hour, "already expired"},
		{2 * time.Hour, "2h 0m"},
		{30 * time.Minute, "30m0s"},
		{(24*30 + 5) * time.Hour, "30d 5h"},
	}
	for _, c := range cases {
		got := roundDuration(c.in)
		if got != c.want {
			t.Errorf("roundDuration(%s): got %q, want %q", c.in, got, c.want)
		}
	}
}
