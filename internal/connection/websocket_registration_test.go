package connection

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bisskar/arktis-agent/internal/config"
	"github.com/bisskar/arktis-agent/internal/protocol"
	"github.com/gorilla/websocket"
)

const registrationTestTimeout = 2 * time.Second

func TestConnectRequiresDurableProof(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state config.State
	}{
		{name: "enrollment"},
		{name: "reassignment", state: config.State{HostID: "previous", HostProof: "previous-proof"}},
		{name: "rollout", state: config.State{HostID: "host-1"}},
		{name: "rotation", state: config.State{HostID: "host-1", HostProof: "previous-proof"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "state.json")
			backup := filepath.Join(dir, "previous.json")
			registrations := make(chan protocol.RegisterMessage, 2)
			attempt := 0
			backend := registrationServer(t, protocol.AckMessage{
				Type: "ack", HostID: "host-1", HostProof: "new-proof",
			}, registrations, func() {
				attempt++
				if attempt == 1 {
					// Make replacement fail after preflight succeeds, regardless of
					// the test user's privileges or filesystem permission semantics.
					if err := os.Rename(path, backup); err != nil {
						t.Error(err)
						return
					}
					if err := os.Mkdir(path, 0o700); err != nil {
						t.Error(err)
					}
					return
				}
				persisted, err := config.LoadState(dir)
				if err != nil || persisted.HostID != "host-1" || persisted.HostProof != "new-proof" {
					t.Errorf("proof echoed before durable save: %v", err)
				}
			})
			defer backend.Close()
			client := NewClient(&config.Config{
				BackendURL: websocketURL(backend.URL), StateDir: dir,
			}, &tc.state, nil)
			ctx, cancel := context.WithTimeout(context.Background(), registrationTestTimeout)
			defer cancel()
			if err := client.connect(ctx); err == nil || !strings.Contains(err.Error(), "persist registration state") {
				t.Fatalf("connect must fail when the proof cannot be saved: %v", err)
			}
			<-registrations
			if client.conn != nil || client.out != nil {
				t.Fatal("failed registration left an active connection")
			}
			if tc.state.HostID != "host-1" || tc.state.HostProof != "new-proof" {
				t.Fatal("acknowledged identity was not retained for retry")
			}
			if err := client.connect(ctx); err == nil || !strings.Contains(err.Error(), "persist state before registration") {
				t.Fatalf("retry must fail before echoing an unsaved proof: %v", err)
			}
			if len(registrations) != 0 {
				t.Fatal("retry registered while state was unwritable")
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(backup, path); err != nil {
				t.Fatal(err)
			}
			if err := client.connect(ctx); err != nil {
				t.Fatalf("retry after restoring storage: %v", err)
			}
			registration := <-registrations
			if registration.HostID != "host-1" || registration.HostProof != "new-proof" {
				t.Fatal("retry did not return acknowledged identity")
			}
		})
	}
}

func TestConnectPersistsIssuedHostProof(t *testing.T) {
	registrations := make(chan protocol.RegisterMessage, 1)
	backend := registrationServer(t, protocol.AckMessage{
		Type:      "ack",
		HostID:    "host-1",
		HostProof: "proof-1",
	}, registrations)
	defer backend.Close()

	dir := t.TempDir()
	state := &config.State{}
	client := NewClient(&config.Config{
		BackendURL: websocketURL(backend.URL),
		StateDir:   dir,
	}, state, nil)

	ctx, cancel := context.WithTimeout(context.Background(), registrationTestTimeout)
	defer cancel()
	if err := client.connect(ctx); err != nil {
		t.Fatalf("connect: %v", err)
	}

	registration := <-registrations
	if !registration.HostProofCapable {
		t.Fatal("first registration did not advertise host_proof_capable")
	}
	if registration.HostProof != "" {
		t.Fatalf("first registration host_proof = %q, want empty", registration.HostProof)
	}
	if state.HostID != "host-1" || state.HostProof != "proof-1" {
		t.Fatalf("in-memory state = %#v, want issued host ID and proof", state)
	}

	loaded, err := config.LoadState(dir)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if loaded.HostID != "host-1" || loaded.HostProof != "proof-1" {
		t.Fatalf("persisted state = %#v, want issued host ID and proof", loaded)
	}
}

func TestConnectPersistsProofAddedToExistingHost(t *testing.T) {
	registrations := make(chan protocol.RegisterMessage, 1)
	backend := registrationServer(t, protocol.AckMessage{
		Type:      "ack",
		HostID:    "host-1",
		HostProof: "proof-1",
	}, registrations)
	defer backend.Close()

	dir := t.TempDir()
	state := &config.State{HostID: "host-1"}
	client := NewClient(&config.Config{
		BackendURL: websocketURL(backend.URL),
		StateDir:   dir,
	}, state, nil)

	ctx, cancel := context.WithTimeout(context.Background(), registrationTestTimeout)
	defer cancel()
	if err := client.connect(ctx); err != nil {
		t.Fatalf("connect: %v", err)
	}
	<-registrations

	loaded, err := config.LoadState(dir)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if loaded.HostID != "host-1" || loaded.HostProof != "proof-1" {
		t.Fatalf("persisted state = %#v, want rollout proof on existing host", loaded)
	}
}

func TestConnectReturnsStoredHostProof(t *testing.T) {
	registrations := make(chan protocol.RegisterMessage, 1)
	backend := registrationServer(t, protocol.AckMessage{
		Type:   "ack",
		HostID: "host-1",
	}, registrations)
	defer backend.Close()

	state := &config.State{HostID: "host-1", HostProof: "proof-1"}
	client := NewClient(&config.Config{
		BackendURL: websocketURL(backend.URL),
		StateDir:   t.TempDir(),
	}, state, nil)

	ctx, cancel := context.WithTimeout(context.Background(), registrationTestTimeout)
	defer cancel()
	if err := client.connect(ctx); err != nil {
		t.Fatalf("connect: %v", err)
	}

	registration := <-registrations
	if !registration.HostProofCapable {
		t.Fatal("reconnect did not advertise host_proof_capable")
	}
	if registration.HostID != "host-1" || registration.HostProof != "proof-1" {
		t.Fatalf("registration = %#v, want stored host ID and proof", registration)
	}
	if state.HostProof != "proof-1" {
		t.Fatalf("legacy ack erased stored proof: %#v", state)
	}
}

func TestConnectDoesNotCarryProofAcrossHostReassignment(t *testing.T) {
	registrations := make(chan protocol.RegisterMessage, 1)
	backend := registrationServer(t, protocol.AckMessage{
		Type:   "ack",
		HostID: "host-2",
	}, registrations)
	defer backend.Close()

	state := &config.State{HostID: "host-1", HostProof: "proof-1"}
	client := NewClient(&config.Config{
		BackendURL: websocketURL(backend.URL),
		StateDir:   t.TempDir(),
	}, state, nil)

	ctx, cancel := context.WithTimeout(context.Background(), registrationTestTimeout)
	defer cancel()
	if err := client.connect(ctx); err != nil {
		t.Fatalf("connect: %v", err)
	}
	<-registrations

	if state.HostID != "host-2" || state.HostProof != "" {
		t.Fatalf("reassigned state = %#v, want new host ID without stale proof", state)
	}
}

func registrationServer(
	t *testing.T,
	ack protocol.AckMessage,
	registrations chan<- protocol.RegisterMessage,
	beforeAck ...func(),
) *httptest.Server {
	t.Helper()
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		for _, hook := range beforeAck {
			hook()
		}
		if err := conn.WriteJSON(ack); err != nil {
			t.Errorf("write ack: %v", err)
		}
	}))
}

func websocketURL(httpURL string) string {
	return "ws" + strings.TrimPrefix(httpURL, "http")
}
