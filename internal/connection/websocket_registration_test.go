package connection

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bisskar/arktis-agent/internal/config"
	"github.com/bisskar/arktis-agent/internal/protocol"
	"github.com/gorilla/websocket"
)

const registrationTestTimeout = 2 * time.Second

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
		if err := conn.WriteJSON(ack); err != nil {
			t.Errorf("write ack: %v", err)
		}
	}))
}

func websocketURL(httpURL string) string {
	return "ws" + strings.TrimPrefix(httpURL, "http")
}
