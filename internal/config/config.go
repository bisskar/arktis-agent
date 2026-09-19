package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config holds runtime configuration parsed from CLI flags.
type Config struct {
	BackendURL     string
	Key            string
	StateDir       string
	CACertPath     string // PEM file used as the *only* trusted root; empty = system roots
	PinSPKI        string // hex SHA-256 of expected leaf SubjectPublicKeyInfo; empty = unpinned
	StrictEndpoint bool   // refuse to reconnect to a different IP than last seen (#31)
}

// State holds persistent agent state across restarts.
type State struct {
	HostID        string `json:"host_id"`
	HostProof     string `json:"host_proof,omitempty"` // secret issued by the backend for this HostID
	RegisteredAt  string `json:"registered_at"`
	LastBackendIP string `json:"last_backend_ip,omitempty"`
}

const stateFileName = "state.json"

// LoadState reads the state file from the given directory.
// Returns an error if the file does not exist or cannot be parsed.
func LoadState(dir string) (*State, error) {
	path := filepath.Join(dir, stateFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read state file: %w", err)
	}

	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse state file: %w", err)
	}

	return &s, nil
}

// SaveState replaces state.json with a protected new file. Readers holding an
// older, potentially public file open must never see a newly issued host proof.
func SaveState(dir string, state *State) error {
	if err := protectStateDir(dir); err != nil {
		return fmt.Errorf("protect state directory: %w", err)
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}

	file, err := os.CreateTemp(dir, ".state-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary state file: %w", err)
	}
	defer func() {
		_ = file.Close()
		_ = os.Remove(file.Name())
	}()
	if err := protectStateFile(file); err != nil {
		return fmt.Errorf("protect state file: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write state file: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync state file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close state file: %w", err)
	}
	if err := replaceStateFile(file.Name(), filepath.Join(dir, stateFileName)); err != nil {
		return fmt.Errorf("replace state file: %w", err)
	}

	return nil
}
