package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config holds runtime configuration parsed from CLI flags.
type Config struct {
	BackendURL string
	Key        string
	StateDir   string
}

// State holds persistent agent state across restarts.
type State struct {
	HostID       string `json:"host_id"`
	RegisteredAt string `json:"registered_at"`
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

// SaveState writes the state to state.json in the given directory.
func SaveState(dir string, state *State) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}

	path := filepath.Join(dir, stateFileName)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write state file: %w", err)
	}

	return nil
}
