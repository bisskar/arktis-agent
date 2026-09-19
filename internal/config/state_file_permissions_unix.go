//go:build !windows

package config

import (
	"fmt"
	"os"
	"path/filepath"
)

func replaceStateFile(oldPath, newPath string) error {
	if err := os.Rename(oldPath, newPath); err != nil {
		return err
	}
	// Syncing the file contents alone does not persist the renamed directory
	// entry. Do not allow a proof echo until both survive a host power loss.
	dir, err := os.Open(filepath.Dir(newPath)) // #nosec G304 -- The state directory is selected by the local operator, not remote input.
	if err != nil {
		return fmt.Errorf("open state directory for sync: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync state directory: %w", err)
	}
	return nil
}

func protectStateDir(dir string) error {
	return os.Chmod(dir, 0o700) // #nosec G302 -- This is a directory: owner traversal requires execute permission; group and other have no access.
}

func protectStateFile(file *os.File) error {
	return file.Chmod(0o600)
}
