//go:build !windows

package config

import "os"

func protectStateDir(dir string) error {
	return os.Chmod(dir, 0o700) // #nosec G302 -- This is a directory: owner traversal requires execute permission; group and other have no access.
}

func protectStateFile(file *os.File) error {
	return file.Chmod(0o600)
}
