//go:build !windows

package config

import "os"

func protectStateDir(dir string) error {
	return os.Chmod(dir, 0o700)
}

func protectStateFile(file *os.File) error {
	return file.Chmod(0o600)
}
