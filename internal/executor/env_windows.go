//go:build windows

package executor

import "os"

// minimalEnv returns the env vars that we propagate to child processes.
// Windows tools (PowerShell in particular) lean on a wider set of
// system-defined variables than Unix shells, so the allowlist is larger
// — but it still excludes anything the agent's launcher might have
// injected (registration key, cloud creds, CI tokens, etc.).
func minimalEnv() []string {
	keys := []string{
		"SystemRoot", "SystemDrive", "windir",
		"PATH", "PATHEXT",
		"COMSPEC",
		"USERPROFILE", "USERNAME", "USERDOMAIN",
		"HOMEDRIVE", "HOMEPATH",
		"TEMP", "TMP",
		"ProgramFiles", "ProgramFiles(x86)", "ProgramW6432",
		"ProgramData", "ALLUSERSPROFILE",
		"APPDATA", "LOCALAPPDATA",
		"PUBLIC",
		"PSModulePath",
	}
	env := make([]string, 0, len(keys))
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	return env
}
