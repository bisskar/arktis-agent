//go:build linux

package executor

import "os"

// minimalEnv returns the env vars that we propagate to child processes.
// Anything not listed here (e.g. ARKTIS_KEY, AWS_*, GITHUB_TOKEN,
// LD_PRELOAD, systemd EnvironmentFile secrets) is deliberately stripped
// so a backend-issued `env` cannot exfiltrate them via stdout.
func minimalEnv() []string {
	env := []string{
		"PATH=" + getenvDefault("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
		"LANG=" + getenvDefault("LANG", "C.UTF-8"),
	}
	for _, k := range []string{"HOME", "USER", "LOGNAME", "SHELL"} {
		if v := os.Getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	return env
}

func getenvDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
