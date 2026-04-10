package executor

import (
	"bytes"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// DetectPlatform returns "windows" or "linux" based on the Go runtime.
func DetectPlatform() string {
	return runtime.GOOS
}

// DetectOsFamily returns a human-readable OS family identifier.
//
// Linux: parses /etc/os-release for the ID field (e.g. "ubuntu", "kali", "debian").
// Windows: runs PowerShell to query Win32_OperatingSystem.Caption.
// Fallback: returns runtime.GOOS.
func DetectOsFamily() string {
	switch runtime.GOOS {
	case "linux":
		return detectLinuxFamily()
	case "windows":
		return detectWindowsFamily()
	default:
		return runtime.GOOS
	}
}

// DetectOsVersion returns a full OS version string.
//
// Linux: reads the PRETTY_NAME field from /etc/os-release.
// Windows: runs PowerShell to query Win32_OperatingSystem.Caption + Version.
// Fallback: returns runtime.GOOS + "/" + runtime.GOARCH.
func DetectOsVersion() string {
	switch runtime.GOOS {
	case "linux":
		return detectLinuxVersion()
	case "windows":
		return detectWindowsVersion()
	default:
		return runtime.GOOS + "/" + runtime.GOARCH
	}
}

// detectLinuxFamily reads the ID field from /etc/os-release.
func detectLinuxFamily() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "linux"
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "ID=") {
			val := strings.TrimPrefix(line, "ID=")
			val = strings.Trim(val, `"`)
			return val
		}
	}
	return "linux"
}

// detectLinuxVersion reads PRETTY_NAME from /etc/os-release.
func detectLinuxVersion() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "Linux (unknown version)"
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			val := strings.TrimPrefix(line, "PRETTY_NAME=")
			val = strings.Trim(val, `"`)
			return val
		}
	}
	return "Linux (unknown version)"
}

// detectWindowsFamily runs PowerShell to get a Windows edition identifier.
func detectWindowsFamily() string {
	out, err := runPowerShell(`(Get-CimInstance Win32_OperatingSystem).Caption`)
	if err != nil {
		return "windows"
	}
	caption := strings.TrimSpace(out)
	lower := strings.ToLower(caption)
	switch {
	case strings.Contains(lower, "server"):
		return "windows_server"
	default:
		return "windows_desktop"
	}
}

// detectWindowsVersion returns the full Windows caption + version.
func detectWindowsVersion() string {
	out, err := runPowerShell(
		`$os = Get-CimInstance Win32_OperatingSystem; "$($os.Caption) $($os.Version)"`,
	)
	if err != nil {
		return "Windows (unknown version)"
	}
	return strings.TrimSpace(out)
}

// runPowerShell executes a one-liner in PowerShell and returns stdout.
func runPowerShell(script string) (string, error) {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return buf.String(), nil
}
