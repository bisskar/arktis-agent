package executor

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"
	"unicode/utf16"
)

const maxOutputBytes = 1 * 1024 * 1024 // 1 MB

// WrapCommand prepares the raw command string for execution through the
// appropriate shell or interpreter, mirroring the Python SSHExecutor logic.
func WrapCommand(command string, executorName string, elevationRequired bool) string {
	switch strings.ToLower(executorName) {
	case "powershell":
		return wrapPowerShell(command)
	case "command_prompt":
		return wrapCommandPrompt(command)
	case "bash":
		return wrapBash(command, elevationRequired)
	case "sh":
		return wrapSh(command, elevationRequired)
	default:
		return command
	}
}

// wrapPowerShell encodes the command as UTF-16LE base64 for -EncodedCommand.
func wrapPowerShell(command string) string {
	// Prepend stream-silencing preferences.
	preamble := "$ProgressPreference='SilentlyContinue';" +
		"$WarningPreference='SilentlyContinue';\n"
	full := preamble + command

	// Encode to UTF-16LE.
	runes := utf16.Encode([]rune(full))
	buf := make([]byte, len(runes)*2)
	for i, r := range runes {
		buf[i*2] = byte(r)
		buf[i*2+1] = byte(r >> 8)
	}
	encoded := base64.StdEncoding.EncodeToString(buf)

	return fmt.Sprintf("powershell.exe -NoProfile -NonInteractive -EncodedCommand %s", encoded)
}

// wrapCommandPrompt creates a base64-encoded batch script, decoded via
// PowerShell bootstrap into a temp file, then executed with cmd.exe /c.
func wrapCommandPrompt(command string) string {
	b64 := base64.StdEncoding.EncodeToString([]byte(command))

	// PowerShell decodes the base64, writes a temp .bat, runs it, cleans up.
	bootstrap := fmt.Sprintf(
		`$b=[System.Convert]::FromBase64String('%s');`+
			`$f=[System.IO.Path]::GetTempFileName()+'.bat';`+
			`[System.IO.File]::WriteAllBytes($f,$b);`+
			`cmd.exe /c $f;`+
			`Remove-Item $f -Force`,
		b64,
	)

	return fmt.Sprintf("powershell.exe -NoProfile -NonInteractive -Command \"%s\"", bootstrap)
}

// wrapBash base64-encodes the script and pipes it through bash.
func wrapBash(command string, elevationRequired bool) string {
	b64 := base64.StdEncoding.EncodeToString([]byte(command))
	cmd := fmt.Sprintf("echo %s | base64 -d | /bin/bash", b64)
	if elevationRequired {
		cmd = "sudo " + cmd
	}
	return cmd
}

// wrapSh base64-encodes the script and pipes it through sh.
func wrapSh(command string, elevationRequired bool) string {
	b64 := base64.StdEncoding.EncodeToString([]byte(command))
	cmd := fmt.Sprintf("echo %s | base64 -d | /bin/sh", b64)
	if elevationRequired {
		cmd = "sudo " + cmd
	}
	return cmd
}

// ExecuteCommand runs the wrapped command with the given timeout.
// Returns stdout, stderr, exit code, duration in seconds, and any error.
func ExecuteCommand(ctx context.Context, wrappedCmd string, timeoutSec int) (stdout string, stderr string, exitCode int, duration float64, err error) {
	if timeoutSec <= 0 {
		timeoutSec = 300 // Default 5 minutes.
	}

	cmdCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(cmdCtx, "cmd.exe", "/C", wrappedCmd)
	} else {
		cmd = exec.CommandContext(cmdCtx, "/bin/sh", "-c", wrappedCmd)
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	start := time.Now()
	runErr := cmd.Run()
	duration = time.Since(start).Seconds()

	stdout = truncate(stdoutBuf.String(), maxOutputBytes)
	stderr = truncate(stderrBuf.String(), maxOutputBytes)

	// Determine exit code.
	exitCode = 0
	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else if cmdCtx.Err() == context.DeadlineExceeded {
			exitCode = 124 // Standard timeout exit code.
			stderr = truncate(stderr+"\n[TIMEOUT] Command exceeded "+fmt.Sprintf("%d", timeoutSec)+"s limit", maxOutputBytes)
			err = fmt.Errorf("command timed out after %ds", timeoutSec)
			return
		} else {
			exitCode = 1
			err = fmt.Errorf("exec error: %w", runErr)
			return
		}
	}

	return
}

// truncate limits a string to maxBytes, appending a truncation notice.
func truncate(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	return s[:maxBytes] + "\n[OUTPUT TRUNCATED at 1MB]"
}
