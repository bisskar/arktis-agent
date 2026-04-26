package executor

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"
)

const maxOutputBytes = 1 * 1024 * 1024 // 1 MB

// ExecuteCommand runs a command through the specified shell WITHOUT encoding.
//
// Commands are executed in plain text so that detection rules (EDR, Sysmon,
// Sentinel) can see the actual command line in process creation events.
// This is critical for atomic test validation — base64-encoded commands
// are invisible to most detection rules.
//
// Shell dispatch:
//   - powershell  → powershell.exe -NoProfile -Command "<command>"
//   - command_prompt → writes temp .bat file, runs cmd.exe /c <file>
//   - bash → /bin/bash -c "<command>"
//   - sh   → /bin/sh -c "<command>"
func ExecuteCommand(ctx context.Context, command string, executorName string, elevationRequired bool, timeoutSec int) (stdout string, stderr string, exitCode int, duration float64, err error) {
	if timeoutSec <= 0 {
		timeoutSec = 300
	}

	cmdCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
	defer cancel()

	var cmd *exec.Cmd

	switch strings.ToLower(executorName) {
	case "powershell":
		cmd = buildPowerShellCmd(cmdCtx, command)

	case "command_prompt":
		cmd, err = buildCmdPromptCmd(cmdCtx, command)
		if err != nil {
			return "", "", 1, 0, fmt.Errorf("failed to prepare cmd script: %w", err)
		}

	case "bash":
		cmd = buildBashCmd(cmdCtx, command, elevationRequired)

	case "sh":
		cmd = buildShCmd(cmdCtx, command, elevationRequired)

	default:
		// Unknown executor — try to run directly
		if runtime.GOOS == "windows" {
			cmd = exec.CommandContext(cmdCtx, "cmd.exe", "/C", command)
		} else {
			cmd = exec.CommandContext(cmdCtx, "/bin/sh", "-c", command)
		}
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	start := time.Now()
	runErr := cmd.Run()
	duration = time.Since(start).Seconds()

	stdout = truncate(stdoutBuf.String(), maxOutputBytes)
	stderr = truncate(stderrBuf.String(), maxOutputBytes)

	exitCode = 0
	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else if cmdCtx.Err() == context.DeadlineExceeded {
			exitCode = 124
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

// buildPowerShellCmd creates a PowerShell process that executes the command
// via stdin piping. The process command line shows:
//   powershell.exe -NoProfile -NonInteractive -Command -
// and the actual command goes through stdin, but PowerShell still logs
// the script block content in ScriptBlock Logging (Event ID 4104) which
// detection rules can read.
//
// We also set preference variables to suppress noisy output streams
// that interfere with clean stdout/stderr capture.
func buildPowerShellCmd(ctx context.Context, command string) *exec.Cmd {
	// Pipe the command via stdin to avoid all quoting issues.
	// PowerShell's -Command - reads from stdin.
	// ScriptBlock Logging (4104) still captures the full script text.
	preamble := "$ProgressPreference='SilentlyContinue';" +
		"$InformationPreference='SilentlyContinue';" +
		"$WarningPreference='SilentlyContinue';" +
		"$ErrorActionPreference='Continue';\n"

	fullScript := preamble + command

	cmd := exec.CommandContext(ctx,
		"powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-Command", "-",
	)
	cmd.Stdin = strings.NewReader(fullScript)
	return cmd
}

// buildCmdPromptCmd writes the command to a temp .bat file and executes it
// with cmd.exe /c. The process tree shows the actual batch commands.
// The temp file is cleaned up after execution.
func buildCmdPromptCmd(ctx context.Context, command string) (*exec.Cmd, error) {
	// Write to temp .bat file — avoids quoting issues entirely.
	// cmd.exe runs the file directly, so the commands are visible in
	// process creation events and file system monitoring.
	tmpDir := os.TempDir()
	tmpFile := filepath.Join(tmpDir, fmt.Sprintf("arktis_%d.bat", time.Now().UnixNano()))

	// Ensure CRLF line endings for Windows batch files, append self-cleanup
	script := strings.ReplaceAll(command, "\n", "\r\n")
	script += "\r\ndel /Q \"" + tmpFile + "\" >nul 2>&1\r\n"

	if err := os.WriteFile(tmpFile, []byte(script), 0644); err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, "cmd.exe", "/C", tmpFile)
	return cmd, nil
}

// buildBashCmd writes the command to a temp .sh script and executes it.
//
// Why not bash -c? Complex ART commands contain quotes, $variables,
// backticks, pipes, and multi-line heredocs that break shell argument
// parsing. A temp file avoids all escaping issues.
//
// Detection visibility:
//   - Process tree shows: /bin/bash /tmp/arktis_xxx.sh
//   - Each command inside the script spawns child processes with
//     their full command lines visible to auditd/sysmon
//   - File integrity monitoring can read the script content
//   - The script is cleaned up after execution
func buildBashCmd(ctx context.Context, command string, elevationRequired bool) *exec.Cmd {
	return buildShellScript(ctx, command, "/bin/bash", elevationRequired)
}

// buildShCmd writes the command to a temp .sh script and executes it via sh.
func buildShCmd(ctx context.Context, command string, elevationRequired bool) *exec.Cmd {
	return buildShellScript(ctx, command, "/bin/sh", elevationRequired)
}

// buildShellScript writes a command to a temp script and returns a Cmd to run it.
// The script is self-deleting (trap on EXIT removes the temp file).
func buildShellScript(ctx context.Context, command string, shell string, elevationRequired bool) *exec.Cmd {
	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("arktis_%d.sh", time.Now().UnixNano()))

	// Prepend a self-cleanup trap and a shebang
	script := fmt.Sprintf("#!%s\ntrap 'rm -f \"%s\"' EXIT\n%s\n", shell, tmpFile, command)
	// Best-effort write — if it fails, exec will fail with a clear error
	os.WriteFile(tmpFile, []byte(script), 0700)

	if elevationRequired {
		return exec.CommandContext(ctx, "sudo", shell, tmpFile)
	}
	return exec.CommandContext(ctx, shell, tmpFile)
}

func truncate(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	// Back up to a UTF-8 rune boundary so we don't emit invalid UTF-8
	// (which JSON encoding would later replace with U+FFFD).
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "\n[OUTPUT TRUNCATED at 1MB]"
}
