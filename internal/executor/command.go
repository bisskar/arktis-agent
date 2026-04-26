package executor

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
	"unicode/utf8"
)

const maxOutputBytes = 1 * 1024 * 1024 // 1 MB

// ExecRequest bundles the inputs to ExecuteCommand. Using a struct keeps
// the call site readable as the parameter list grows (e.g. opt-in
// PowerShell preference suppression).
type ExecRequest struct {
	Ctx                context.Context
	ScriptsDir         string
	Command            string
	ExecutorName       string
	ElevationRequired  bool
	TimeoutSeconds     int
	SilencePreferences bool
}

// ExecResult is the outcome of running a backend-issued command.
type ExecResult struct {
	Stdout          string
	Stderr          string
	StdoutTruncated bool
	StderrTruncated bool
	ExitCode        int
	DurationSeconds float64
}

// ExecuteCommand runs a command through the specified shell WITHOUT encoding.
//
// Commands are executed in plain text so that detection rules (EDR, Sysmon,
// Sentinel) can see the actual command line in process creation events.
// This is critical for atomic test validation — base64-encoded commands
// are invisible to most detection rules.
//
// Shell dispatch:
//   - powershell      → powershell.exe -NoProfile -NonInteractive -Command -
//   - command_prompt  → writes temp .bat file, runs cmd.exe /C <file>
//   - bash            → /bin/bash <tmp.sh>
//   - sh              → /bin/sh   <tmp.sh>
//
// req.ScriptsDir is the agent-private directory used for staging temp
// scripts; it must exist with mode 0700 (caller's responsibility). An
// unknown ExecutorName is rejected — we never silently downgrade to
// /bin/sh -c.
func ExecuteCommand(req ExecRequest) (ExecResult, error) {
	timeoutSec := req.TimeoutSeconds
	if timeoutSec <= 0 {
		timeoutSec = 300
	}

	cmdCtx, cancel := context.WithTimeout(req.Ctx, time.Duration(timeoutSec)*time.Second)
	defer cancel()

	var (
		cmd     *exec.Cmd
		tmpFile string // staged script path; cleaned up below if non-empty
		err     error
	)

	switch strings.ToLower(req.ExecutorName) {
	case "powershell":
		cmd = buildPowerShellCmd(cmdCtx, req.Command, req.SilencePreferences)

	case "command_prompt":
		cmd, tmpFile, err = buildCmdPromptCmd(cmdCtx, req.ScriptsDir, req.Command)
		if err != nil {
			return ExecResult{ExitCode: 1}, fmt.Errorf("stage cmd script: %w", err)
		}

	case "bash":
		cmd, tmpFile, err = buildShellCmd(cmdCtx, req.ScriptsDir, req.Command, "/bin/bash", req.ElevationRequired)
		if err != nil {
			return ExecResult{ExitCode: 1}, fmt.Errorf("stage bash script: %w", err)
		}

	case "sh":
		cmd, tmpFile, err = buildShellCmd(cmdCtx, req.ScriptsDir, req.Command, "/bin/sh", req.ElevationRequired)
		if err != nil {
			return ExecResult{ExitCode: 1}, fmt.Errorf("stage sh script: %w", err)
		}

	default:
		// Reject unknown executors instead of silently downgrading to the
		// most permissive shell on the host.
		return ExecResult{
			Stderr:   fmt.Sprintf("unknown executor_name %q (allowed: powershell, command_prompt, bash, sh)", req.ExecutorName),
			ExitCode: 2,
		}, fmt.Errorf("unknown executor_name %q", req.ExecutorName)
	}

	if tmpFile != "" {
		defer os.Remove(tmpFile)
	}

	// Strip the agent's environment from the child. We only forward a
	// minimal set of OS env vars — anything secret-shaped that the agent
	// inherited (ARKTIS_KEY, cloud creds, systemd EnvironmentFile entries)
	// is deliberately excluded so a backend-issued `env` can't exfiltrate it.
	cmd.Env = minimalEnv()

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	start := time.Now()
	runErr := cmd.Run()
	duration := time.Since(start).Seconds()

	stdout, stdoutTruncated := truncate(stdoutBuf.String(), maxOutputBytes)
	stderr, stderrTruncated := truncate(stderrBuf.String(), maxOutputBytes)

	res := ExecResult{
		Stdout:          stdout,
		Stderr:          stderr,
		StdoutTruncated: stdoutTruncated,
		StderrTruncated: stderrTruncated,
		DurationSeconds: duration,
	}

	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			res.ExitCode = exitErr.ExitCode()
		} else if cmdCtx.Err() == context.DeadlineExceeded {
			res.ExitCode = 124
			res.Stderr, res.StderrTruncated = truncate(res.Stderr+"\n[TIMEOUT] Command exceeded "+fmt.Sprintf("%d", timeoutSec)+"s limit", maxOutputBytes)
			return res, fmt.Errorf("command timed out after %ds", timeoutSec)
		} else {
			res.ExitCode = 1
			return res, fmt.Errorf("exec error: %w", runErr)
		}
	}

	return res, nil
}

// buildPowerShellCmd creates a PowerShell process that executes the command
// via stdin piping. The process command line shows:
//
//	powershell.exe -NoProfile -NonInteractive -Command -
//
// and the actual command goes through stdin, but PowerShell still logs
// the script block content in ScriptBlock Logging (Event ID 4104) which
// detection rules can read.
//
// We deliberately do NOT pass -ExecutionPolicy Bypass: it's a
// high-fidelity malicious-PowerShell indicator that EDR rules look for,
// and the agent has no business pretending to be malware on the host.
// If the host policy is Restricted/AllSigned the test should fail loudly
// rather than be smuggled past it.
//
// silencePreferences is opt-in per-test: when false (the default), the
// preamble is omitted so $ErrorActionPreference stays at Stop and real
// failures surface as non-zero exit. When true, the original
// SilentlyContinue / Continue preamble is restored for atomics that
// depend on the legacy behaviour.
func buildPowerShellCmd(ctx context.Context, command string, silencePreferences bool) *exec.Cmd {
	cmd := exec.CommandContext(ctx,
		"powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-Command", "-",
	)

	fullScript := command
	if silencePreferences {
		preamble := "$ProgressPreference='SilentlyContinue';" +
			"$InformationPreference='SilentlyContinue';" +
			"$WarningPreference='SilentlyContinue';" +
			"$ErrorActionPreference='Continue';\n"
		fullScript = preamble + command
	}
	cmd.Stdin = strings.NewReader(fullScript)
	return cmd
}

// buildCmdPromptCmd writes the command to a temp .bat file under scriptsDir
// (created with mode 0600 + an unguessable suffix via os.CreateTemp) and
// executes it with cmd.exe /c. The caller is responsible for removing the
// returned path.
func buildCmdPromptCmd(ctx context.Context, scriptsDir, command string) (*exec.Cmd, string, error) {
	f, err := os.CreateTemp(scriptsDir, "arktis-*.bat")
	if err != nil {
		return nil, "", fmt.Errorf("create temp script: %w", err)
	}
	tmpFile := f.Name()

	// Ensure CRLF line endings for Windows batch files.
	script := strings.ReplaceAll(command, "\n", "\r\n")
	if _, err := f.WriteString(script); err != nil {
		f.Close()
		os.Remove(tmpFile)
		return nil, "", fmt.Errorf("write temp script: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpFile)
		return nil, "", fmt.Errorf("close temp script: %w", err)
	}

	return exec.CommandContext(ctx, "cmd.exe", "/C", tmpFile), tmpFile, nil
}

// buildShellCmd writes the command to a temp .sh script under scriptsDir
// (created with mode 0600 + an unguessable suffix via os.CreateTemp) and
// returns a Cmd that invokes `<shell> <tmpFile>`. The caller is responsible
// for removing the returned path.
//
// Why not bash -c? Complex commands contain quotes, $variables, backticks,
// pipes, and multi-line heredocs that break shell argument parsing. A temp
// file avoids all escaping issues. Detection visibility is preserved
// because each command inside the script spawns a child process with its
// full command line visible to auditd/sysmon.
func buildShellCmd(ctx context.Context, scriptsDir, command, shell string, elevationRequired bool) (*exec.Cmd, string, error) {
	f, err := os.CreateTemp(scriptsDir, "arktis-*.sh")
	if err != nil {
		return nil, "", fmt.Errorf("create temp script: %w", err)
	}
	tmpFile := f.Name()

	script := fmt.Sprintf("#!%s\n%s\n", shell, command)
	if _, err := f.WriteString(script); err != nil {
		f.Close()
		os.Remove(tmpFile)
		return nil, "", fmt.Errorf("write temp script: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpFile)
		return nil, "", fmt.Errorf("close temp script: %w", err)
	}

	if elevationRequired {
		return exec.CommandContext(ctx, "sudo", shell, tmpFile), tmpFile, nil
	}
	return exec.CommandContext(ctx, shell, tmpFile), tmpFile, nil
}

func truncate(s string, maxBytes int) (string, bool) {
	if len(s) <= maxBytes {
		return s, false
	}
	// Back up to a UTF-8 rune boundary so we don't emit invalid UTF-8
	// (which JSON encoding would later replace with U+FFFD).
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "\n[OUTPUT TRUNCATED at 1MB]", true
}
