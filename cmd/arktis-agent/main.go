package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"

	"github.com/bisskar/arktis-agent/internal/audit"
	"github.com/bisskar/arktis-agent/internal/config"
	"github.com/bisskar/arktis-agent/internal/connection"
	"github.com/bisskar/arktis-agent/internal/session"
)

// Version is set via ldflags at build time.
var Version = "dev"

func defaultStateDir() string {
	if runtime.GOOS == "windows" {
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		return pd + `\arktis-agent`
	}
	return "/etc/arktis-agent"
}

func main() {
	url := flag.String("url", "", "Backend WebSocket URL (required)")
	key := flag.String("key", "", "Registration key (required)")
	stateDir := flag.String("state-dir", defaultStateDir(), "Directory for persistent state")
	allowElevation := flag.Bool("allow-elevation", envBool("ARKTIS_ALLOW_ELEVATION", false),
		"Honour exec messages with elevation_required=true (otherwise: refuse with exit_code=126)")
	maxExec := flag.Int("max-exec-concurrency", envInt("ARKTIS_MAX_EXEC", 8),
		"Maximum simultaneous in-flight exec commands; further requests are rejected with exit_code=503")
	maxPty := flag.Int("max-pty-sessions", envInt("ARKTIS_MAX_PTY", 4),
		"Maximum simultaneous PTY sessions; further opens are rejected with reason=\"agent at pty capacity\"")
	auditLogPath := flag.String("audit-log", os.Getenv("ARKTIS_AUDIT_LOG"),
		"Path to a JSON-line audit log of every exec/pty event (file is opened with O_APPEND|O_CREAT, mode 0600). Empty disables auditing.")
	auditIncludeCmd := flag.Bool("audit-log-include-command", envBool("ARKTIS_AUDIT_LOG_INCLUDE_COMMAND", false),
		"Include the full command body in audit records. Default logs only a SHA-256 hash + byte count.")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("arktis-agent %s\n", Version)
		os.Exit(0)
	}

	if *url == "" || *key == "" {
		fmt.Fprintln(os.Stderr, "Error: --url and --key are required")
		flag.Usage()
		os.Exit(1)
	}

	cfg := &config.Config{
		BackendURL: *url,
		Key:        *key,
		StateDir:   *stateDir,
	}

	// Ensure state directory exists.
	if err := os.MkdirAll(cfg.StateDir, 0700); err != nil {
		log.Fatalf("Failed to create state directory %s: %v", cfg.StateDir, err)
	}

	// Stage exec scripts under the agent's private state dir rather than
	// the shared system temp — keeps payloads (which may contain secrets)
	// off a world-readable path and removes the predictable-name TOCTOU
	// vector.
	scriptsDir := filepath.Join(cfg.StateDir, "scripts")
	if err := os.MkdirAll(scriptsDir, 0700); err != nil {
		log.Fatalf("Failed to create scripts directory %s: %v", scriptsDir, err)
	}

	// Load or create persistent state. Only the genuine "no file yet" case
	// should silently fall through to a fresh registration; everything else
	// (permission denied, corrupt JSON, failing disk) must abort startup
	// rather than silently re-register and orphan the previous host record.
	state, err := config.LoadState(cfg.StateDir)
	switch {
	case err == nil:
		// proceed with the loaded state
	case errors.Is(err, fs.ErrNotExist):
		log.Printf("First boot: no state.json in %s, starting fresh", cfg.StateDir)
		state = &config.State{}
	default:
		log.Fatalf("Failed to load state from %s: %v "+
			"(refusing to start; fix manually or delete state.json)",
			cfg.StateDir, err)
	}

	log.Printf("arktis-agent %s starting (state-dir=%s)", Version, cfg.StateDir)

	// Inject version into the connection package for registration messages.
	connection.SetVersion(Version)

	if *allowElevation {
		log.Printf("Elevation enabled: backend-issued elevation_required=true commands will run via sudo")
	}

	auditLog, err := audit.Open(*auditLogPath, *auditIncludeCmd)
	if err != nil {
		log.Fatalf("Failed to open audit log: %v", err)
	}
	defer auditLog.Close()
	if *auditLogPath != "" {
		log.Printf("Audit log enabled at %s (include_command=%v)", *auditLogPath, *auditIncludeCmd)
	}

	// Create session manager and WebSocket client.
	mgr := session.NewManager(session.Config{
		ScriptsDir:     scriptsDir,
		MaxExec:        *maxExec,
		MaxPty:         *maxPty,
		AllowElevation: *allowElevation,
		Audit:          auditLog,
	})
	client := connection.NewClient(cfg, state, mgr)

	// Context with OS signal cancellation.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		sig := <-sigCh
		log.Printf("Received signal %s, shutting down gracefully...", sig)
		mgr.CloseAll()
		cancel()

		// Stop intercepting signals so a second Ctrl+C triggers Go's default
		// SIGINT handler and force-exits. Prevents the process from hanging
		// if graceful shutdown gets stuck.
		signal.Stop(sigCh)
	}()

	if err := client.Run(ctx); err != nil {
		log.Fatalf("Agent exited with error: %v", err)
	}

	log.Println("arktis-agent stopped")
}

func envBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		log.Printf("Warning: ignoring %s=%q: %v", key, v, err)
		return fallback
	}
	return b
}

func envInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		log.Printf("Warning: ignoring %s=%q: must be a positive integer", key, v)
		return fallback
	}
	return n
}
