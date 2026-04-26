package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
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
	urlFlag := flag.String("url", os.Getenv("ARKTIS_URL"),
		"Backend WebSocket URL (required). Must be wss:// unless --insecure is set.")
	keyFlag := flag.String("key", "",
		"DEPRECATED: registration key on argv. Visible to ps/auditd. Use --key-file or ARKTIS_KEY instead.")
	keyFilePath := flag.String("key-file", os.Getenv("ARKTIS_KEY_FILE"),
		"Path to a file containing the registration key. Preferred over --key. File must be mode 0600 or stricter.")
	insecure := flag.Bool("insecure", envBool("ARKTIS_INSECURE", false),
		"Allow ws:// (plaintext) backend URLs. The dial path will log a loud warning on every connect.")
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
	requireNonRoot := flag.Bool("require-non-root", envBool("ARKTIS_REQUIRE_NON_ROOT", false),
		"Refuse to start if the agent is running as root (Linux euid=0). Combine with --allow-elevation=false (the default) to enforce least privilege.")
	caCertPath := flag.String("ca-cert", os.Getenv("ARKTIS_CA_CERT"),
		"Path to a PEM file used as the *only* trusted root for the backend's TLS cert. Defence-in-depth against system-CA compromise.")
	pinSPKI := flag.String("pin-spki", os.Getenv("ARKTIS_PIN_SPKI"),
		"Hex-encoded SHA-256 of the backend's SubjectPublicKeyInfo. The dial fails if the leaf cert's SPKI hash does not match.")
	strictEndpoint := flag.Bool("strict-endpoint", envBool("ARKTIS_STRICT_ENDPOINT", false),
		"Refuse to reconnect if the backend's resolved IP differs from the one captured on first connect (DNS-rebinding mitigation).")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("arktis-agent %s\n", Version)
		os.Exit(0)
	}

	if *urlFlag == "" {
		fmt.Fprintln(os.Stderr, "Error: --url (or ARKTIS_URL) is required")
		flag.Usage()
		os.Exit(1)
	}

	// Validate the backend URL scheme. wss:// is required unless the
	// operator opts into ws:// via --insecure (or ARKTIS_INSECURE=1).
	// Without this gate, a typo or copy-pasted dev command leaks the
	// registration key (and every exec/PTY frame) over plaintext.
	parsedURL, err := url.Parse(*urlFlag)
	if err != nil {
		log.Fatalf("Invalid --url: %v", err)
	}
	switch parsedURL.Scheme {
	case "wss":
		// fine
	case "ws":
		if !*insecure {
			log.Fatalf("Refusing ws:// URL %q: TLS is required by default. "+
				"Pass --insecure (or ARKTIS_INSECURE=1) only for local development.", *urlFlag)
		}
		log.Println("WARNING: TLS DISABLED. ws:// is unencrypted; the registration key " +
			"and every exec/PTY frame are visible on the wire. Use only for local dev.")
	default:
		log.Fatalf("Unsupported --url scheme %q (expected wss:// or ws://)", parsedURL.Scheme)
	}

	// Resolve the registration key in priority order. We unset the env
	// var after consuming it so a child process spawned later in this
	// binary's lifetime cannot grep it back out.
	resolvedKey, err := loadKey(*keyFilePath, *keyFlag)
	if err != nil {
		log.Fatalf("Failed to load registration key: %v", err)
	}
	if *keyFlag != "" {
		log.Println("WARNING: --key on argv is deprecated and visible via /proc, ps, and auditd. " +
			"Switch to --key-file or ARKTIS_KEY (loaded from systemd EnvironmentFile).")
	}
	_ = os.Unsetenv("ARKTIS_KEY")

	cfg := &config.Config{
		BackendURL:     *urlFlag,
		Key:            resolvedKey,
		StateDir:       *stateDir,
		CACertPath:     *caCertPath,
		PinSPKI:        *pinSPKI,
		StrictEndpoint: *strictEndpoint,
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

	// Least-privilege gate. os.Geteuid() returns -1 on Windows, so the
	// numerical check naturally only applies on Unix.
	euid := os.Geteuid()
	if *requireNonRoot && euid == 0 {
		log.Fatalf("--require-non-root set but agent is running as root (euid=0); " +
			"create a dedicated user (see README 'Security Model')")
	}
	if euid == 0 && !*allowElevation {
		log.Println("Warning: running as root without --allow-elevation. " +
			"The agent does not need root privileges to run non-elevated tests. " +
			"See README 'Security Model' for least-privilege setup.")
	}

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
		// Operator-supplied path (--audit-log flag); %q neutralises any
		// embedded newline/tab. gosec G706 flags this as taint, but the
		// "attacker" here is whoever already configured the agent's CLI.
		// #nosec G706 -- operator input, not network input.
		log.Printf("Audit log enabled at %q (include_command=%v)", *auditLogPath, *auditIncludeCmd)
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
		// #nosec G706 -- operator-supplied env var; %q neutralises escapes.
		log.Printf("Warning: ignoring %s=%q: %v", key, v, err)
		return fallback
	}
	return b
}

// loadKey resolves the registration key in priority order:
//  1. --key-file
//  2. ARKTIS_KEY environment variable (loaded once)
//  3. --key on argv (deprecated)
//
// Returns an error if none are set. --key-file requires the file mode
// to be 0600 or stricter on Unix; on Windows the check is a no-op.
func loadKey(keyFilePath, keyFlag string) (string, error) {
	if keyFilePath != "" {
		// #nosec G304 -- operator-supplied --key-file path.
		fi, err := os.Stat(keyFilePath)
		if err != nil {
			return "", fmt.Errorf("stat --key-file %s: %w", keyFilePath, err)
		}
		if runtime.GOOS != "windows" {
			if mode := fi.Mode().Perm(); mode&0o077 != 0 {
				return "", fmt.Errorf("--key-file %s has insecure permissions %o; must be 0600 or stricter",
					keyFilePath, mode)
			}
		}
		// #nosec G304 -- operator-supplied --key-file path.
		raw, err := os.ReadFile(keyFilePath)
		if err != nil {
			return "", fmt.Errorf("read --key-file %s: %w", keyFilePath, err)
		}
		k := strings.TrimSpace(string(raw))
		if k == "" {
			return "", fmt.Errorf("--key-file %s is empty", keyFilePath)
		}
		return k, nil
	}
	if env := os.Getenv("ARKTIS_KEY"); env != "" {
		return env, nil
	}
	if keyFlag != "" {
		return keyFlag, nil
	}
	return "", errors.New("registration key not provided (set --key-file, ARKTIS_KEY, or --key)")
}

func envInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		// #nosec G706 -- operator-supplied env var; %q neutralises escapes.
		log.Printf("Warning: ignoring %s=%q: must be a positive integer", key, v)
		return fallback
	}
	return n
}
