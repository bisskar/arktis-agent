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
	"time"

	"github.com/bisskar/arktis-agent/internal/audit"
	"github.com/bisskar/arktis-agent/internal/config"
	"github.com/bisskar/arktis-agent/internal/connection"
	"github.com/bisskar/arktis-agent/internal/diagnose"
	"github.com/bisskar/arktis-agent/internal/logging"
	"github.com/bisskar/arktis-agent/internal/session"
)

// Default WebSocket path appended to a --host value when --url is not
// explicitly set. Mirrors the path the backend serves at.
const defaultWSPath = "/api/v1/agent/ws"

// devPort is the local-dev backend port the agent connects to when
// --dev is set. Matches the FastAPI dev stack documented in
// CLAUDE.md (`host.docker.internal:8000`).
const devPort = "8000"

// prodPort is the production WS port. 443 is the only outbound port
// guaranteed available across corporate egress rules, so the agent
// defaults to it when --host is given without an explicit --url.
const prodPort = "443"

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

// synthesizeURL builds the WebSocket URL from --host when --url is empty.
// Returns "" if --host is also empty (caller must surface the error).
//
//   - prod default (the line the issue calls out): wss://<host>:443/api/v1/agent/ws
//   - --dev: ws://<host>:8000/api/v1/agent/ws — keeps the legacy local-stack shape
//
// 443 was chosen because it is the one outbound port corporate egress
// is guaranteed to allow; the old 3000/8000 defaults forced operators
// to ask for firewall changes on every customer install.
func synthesizeURL(host string, dev bool) string {
	if host == "" {
		return ""
	}
	if dev {
		return "ws://" + host + ":" + devPort + defaultWSPath
	}
	return "wss://" + host + ":" + prodPort + defaultWSPath
}

func main() {
	urlFlag := flag.String("url", os.Getenv("ARKTIS_URL"),
		"Backend WebSocket URL. Required unless --host (and optionally --dev) are set. Must be wss:// unless --insecure.")
	hostFlag := flag.String("host", os.Getenv("ARKTIS_HOST"),
		"Backend hostname. When --url is not set, the agent synthesizes wss://<host>:443/api/v1/agent/ws (prod) or ws://<host>:8000/api/v1/agent/ws (--dev).")
	devMode := flag.Bool("dev", envBool("ARKTIS_DEV", false),
		"Local-dev mode. With --host, defaults to ws://<host>:8000/api/v1/agent/ws instead of the prod 443/wss shape.")
	diagnoseFlag := flag.Bool("diagnose", false,
		"Run connectivity checks (DNS → TCP → TLS → WS upgrade → register/ack) against the configured backend, print a per-step verdict, and exit. Returns 0 on healthy, 1 on any failure.")
	logFileFlag := flag.String("log-file", os.Getenv("ARKTIS_LOG_FILE"),
		"Path to the rotated agent log file. Defaults to the OS-specific predictable path (Windows: %ProgramData%\\arktis-agent\\agent.log, Linux: /var/log/arktis-agent/agent.log, macOS: /Library/Logs/arktis-agent/agent.log). Pass '-' to skip file logging entirely.")
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
	auditChainKey := flag.String("audit-log-chain-key", os.Getenv("ARKTIS_AUDIT_LOG_CHAIN_KEY"),
		"Path to a 32-byte HMAC key used to chain audit log records (tamper-evident). The key is generated on first run if missing. Empty disables chaining.")
	requireNonRoot := flag.Bool("require-non-root", envBool("ARKTIS_REQUIRE_NON_ROOT", false),
		"Refuse to start if the agent is running as root (Linux euid=0). Combine with --allow-elevation=false (the default) to enforce least privilege.")
	caCertPath := flag.String("ca-cert", os.Getenv("ARKTIS_CA_CERT"),
		"Path to a PEM file used as the *only* trusted root for the backend's TLS cert. Defence-in-depth against system-CA compromise.")
	pinSPKI := flag.String("pin-spki", os.Getenv("ARKTIS_PIN_SPKI"),
		"Hex-encoded SHA-256 of the backend's SubjectPublicKeyInfo. The dial fails if the leaf cert's SPKI hash does not match.")
	strictEndpoint := flag.Bool("strict-endpoint", envBool("ARKTIS_STRICT_ENDPOINT", false),
		"Refuse to reconnect if the backend's resolved IP differs from the one captured on first connect (DNS-rebinding mitigation).")
	signingPubkeyFile := flag.String("signing-pubkey-file", os.Getenv("ARKTIS_SIGNING_PUBKEY_FILE"),
		"Path to a PEM-encoded Ed25519 public key. When set, exec / pty_open messages are verified against it before dispatch.")
	requireSignature := flag.Bool("require-message-signature", envBool("ARKTIS_REQUIRE_MESSAGE_SIGNATURE", false),
		"Reject unsigned exec / pty_open messages. Requires --signing-pubkey-file. Default lets unsigned messages through with a warning.")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("arktis-agent %s\n", Version)
		os.Exit(0)
	}

	if *urlFlag == "" {
		// Synthesize from --host so production installs only need to
		// provide the hostname. We pick port 443 / wss:// (or 8000 / ws://
		// under --dev) so corporate egress works out of the box.
		*urlFlag = synthesizeURL(*hostFlag, *devMode)
	}
	if *urlFlag == "" {
		fmt.Fprintln(os.Stderr, "Error: --url (or ARKTIS_URL) is required, or pass --host so the agent can build the default URL")
		flag.Usage()
		os.Exit(1)
	}

	// Configure the rotated log destination before any other startup
	// work so even early-startup errors land in the predictable file.
	// `--log-file -` opts out; empty falls back to the OS default.
	logPath := *logFileFlag
	switch logPath {
	case "-":
		logPath = ""
	case "":
		logPath = logging.DefaultPath()
	}
	logCloser, err := logging.Setup(logPath, os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "logging setup: %v\n", err)
	}
	if logCloser != nil {
		defer func() { _ = logCloser.Close() }()
	}

	// Validate the backend URL scheme. wss:// is required unless the
	// operator opts into ws:// via --insecure (or ARKTIS_INSECURE=1).
	// Without this gate, a typo or copy-pasted dev command leaks the
	// registration key (and every exec/PTY frame) over plaintext.
	parsedURL, err := url.Parse(*urlFlag)
	if err != nil {
		log.Fatalf("Invalid --url: %v", err)
	}
	// --dev is an explicit local-stack opt-in; treat it as equivalent
	// to --insecure for the URL-scheme gate so operators don't have to
	// remember both flags. The plaintext warning is still emitted so a
	// production deploy that accidentally inherits ARKTIS_DEV=1 is
	// loud about it.
	allowWS := *insecure || *devMode
	switch parsedURL.Scheme {
	case "wss":
		// fine
	case "ws":
		if !allowWS {
			log.Fatalf("Refusing ws:// URL %q: TLS is required by default. "+
				"Pass --insecure (or --dev / ARKTIS_INSECURE=1 / ARKTIS_DEV=1) only for local development.", *urlFlag)
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

	// --diagnose short-circuits before we open the audit log, write the
	// state dir, or start the reconnect loop. It is a read-only probe:
	// build the same TLS config the live agent would use, walk the five
	// connection layers, print a verdict, and exit. Onboarding now takes
	// one command instead of a 20-minute PowerShell safari.
	if *diagnoseFlag {
		tlsCfg, terr := connection.BuildTLSConfig(*caCertPath, *pinSPKI)
		if terr != nil {
			log.Fatalf("--diagnose: build tls config: %v", terr)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		res := diagnose.Run(ctx, diagnose.Options{
			URL:       *urlFlag,
			Key:       resolvedKey,
			TLSConfig: tlsCfg,
			Insecure:  allowWS,
			Out:       os.Stdout,
		})
		if !res.Healthy {
			os.Exit(1)
		}
		return
	}

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

	auditLog, err := audit.Open(audit.Options{
		Path:           *auditLogPath,
		IncludeCommand: *auditIncludeCmd,
		ChainKeyPath:   *auditChainKey,
	})
	if err != nil {
		log.Fatalf("Failed to open audit log: %v", err)
	}
	defer auditLog.Close()
	if *auditLogPath != "" {
		// Operator-supplied path (--audit-log flag); %q neutralises any
		// embedded newline/tab. gosec G706 flags this as taint, but the
		// "attacker" here is whoever already configured the agent's CLI.
		// #nosec G706 -- operator input, not network input.
		log.Printf("Audit log enabled at %q (include_command=%v, chain=%v)",
			*auditLogPath, *auditIncludeCmd, *auditChainKey != "")
	}

	// Create session manager and WebSocket client.
	signingPubkey, err := session.LoadSigningKey(*signingPubkeyFile)
	if err != nil {
		log.Fatalf("Failed to load --signing-pubkey-file: %v", err)
	}
	if *requireSignature && signingPubkey == nil {
		log.Fatalf("--require-message-signature set but --signing-pubkey-file is empty")
	}
	if signingPubkey != nil {
		log.Printf("Per-message signing enabled (require=%v)", *requireSignature)
	}

	mgr := session.NewManager(session.Config{
		ScriptsDir:       scriptsDir,
		ReplayDir:        cfg.StateDir,
		MaxExec:          *maxExec,
		MaxPty:           *maxPty,
		AllowElevation:   *allowElevation,
		Audit:            auditLog,
		SigningPubkey:    signingPubkey,
		RequireSignature: *requireSignature,
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
