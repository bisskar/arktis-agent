package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/bisskar/sentinel-agent/internal/config"
	"github.com/bisskar/sentinel-agent/internal/connection"
	"github.com/bisskar/sentinel-agent/internal/session"
)

// Version is set via ldflags at build time.
var Version = "dev"

func defaultStateDir() string {
	if runtime.GOOS == "windows" {
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		return pd + `\sentinel-agent`
	}
	return "/etc/sentinel-agent"
}

func main() {
	url := flag.String("url", "", "Backend WebSocket URL (required)")
	key := flag.String("key", "", "Registration key (required)")
	stateDir := flag.String("state-dir", defaultStateDir(), "Directory for persistent state")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("sentinel-agent %s\n", Version)
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

	// Load or create persistent state.
	state, err := config.LoadState(cfg.StateDir)
	if err != nil {
		log.Printf("No existing state found, starting fresh: %v", err)
		state = &config.State{}
	}

	log.Printf("sentinel-agent %s starting (state-dir=%s)", Version, cfg.StateDir)

	// Inject version into the connection package for registration messages.
	connection.SetVersion(Version)

	// Create session manager and WebSocket client.
	mgr := session.NewManager()
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
	}()

	if err := client.Run(ctx); err != nil {
		log.Fatalf("Agent exited with error: %v", err)
	}

	log.Println("sentinel-agent stopped")
}
