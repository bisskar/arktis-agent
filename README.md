# Sentinel Agent

Lightweight reverse-connection agent for [Sentinel Review](https://github.com/bisskar/app-sentinel-review). Connects lab hosts back to the Sentinel Review backend via WebSocket for remote Atomic Red Team test execution, interactive terminal sessions, and AI-powered analysis.

Single binary. Zero dependencies on target.

## How It Works

```
Traditional:  Backend --SSH--> Lab Host    (requires inbound firewall rules)
Sentinel Agent:  Backend <--WS-- Agent    (outbound only, NAT-friendly)
```

The agent runs on your lab hosts (Windows or Linux) and maintains a persistent WebSocket connection to the Sentinel Review backend. The backend sends commands through this connection — no inbound ports, no SSH keys, no firewall rules needed on the target.

## Quick Start

### 1. Generate a Registration Key

In Sentinel Review, go to **Org Settings > Lab Hosts > Registration Keys** and click **Generate Key**. Select the workspace to scope the key to (or leave blank for org-wide).

### 2. Install the Agent

**Linux:**

```bash
curl -sSL https://github.com/bisskar/sentinel-agent/releases/latest/download/sentinel-agent-linux-amd64 \
  -o /usr/local/bin/sentinel-agent && chmod +x /usr/local/bin/sentinel-agent

sentinel-agent --url wss://your-server.com/api/v1/agent/ws --key <YOUR_KEY>
```

**Windows (PowerShell):**

```powershell
Invoke-WebRequest -Uri "https://github.com/bisskar/sentinel-agent/releases/latest/download/sentinel-agent-windows-amd64.exe" `
  -OutFile "$env:ProgramFiles\sentinel-agent.exe"

& "$env:ProgramFiles\sentinel-agent.exe" --url wss://your-server.com/api/v1/agent/ws --key <YOUR_KEY>
```

The agent self-registers on first connect. It will appear in your Lab Hosts list within seconds.

### 3. Run as a Service (Optional)

**Linux (systemd):**

```bash
sudo tee /etc/systemd/system/sentinel-agent.service > /dev/null <<EOF
[Unit]
Description=Sentinel Agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/sentinel-agent --url wss://your-server.com/api/v1/agent/ws --key <YOUR_KEY>
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now sentinel-agent
```

**Windows (as a scheduled task):**

```powershell
$action = New-ScheduledTaskAction -Execute "$env:ProgramFiles\sentinel-agent.exe" `
  -Argument "--url wss://your-server.com/api/v1/agent/ws --key <YOUR_KEY>"
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Seconds 30)
Register-ScheduledTask -TaskName "SentinelAgent" -Action $action -Trigger $trigger `
  -Settings $settings -User "SYSTEM" -RunLevel Highest
```

## Features

| Feature | Description |
|---------|-------------|
| **Atomic Test Execution** | Run Atomic Red Team tests with full prerequisite, execution, and cleanup phases |
| **Interactive Terminal** | Full PTY terminal sessions via xterm.js in the browser |
| **Ad-hoc Commands** | Execute one-off commands from AI analysis suggestions |
| **Auto-reconnection** | Exponential backoff (1s to 60s) on disconnect |
| **Self-registration** | No manual host setup — agent registers itself on first connect |
| **Multi-shell** | PowerShell, cmd.exe, bash, sh with proper command wrapping |
| **OS Detection** | Automatic platform and OS family identification |

## Architecture

```
┌──────────────┐     WebSocket (outbound)     ┌──────────────────┐
│  Lab Host    │ ──────────────────────────>   │  Sentinel Review │
│              │                               │  Backend         │
│  sentinel-   │  <── exec commands            │                  │
│  agent       │  ──> exec results             │  AgentConnection │
│              │  <── pty_open/input/resize     │  Manager         │
│              │  ──> pty_output                │                  │
│              │  <── heartbeat_ack             │                  │
│              │  ──> heartbeat (15s)           │                  │
└──────────────┘                               └──────────────────┘
```

## Configuration

| Flag | Environment Variable | Default | Description |
|------|---------------------|---------|-------------|
| `--url` | `SENTINEL_URL` | (required) | Backend WebSocket URL |
| `--key` | `SENTINEL_KEY` | (required) | Registration key from Sentinel Review |
| `--state-dir` | `SENTINEL_STATE_DIR` | `/etc/sentinel-agent` (Linux) or `%ProgramData%\sentinel-agent` (Windows) | Directory for persistent state |
| `--version` | — | — | Print version and exit |

## Security

- **Outbound only** — the agent initiates the connection. No inbound ports needed on the target host.
- **Key-based authentication** — agents authenticate with a registration key (SHA-256 hashed server-side, never stored in plaintext).
- **Key revocation** — revoking a key in Sentinel Review immediately disconnects all agents using it.
- **Per-agent revocation** — individual hosts can be deactivated without affecting other agents on the same key.
- **TLS transport** — use `wss://` in production for encrypted communication.
- **Org/workspace scoping** — each key is bound to one organization and optionally one workspace. Agents cannot execute commands for other tenants.

## Building from Source

Requires Go 1.22+.

```bash
# All platforms
make build-all

# Single platform
make build-linux-amd64
make build-linux-arm64
make build-windows-amd64

# Output in dist/
ls dist/
```

## Development

```bash
# Run locally
go run ./cmd/sentinel-agent --url ws://localhost:8000/api/v1/agent/ws --key <KEY>

# Run tests
make test
```

## License

Private. Part of the Sentinel Review platform.
