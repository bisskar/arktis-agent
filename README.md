# Arktis Agent

Lightweight reverse-connection agent for [Arktis](https://github.com/bisskar/arktis). Connects lab hosts back to the Arktis backend via WebSocket for remote Atomic Red Team test execution, interactive terminal sessions, and AI-powered analysis.

Single binary. Zero dependencies on target.

## How It Works

```
Traditional:  Backend --SSH--> Lab Host    (requires inbound firewall rules)
Arktis Agent: Backend <--WS-- Agent        (outbound only, NAT-friendly)
```

The agent runs on your lab hosts (Windows or Linux) and maintains a persistent WebSocket connection to the Arktis backend. The backend sends commands through this connection — no inbound ports, no SSH keys, no firewall rules needed on the target.

## Quick Start

### 1. Generate a Registration Key

In Arktis, go to **Org Settings > Lab Hosts > Registration Keys** and click **Generate Key**. Select the workspace to scope the key to (or leave blank for org-wide).

### 2. Install the Agent

**Linux:**

```bash
curl -sSL https://github.com/bisskar/arktis-agent/releases/latest/download/arktis-agent-linux-amd64 \
  -o /usr/local/bin/arktis-agent && chmod +x /usr/local/bin/arktis-agent

arktis-agent --url wss://your-server.com/api/v1/agent/ws --key <YOUR_KEY>
```

**Windows (PowerShell):**

```powershell
Invoke-WebRequest -Uri "https://github.com/bisskar/arktis-agent/releases/latest/download/arktis-agent-windows-amd64.exe" `
  -OutFile "$env:ProgramFiles\arktis-agent.exe"

& "$env:ProgramFiles\arktis-agent.exe" --url wss://your-server.com/api/v1/agent/ws --key <YOUR_KEY>
```

The agent self-registers on first connect. It will appear in your Lab Hosts list within seconds.

### 3. Run as a Service (Optional)

**Linux (systemd):**

```bash
sudo tee /etc/systemd/system/arktis-agent.service > /dev/null <<EOF
[Unit]
Description=Arktis Agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/arktis-agent --url wss://your-server.com/api/v1/agent/ws --key <YOUR_KEY>
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now arktis-agent
```

**Windows (as a scheduled task):**

```powershell
$action = New-ScheduledTaskAction -Execute "$env:ProgramFiles\arktis-agent.exe" `
  -Argument "--url wss://your-server.com/api/v1/agent/ws --key <YOUR_KEY>"
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Seconds 30)
Register-ScheduledTask -TaskName "ArktisAgent" -Action $action -Trigger $trigger `
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
│  Lab Host    │ ──────────────────────────>  │  Arktis Backend  │
│              │                              │                  │
│  arktis-     │  <── exec commands           │                  │
│  agent       │  ──> exec results            │  AgentConnection │
│              │  <── pty_open/input/resize   │  Manager         │
│              │  ──> pty_output              │                  │
│              │  <── heartbeat_ack           │                  │
│              │  ──> heartbeat (15s)         │                  │
└──────────────┘                              └──────────────────┘
```

## Configuration

| Flag | Environment Variable | Default | Description |
|------|---------------------|---------|-------------|
| `--url` | `ARKTIS_URL` | (required) | Backend WebSocket URL |
| `--key` | `ARKTIS_KEY` | (required) | Registration key from Arktis |
| `--state-dir` | `ARKTIS_STATE_DIR` | `/etc/arktis-agent` (Linux) or `%ProgramData%\arktis-agent` (Windows) | Directory for persistent state |
| `--version` | — | — | Print version and exit |

## Security

- **Outbound only** — the agent initiates the connection. No inbound ports needed on the target host.
- **Key-based authentication** — agents authenticate with a registration key (SHA-256 hashed server-side, never stored in plaintext).
- **Key revocation** — revoking a key in Arktis immediately disconnects all agents using it.
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
go run ./cmd/arktis-agent --url ws://localhost:8000/api/v1/agent/ws --key <KEY>

# Run tests
make test
```

## License

Private. Part of the Arktis platform.
