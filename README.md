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

Every release ships with a `sha256sums.txt` checksum manifest and a
keyless [cosign](https://docs.sigstore.dev/cosign/overview/) signature
bundle. Verify before running.

**Linux:**

```bash
RELEASE_URL=https://github.com/bisskar/arktis-agent/releases/latest/download

# 1. Download the binary, the checksum manifest, and its signature bundle.
curl -sSL "${RELEASE_URL}/arktis-agent-linux-amd64"          -o arktis-agent
curl -sSL "${RELEASE_URL}/sha256sums.txt"                    -o sha256sums.txt
curl -sSL "${RELEASE_URL}/sha256sums.txt.cosign.bundle"      -o sha256sums.txt.cosign.bundle

# 2. Verify the checksum manifest's signature against the GitHub-issued
#    OIDC identity. Adjust the regex if you fork the repo.
cosign verify-blob \
  --bundle sha256sums.txt.cosign.bundle \
  --certificate-identity-regexp '^https://github.com/bisskar/arktis-agent/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  sha256sums.txt

# 3. Verify the binary against the signed manifest, then install.
sha256sum -c --ignore-missing sha256sums.txt
sudo install -m 0755 arktis-agent /usr/local/bin/arktis-agent

arktis-agent --url wss://your-server.com/api/v1/agent/ws --key <YOUR_KEY>
```

**Windows (PowerShell):**

```powershell
$ReleaseUrl = "https://github.com/bisskar/arktis-agent/releases/latest/download"
Invoke-WebRequest -Uri "$ReleaseUrl/arktis-agent-windows-amd64.exe"             -OutFile "arktis-agent.exe"
Invoke-WebRequest -Uri "$ReleaseUrl/sha256sums.txt"                             -OutFile "sha256sums.txt"
Invoke-WebRequest -Uri "$ReleaseUrl/sha256sums.txt.cosign.bundle"               -OutFile "sha256sums.txt.cosign.bundle"

# Verify checksum-manifest signature (requires cosign in PATH).
cosign verify-blob `
  --bundle sha256sums.txt.cosign.bundle `
  --certificate-identity-regexp '^https://github.com/bisskar/arktis-agent/' `
  --certificate-oidc-issuer https://token.actions.githubusercontent.com `
  sha256sums.txt

# Verify the binary against the manifest.
$expected = (Select-String -Path sha256sums.txt -Pattern 'arktis-agent-windows-amd64.exe').Line.Split(' ')[0]
$actual   = (Get-FileHash arktis-agent.exe -Algorithm SHA256).Hash.ToLower()
if ($expected -ne $actual) { throw "checksum mismatch" }

Move-Item -Force arktis-agent.exe "$env:ProgramFiles\arktis-agent.exe"
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

## Release Process

There are two workflows in `.github/workflows/`:

| Workflow | Trigger | What it does |
|----------|---------|--------------|
| `ci.yml` | Every PR and every push to `main` | Lint, vet, test — **no binaries built, no release created** |
| `release.yml` | Only when a `v*` git tag is pushed | Builds binaries for all platforms and publishes a GitHub Release |

**Important:** merging a PR to `main` does NOT create a release. A PR merge only runs CI. You must push a version tag separately to publish binaries.

### Cutting a new release

```bash
# 1. Make sure main is green and you're on the commit you want to release
git checkout main && git pull

# 2. Tag it (use semver: MAJOR.MINOR.PATCH)
git tag v0.2.0

# 3. Push the tag — this triggers release.yml
git push origin v0.2.0
```

Within ~2 minutes the release appears at `https://github.com/bisskar/arktis-agent/releases/latest` with three assets attached:

- `arktis-agent-linux-amd64`
- `arktis-agent-linux-arm64`
- `arktis-agent-windows-amd64.exe`

The install commands in the Quick Start section above always pull `/releases/latest/download/...` so they automatically use the newest tagged version.

### If a release fails

Fix the issue on `main` (a new commit), then move the tag:

```bash
git tag -d v0.2.0                      # delete local
git push origin --delete v0.2.0        # delete remote
git tag v0.2.0 <new-commit-sha>        # retag on fixed commit
git push origin v0.2.0                 # re-trigger release.yml
```

## License

Private. Part of the Arktis platform.
