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

The agent does **not** need root / SYSTEM to run non-elevated tests. The
recommended setup runs the agent as a dedicated low-privilege user and
opts elevation in only when you actually need atomics that ship
`elevation_required=true`.

**Linux (systemd, least privilege — recommended):**

```bash
# 1. Create a dedicated user + state directory.
sudo useradd --system --home-dir /var/lib/arktis-agent --shell /usr/sbin/nologin arktis
sudo install -d -o arktis -g arktis -m 0700 /var/lib/arktis-agent

# 2. Install the verified binary as root, run as `arktis`.
sudo install -o root -g root -m 0755 arktis-agent /usr/local/bin/arktis-agent

sudo tee /etc/systemd/system/arktis-agent.service > /dev/null <<'EOF'
[Unit]
Description=Arktis Agent
After=network-online.target
Wants=network-online.target

[Service]
User=arktis
Group=arktis
ExecStart=/usr/local/bin/arktis-agent \
  --url wss://your-server.com/api/v1/agent/ws \
  --key <YOUR_KEY> \
  --state-dir /var/lib/arktis-agent \
  --require-non-root \
  --audit-log /var/lib/arktis-agent/audit.log
Restart=always
RestartSec=5

# Standard hardening — fail closed on anything the agent doesn't need.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/arktis-agent

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now arktis-agent
```

`--require-non-root` makes the agent fail fast if it ever finds itself
running as `euid=0`, so a misconfigured unit can't quietly grant the
backend root.

**Linux ("Lab mode" — when you need elevation):**

If your atomics include tests that require `sudo` (e.g. process
injection, kernel-module load), pass `--allow-elevation` and grant the
`arktis` user a *minimal* sudoers entry scoped to the agent's staged
scripts under `/var/lib/arktis-agent/scripts/`. Do not run the agent
itself as root.

```sudoers
# /etc/sudoers.d/arktis
arktis ALL=(root) NOPASSWD: /bin/bash /var/lib/arktis-agent/scripts/arktis-*.sh, \
                              /bin/sh   /var/lib/arktis-agent/scripts/arktis-*.sh
Defaults!/bin/bash, /bin/sh env_reset
```

**Windows (managed service account — recommended):**

Create a low-privilege local account (or a domain-managed service
account / gMSA) and register the scheduled task under it instead of
SYSTEM. Grant the account write access to `%ProgramData%\arktis-agent`.

```powershell
# Replace with your account; use a gMSA in domain environments.
$cred  = Get-Credential -UserName ".\arktis-svc" -Message "Service account password"

$action   = New-ScheduledTaskAction -Execute "$env:ProgramFiles\arktis-agent.exe" `
  -Argument "--url wss://your-server.com/api/v1/agent/ws --key <YOUR_KEY> --require-non-root"
$trigger  = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Seconds 30)

Register-ScheduledTask -TaskName "ArktisAgent" `
  -Action $action -Trigger $trigger -Settings $settings `
  -User $cred.UserName -Password $cred.GetNetworkCredential().Password
```

**Windows ("Lab mode"):** if you genuinely need SYSTEM (atomics that
exercise kernel APIs), use `-User "SYSTEM" -RunLevel Highest` and
`--allow-elevation` — but treat that host as fully owned by the
backend.

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
| `--require-non-root` | `ARKTIS_REQUIRE_NON_ROOT` | `false` | Refuse to start if running as root (Linux euid=0). Recommended for production. |
| `--allow-elevation` | `ARKTIS_ALLOW_ELEVATION` | `false` | Honour `elevation_required=true` exec messages (otherwise: refuse with `exit_code=126`). |
| `--max-exec-concurrency` | `ARKTIS_MAX_EXEC` | `8` | Max simultaneous in-flight exec commands. |
| `--max-pty-sessions` | `ARKTIS_MAX_PTY` | `4` | Max simultaneous PTY sessions. |
| `--audit-log` | `ARKTIS_AUDIT_LOG` | `` | Path to a JSON-line audit log of every exec/pty event. Empty disables auditing. |
| `--audit-log-include-command` | `ARKTIS_AUDIT_LOG_INCLUDE_COMMAND` | `false` | Include the full command body in audit records (default logs only a SHA-256 + byte count). |
| `--ca-cert` | `ARKTIS_CA_CERT` | (system) | Path to a PEM file used as the **only** trusted root for the backend's TLS cert. Defence-in-depth against system-CA compromise. |
| `--pin-spki` | `ARKTIS_PIN_SPKI` | `` | Hex-encoded SHA-256 of the backend's SubjectPublicKeyInfo. The dial fails if the leaf cert's SPKI hash does not match. |
| `--strict-endpoint` | `ARKTIS_STRICT_ENDPOINT` | `false` | After a successful first connect, refuse to reconnect if the backend's resolved IP changes (DNS-rebinding mitigation). |
| `--version` | — | — | Print version and exit |

## Security Model

The agent is a **remote command executor**: whoever controls the
backend can run arbitrary commands on every connected host with the
agent's process privileges. The trust assumptions, in order of
strength:

1. **Backend → agent**: trusted by design. Anything the backend sends
   (an `exec` with arbitrary `command`, a `pty_open`) will run.
2. **Agent → host**: the agent only has the privileges of the user it
   runs as. **Run as a dedicated low-privilege user.** Root / SYSTEM
   should be reserved for atomics that genuinely need it (see
   "Lab mode" above).
3. **Backend identity**: verified via system-CA TLS (`wss://`) and the
   bearer key. Cert-pinning / message-signing is on the roadmap (#9).

### What runs as root vs. the agent user

| Path | Runs as |
|------|---------|
| Default `exec` (`elevation_required=false`) | The agent's own user |
| `exec` with `elevation_required=true` and `--allow-elevation` set | `sudo` (Linux) / inherited token (Windows) |
| Interactive PTY (`pty_open`) | The agent's own user |

If the agent is **not** started with `--allow-elevation`, any
`elevation_required=true` message is rejected with `exit_code=126`.

### Hardening checklist for production deployments

- [ ] Run as a dedicated user (`arktis` on Linux, `arktis-svc` or a
      gMSA on Windows). Use `--require-non-root` to fail closed.
- [ ] Verify release artifacts (`cosign verify-blob` against the
      published signature bundle) before installing.
- [ ] Use `wss://` for the backend URL, not `ws://`.
- [ ] Enable the audit log (`--audit-log /var/lib/arktis-agent/audit.log`)
      and ship it to a central SIEM.
- [ ] Set `--max-exec-concurrency` and `--max-pty-sessions` consistent
      with the host's capacity.
- [ ] Apply the sudoers fragment above instead of granting blanket
      `NOPASSWD: ALL` if you need elevation.
- [ ] Rotate the registration key on operator off-boarding.

### Built-in defences

- **Outbound only** — the agent initiates the connection. No inbound
  ports needed on the target host.
- **Key-based authentication** — agents authenticate with a
  registration key (SHA-256 hashed server-side, never stored in
  plaintext).
- **Key revocation** — revoking a key in Arktis immediately
  disconnects all agents using it.
- **Per-agent revocation** — individual hosts can be deactivated
  without affecting other agents on the same key.
- **TLS transport** — use `wss://` in production for encrypted
  communication.
- **Org/workspace scoping** — each key is bound to one organization
  and optionally one workspace. Agents cannot execute commands for
  other tenants.
- **Capacity caps** — `--max-exec-concurrency` and
  `--max-pty-sessions` (defaults 8 and 4) bound the resources a
  misbehaving / compromised backend can consume.
- **Stripped child env** — spawned shells receive a minimal
  whitelisted env; `ARKTIS_KEY`, `AWS_*`, `LD_PRELOAD`, etc. are
  never inherited.
- **Sanitised result fields** — `stdout_safe` / `stderr_safe`
  carry an escape-stripped variant of process output for
  log/SIEM ingestion that is sensitive to control bytes.

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
