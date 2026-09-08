# arktis-agent: instructions for Codex

<!-- orch:begin -->
<!-- rendered by orch from projects/arktis-agent.yaml (render abf844c533f2); do not edit inside the markers, change the manifest and re-run orch render -->
## How work moves in arktis-agent

Another agent session is always already running in this repository. The full doctrine is in the `core:*` skills; this is the part every session holds from the first prompt.

### Non-negotiables
1. The primary checkout stays on `main` and is read-only. Feature work happens in `../arktis-agent-worktrees/<slug>/` (`/core:session-worktree`). One branch, one worktree.
2. Start every session at the root of the checkout or worktree. Project plugins, their hooks and this repository's gates load from `.claude/` there; a session started in a subdirectory gets this text and nothing else (probed 2026-09-07).
3. `git stash` is repo-global: never `pop` or `apply` without an explicit ref.
4. No direct push, force-push or history rewrite on `main`. Changes arrive as pull requests from branches matching `^(feature|fix|chore)/`.
5. No merge without a fresh review panel on the current head: `/core:review-local`, then `/core:s`, which merges with `--match-head-commit`. Required lenses: correctness, security.
6. Every issue carries exactly one `type:`, at least one `area:` from {executor, connection, protocol, terminal, audit, config, diagnose, logging, ci, docs}, and `severity:` when it is a bug (`/core:bug`, `/core:feature`).
7. "Should work" is not evidence. Read the diff, run the test, view the result (`core:verification`).
8. Found an unrelated bug while working? File it; do not bundle the fix.

### Branches and deploys
- Integration branch `main`; no DEV environment; no PROD workflow is declared.
- Merge flags: `--merge`; conflicts by `merge`; commits are free-form.

### Commands (always the namespaced form)
| Command | Does |
|---|---|
| `/core:s` | session status; merges a session-owned PR when the gate says mergeable |
| `/core:session-worktree <slug>` | an isolated worktree for this branch |
| `/core:create-pr` | commit, push, review locally, open the PR, hand CI to core:ci-watcher |
| `/core:review-local` | both review lenses on the merge-base diff; posts the markers |
| `/core:quick-commit` | stage, conventional message, commit, push |
| `/core:bug · /core:feature` | file an issue with the closed label taxonomy |
| `/core:clearlocal` | remove merged worktrees and branches, never with -D |
| `/core:pick_feature` | fleet driver: claim an issue and run it to a merged PR |
| `/core:update-docs` | sync the repo's documentation sources |

### Overrides
Operator only, as the environment or as a prefix of the statement that carries the gated command; refused for subagents; `0`/`false` do not count: `ORCH_SKIP_REVIEW`, `ORCH_ALLOW_PUSH`, `ORCH_ALLOW_FORCE_PUSH`, `ORCH_ALLOW_PRIMARY_EDIT`, `ORCH_SKIP_ISSUE_LABELS`, `ORCH_ALLOW_NO_BUN`. The production-deploy guard has none.

### Project doctrine
This repository ships one Go binary (`cmd/arktis-agent`) with no runtime
dependencies on the target host. `go build ./...`, `go vet ./...` and
`go test ./...` must pass before a pull request; ci.yml runs the same. A
release is a `v*` tag pushed by the operator, never by a session; sessions
do not create or push tags. Nothing here deploys to a live system.

### Codex setup (once per machine)
```bash
codex plugin marketplace add bisskar/ai_orchestrator
codex plugin add core@orch
```
Codex loads every enabled plugin in every repository and runs plugin hooks only after hook trust is granted in the TUI; the ORCH_* values a hook needs come from `.claude/orch.json` here (`orch codex-sync` writes the machine-local config; `orch doctor` checks it).
<!-- orch:end -->
