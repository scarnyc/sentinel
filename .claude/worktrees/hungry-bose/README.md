# OpenClaw + Sentinel Setup Guide

## Overview

This guide covers deploying OpenClaw with Sentinel's security pipeline. After setup, all OpenClaw tool calls are classified, rate-limited, and filtered through Sentinel's executor before execution.

**Audience**: Ops engineers and developers deploying Sentinel + OpenClaw.

## Architecture

```
┌─────────────────────────────┐
│  OpenClaw Gateway (host)    │
│  ├── Sentinel Plugin        │
│  │   ├── before_tool_call   │──── POST /classify ────┐
│  │   ├── after_tool_call    │                         │
│  │   └── sanitize_output    │                         │
│  └── LLM calls via proxy    │                         ▼
│       (baseUrl override)    │          ┌──────────────────────┐
└─────────────────────────────┘          │  Executor (:3141)    │
                                         │  (Docker container)  │
┌─────────────────────────────┐          │                      │
│  Agent (Docker, internal)   │──HTTP──▶│  /classify           │
│  NO internet access         │          │  /filter-output      │
│  LLM via /proxy/llm/*      │          │  /execute            │
└─────────────────────────────┘          │  /proxy/llm/*        │
                                         │  /pending-delegations│
┌─────────────────────────────┐          │                      │
│  Confirmation TUI (host)    │◀────────│  Confirmation flow   │
└─────────────────────────────┘          └──────────────────────┘
                                                    │
                                         ┌──────────▼───────────┐
                                         │  LLM APIs            │
                                         │  (Anthropic, OpenAI, │
                                         │   Gemini)            │
                                         └──────────────────────┘
```

## Prerequisites

### Hardware
- 4GB RAM minimum (8GB recommended)
- 2+ CPU cores

### Software
- Docker 24+ with Compose v2
- Node.js 22+
- pnpm 9+
- git 2.40+

### Credentials
- Anthropic API key (`sk-ant-*`)
- OpenAI API key (optional)
- Gemini API key (optional)
- Google OAuth credentials (for Google Workspace tools)

## Quick Start

```bash
# 1. Clone and install
git clone https://github.com/openclaw/secure-openclaw.git
cd secure-openclaw
pnpm install

# 2. Initialize Sentinel (creates vault, stores API keys)
sentinel init

# 3. Configure OpenClaw integration
sentinel setup openclaw

# 4. Build containers
docker compose build

# 5. Start executor
docker compose up executor -d

# 6. Verify health
curl http://localhost:3141/health

# 7. Start OpenClaw gateway
openclaw gateway --port 18789

# 8. Verify plugin loaded (check logs)
docker compose logs executor --tail=20
```

## Detailed Setup

### 5.1 Sentinel Init

First-time setup creates the credential vault and stores API keys:

```bash
sentinel init
```

This prompts for:
1. Master password (encrypts the vault)
2. API keys (Anthropic, OpenAI, Gemini)
3. Security level configuration

Vault is stored at `data/vault.enc` (AES-256-GCM encrypted).

### 5.2 OpenClaw Gateway

Install OpenClaw if not already present:

```bash
npm install -g openclaw
openclaw init
```

The gateway is the process that runs OpenClaw agents and connects to Sentinel's executor.

### 5.3 Sentinel Plugin

The `sentinel setup openclaw` command:
1. Patches `~/.openclaw/openclaw.json` with LLM proxy URLs
2. Installs the Sentinel plugin to `~/.openclaw/extensions/sentinel/`
3. Generates `SOUL.md` with safety boundaries and tier constraints
4. Updates `data/sentinel.json` with OpenClaw integration config

To verify plugin installation:
```bash
ls ~/.openclaw/extensions/sentinel/
cat ~/.openclaw/SOUL.md
```

### 5.4 Docker Compose

Build and start containers:

```bash
# Build all images
docker compose build

# Start executor only (recommended for development)
docker compose up executor -d

# Start both executor + agent
docker compose up -d

# Verify containers are healthy
docker compose ps
```

Container hardening (applied automatically):
- `read_only: true` — immutable filesystem
- `cap_drop: ALL` — no Linux capabilities
- `no-new-privileges` — prevent privilege escalation
- Resource limits: 512MB RAM, 1 CPU, 256 PIDs (executor)

### 5.5 LLM Proxy Configuration

OpenClaw agents use Sentinel's LLM proxy instead of direct API calls. The `sentinel setup openclaw` command patches `openclaw.json` with:

```json
{
  "llm": {
    "baseUrls": {
      "anthropic": "http://localhost:3141/proxy/llm/anthropic",
      "openai": "http://localhost:3141/proxy/llm/openai",
      "gemini": "http://localhost:3141/proxy/llm/gemini"
    }
  }
}
```

The executor injects API keys from the vault at proxy time — agents never hold credentials.

### 5.6 Credential Vault

Store credentials securely:

```bash
# Add API keys
sentinel vault add ANTHROPIC_API_KEY
sentinel vault add OPENAI_API_KEY
sentinel vault add GEMINI_API_KEY

# List stored credentials
sentinel vault list

# Verify vault integrity
sentinel vault verify
```

Credentials are AES-256-GCM encrypted at rest and decrypted only at execution time via `useCredential()` callback pattern.

### 5.7 delegate.code

The `delegate.code` tool spawns isolated Claude Code sessions for coding tasks:

```
Tool: delegate.code
Params:
  task: "Implement feature X"
  worktreeName: "feature-x"    (optional)
  allowedTools: ["Read", "Write", "Edit", "Bash", "Glob", "Grep"]
  maxBudgetUsd: 5
  timeoutSeconds: 900
```

Delegation flow:
1. Agent sends `delegate.code` tool call
2. Executor classifies as `dangerous` → requires confirmation
3. User approves via TUI
4. Task queued in delegation_queue (SQLite)
5. CLI delegation poller spawns Claude Code with `--worktree`
6. Heartbeat monitor checks process health every 5 minutes
7. Result (PR URL or error) posted back to executor

### 5.8 Heartbeat Monitoring

The heartbeat monitor checks active delegations:

```bash
# Start heartbeat (runs in background with delegation poller)
sentinel delegate --watch
```

Configuration in `data/sentinel.json`:
```json
{
  "delegation": {
    "heartbeatIntervalMs": 300000,
    "maxConcurrentDelegations": 3
  }
}
```

### 5.9 SOUL.md Authoring

SOUL.md defines agent safety boundaries. Generated by `sentinel setup openclaw` with tier-specific constraints.

Three sensitivity tiers:
- **Normal**: Standard confirmation model, 60 req/min
- **High**: All ops require confirmation, 30 req/min, no delegation
- **Critical**: Maximum restrictions, 10 req/min, no delegation, no network egress

Edit `~/.openclaw/SOUL.md` to customize constraints.

### 5.10 Per-Agent Scoping

Restrict agents to specific tools and paths:

```json
{
  "gwsAgentScopes": {
    "agent-reader": {
      "allowedServices": ["gmail", "calendar"],
      "denyServices": ["drive"]
    }
  }
}
```

Path restrictions via `allowedRoots`:
```json
{
  "allowedRoots": ["/home/user/Code/project-a"]
}
```

### 5.11 Nightly Consolidation

Extract learnings from audit logs into memory store:

```bash
# Run manually
sentinel consolidate --hours 24

# Cron (every night at 2 AM)
0 2 * * * cd /path/to/secure-openclaw && sentinel consolidate --hours 24
```

## Configuration Reference

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SENTINEL_EXECUTOR_URL` | `http://localhost:3141` | Executor URL for plugin |
| `SENTINEL_AUTH_TOKEN` | — | Bearer token for executor auth |
| `SENTINEL_FAIL_MODE` | `closed` | `closed` (block on error) or `open` |
| `SENTINEL_DOCKER` | `false` | Enable Docker-mode restrictions |
| `SENTINEL_MODERATION_MODE` | `warn` (dev) / `enforce` (Docker) | Content moderation mode |
| `SENTINEL_BASH_SANDBOX` | — | `firejail` for Linux bash sandboxing |

### Config Files

| File | Purpose |
|------|---------|
| `data/sentinel.json` | Main Sentinel configuration |
| `data/vault.enc` | Encrypted credential vault |
| `data/audit.db` | Audit log (SQLite, Merkle-chained) |
| `~/.openclaw/openclaw.json` | OpenClaw configuration |
| `~/.openclaw/SOUL.md` | Agent safety boundaries |
| `~/.openclaw/extensions/sentinel/config.json` | Plugin configuration |

## Security Hardening Checklist

### Container
- [ ] `read_only: true` on all containers
- [ ] `cap_drop: ALL` with minimal `cap_add`
- [ ] `no-new-privileges: true`
- [ ] Resource limits (memory, CPU, PIDs)
- [ ] Agent on `internal: true` network only

### Credentials
- [ ] All API keys in encrypted vault (not env vars)
- [ ] Vault master password stored securely (not in shell history)
- [ ] `useCredential()` pattern for all vault access
- [ ] Credential filter active on all output paths

### Network
- [ ] Agent container cannot reach internet
- [ ] LLM calls routed through executor proxy
- [ ] SSRF guard blocks private IPs
- [ ] Docker DNS restriction on agent

### Policy
- [ ] Policy config frozen at startup (`Object.freeze`)
- [ ] Classification overrides reviewed
- [ ] Rate limits configured per-agent
- [ ] Loop guard thresholds set

### Monitoring
- [ ] Audit logging enabled
- [ ] Merkle chain verified periodically
- [ ] Health checks on executor
- [ ] Log rotation configured

### Host
- [ ] Confirmation TUI runs on host (trust anchor)
- [ ] Docker socket not exposed to containers
- [ ] Host firewall configured (see Appendix B)

## Verification

Post-deployment smoke tests:

```bash
# 1. Health check
curl http://localhost:3141/health
# Expected: {"status":"ok","version":"0.1.0"}

# 2. Test /classify
curl -X POST http://localhost:3141/classify \
  -H "Content-Type: application/json" \
  -d '{"tool":"read_file","params":{"path":"/tmp/test"},"agentId":"test","sessionId":"test"}'
# Expected: {"decision":"auto_approve","category":"read",...}

# 3. Test /filter-output
curl -X POST http://localhost:3141/filter-output \
  -H "Content-Type: application/json" \
  -d '{"output":"clean text","agentId":"test"}'
# Expected: {"filtered":"clean text","redacted":false,...}

# 4. Verify audit chain
sentinel audit 5

# 5. Docker container status
docker compose ps
```

## Monitoring & Maintenance

### Daily
- Check executor health: `curl http://localhost:3141/health`
- Review recent audit: `sentinel audit 20`

### Weekly
- Verify audit chain integrity: `sentinel audit --verify`
- Review blocked actions for policy tuning
- Check container resource usage: `docker stats`

### Monthly
- Rotate vault master password
- Update Docker images: `docker compose build --no-cache`
- Review and update SOUL.md constraints
- Archive old audit entries

### Backup Strategy
- `data/vault.enc` — encrypted, backup weekly
- `data/audit.db` — append-only, backup daily
- `~/.openclaw/openclaw.json` — backup after config changes

### Upgrade Procedure
```bash
git pull origin main
pnpm install
docker compose build
docker compose up -d
sentinel audit --verify  # verify chain integrity post-upgrade
```

## Troubleshooting

### Plugin not loading
- Check `~/.openclaw/extensions/sentinel/config.json` exists
- Verify `executorUrl` is reachable
- Check OpenClaw gateway logs for "Sentinel plugin" messages

### Classification returning wrong category
- Check `data/sentinel.json` classifications array
- Verify tool name matches classification entry
- Use `curl /classify` to test directly

### Executor unreachable
- Check Docker container: `docker compose ps`
- Check port binding: `docker compose port executor 3141`
- Check logs: `docker compose logs executor --tail=50`

### Credentials not injecting
- Verify vault has key: `sentinel vault list`
- Check vault password is correct
- Review executor logs for vault errors

### Rate limit errors
- Current default: 60 req/min per agent
- Adjust in `data/sentinel.json`: `rateLimiter.rate`
- Check which agent is hitting limits: `sentinel audit 50`

## Appendix A: CLI Reference

| Command | Description |
|---------|-------------|
| `sentinel init` | First-time setup |
| `sentinel setup openclaw` | Configure OpenClaw integration |
| `sentinel chat` | Interactive agent session |
| `sentinel vault list` | List stored credentials |
| `sentinel vault add <key>` | Add credential to vault |
| `sentinel audit [N]` | View recent audit entries |
| `sentinel config` | Show current configuration |

## Appendix B: Network Ports

| Port | Service | Direction | Notes |
|------|---------|-----------|-------|
| 3141 | Executor HTTP | Inbound | Bind to 127.0.0.1 only |
| 18789 | OpenClaw Gateway | Inbound | Default OpenClaw port |
| 443 | LLM APIs | Outbound | Anthropic, OpenAI, Gemini |
| — | Docker internal | Internal | Agent ↔ Executor only |

Firewall rule: only executor container should have outbound 443 access. Agent container uses Docker `internal: true` network (no internet).
