# Sentinel Pipeline State Machine

> **Snapshot**: Post-Memory Store + Rampart (PR #9, 542 tests) — Hybrid retrieval memory (`@sentinel/memory`), host-level Rampart firewall (45 standard + 3 project policies), all Phase 1 guards intact.
>
> **Master plan**: [`docs/plans/path-a-v2-adopt-openfang-primitives.md`](plans/path-a-v2-adopt-openfang-primitives.md) — full roadmap including Phase 2 (Google Workspace, OpenClaw agents, CopilotKit/ag-ui, Plano model routing) and outstanding security gaps.
>
> **Previous**: [`docs/pipeline-state-machine-phase-1.md`](pipeline-state-machine-phase-1.md) — Phase 1 pipeline (490 tests, no memory store, no Rampart).

```
              ┌──────────────────────────────────────────────────────┐
              │                 HOST BOUNDARY                        │
              │         Rampart Firewall (launchd daemon)            │
              │    45 standard + 3 Sentinel project policies         │
              │                                                      │
              │  PreToolUse hook on ALL Claude Code tool calls:      │
              │  ┌────────────────────────────────────────────────┐  │
              │  │  Bash, Read, Write, Edit, Glob, Grep, ...     │  │
              │  │                                                │  │
              │  │  ┌──────────┐  ┌──────────┐  ┌─────────────┐  │  │
              │  │  │ DENY     │  │ ASK      │  │ ALLOW       │  │  │
              │  │  │ vault.enc│  │ security │  │ source code │  │  │
              │  │  │ audit.db │  │ code     │  │ tests       │  │  │
              │  │  │ memory.db│  │ edits    │  │ docs        │  │  │
              │  │  │ *.tfstate│  │          │  │ config      │  │  │
              │  │  │ SSH keys │  │          │  │             │  │  │
              │  │  └──────────┘  └──────────┘  └─────────────┘  │  │
              │  └────────────────────────────────────────────────┘  │
              └──────────────────────┬──────────────────────────────┘
                                    │ tool call allowed
                          ┌─────────▼────────┐
                          │   USER INPUT     │
                          │  (terminal/TUI)  │
                          └────────┬─────────┘
                                   │
                          ┌────────▼─────────┐
                          │  AGENT PROCESS   │
                          │  (untrusted)     │
                          │                  │
                          │ ┌──────────────┐ │
                          │ │ Add to       │ │
                          │ │ Conversation │ │
                          │ │ Context      │ │
                          │ └──────┬───────┘ │
                          │        │         │
                          │ ┌──────▼───────┐ │
                          │ │ Call LLM     │ │◄─────────────────────────┐
                          │ │ (via proxy)  │ │                         │
                          │ └──────┬───────┘ │                         │
                          │        │         │                         │
                          │   ┌────▼────┐    │                         │
                          │   │ Text?   │    │                         │
                          │   └─┬────┬──┘    │                         │
                          │  yes│    │no     │                         │
                          │     │ ┌──▼─────┐ │                         │
                          │  display│Tool  │ │                         │
                          │  to  │ call?  │ │                         │
                          │  user└──┬─────┘ │                         │
                          │        yes      │                         │
                          │   ┌────▼──────┐ │    ┌──────────────────┐  │
                          │   │ Build     │ │    │ Add ToolResult   │  │
                          │   │ Action    ├─┼───►│ to context,      ├──┘
                          │   │ Manifest  │ │    │ loop again       │
                          │   └───────────┘ │    └──────────────────┘
                          └────────┼────────┘
                                   │ POST /execute
                    ═══════════════╪══════════════════
                     TRUST BOUNDARY (HTTP :3141)
                    ═══════════════╪══════════════════
                                   │
                          ┌────────▼─────────┐
                          │ EXECUTOR PROCESS │
                          │ (trusted)        │
                          └────────┬─────────┘
                                   │
    ┌──────────────────────────────▼──────────────────────────────┐
    │                     GUARD PIPELINE                          │
    │                     (fail-fast, sequential)                 │
    │                                                            │
    │  ┌─────────┐  ┌───────────┐  ┌──────────┐  ┌───────────┐  │
    │  │ 1.Validate│→│ 2.Rate    │→│ 3.Loop   │→│ 4.Policy  │  │
    │  │ Manifest │  │ Limiter   │  │ Guard    │  │ Classify  │  │
    │  │ (Zod)   │  │ (GCRA     │  │ (SHA-256 │  │ (bash     │  │
    │  │         │  │  per-agent)│  │  fingerp)│  │  parse +  │  │
    │  │ →400    │  │ →422+audit│  │ →422+aud │  │  config)  │  │
    │  └─────────┘  └───────────┘  └──────────┘  └─────┬─────┘  │
    │                                                   │        │
    │                                          ┌────────▼──────┐ │
    │                                          │ 5. DECISION   │ │
    │                                          │    ROUTING    │ │
    │                                          └──┬─────┬───┬──┘ │
    │                                  ┌──────────┘     │   └──────────┐
    │                                  │                │              │
    │                             ┌────▼───┐    ┌──────▼─────┐  ┌─────▼──────┐
    │                             │ BLOCK  │    │AUTO_APPROVE│  │ CONFIRM    │
    │                             │→error  │    │(read ops)  │  │(write/     │
    │                             │+audit  │    │            │  │ dangerous) │
    │                             └────────┘    └──────┬─────┘  └─────┬──────┘
    │                                                  │              │
    │                                                  │    ┌─────────▼────────┐
    │                                                  │    │ AWAITING         │
    │                                                  │    │ CONFIRMATION     │
    │                                                  │    │ (Promise blocks) │
    │                                                  │    └────┬────────┬────┘
    │                                                  │         │        │
    │                                                  │   ┌─────▼──┐ ┌───▼────┐
    │                                                  │   │APPROVED│ │DENIED  │
    │                                                  │   └─────┬──┘ │→error  │
    │                                                  │         │    │+audit  │
    │                                                  ├─────────┘    └────────┘
    │                                                  │
    │  ┌──────────┐  ┌─────────┐  ┌────────┐  ┌───────▼───┐  ┌──────────┐
    │  │10.Post-  │←│ 9.PII   │←│ 8.Cred │←│ 7.TOOL    │←│ 6.Pre-   │
    │  │execute   │  │ Scrub   │  │ Filter │  │ EXECUTE   │  │execute   │
    │  │moderation│  │         │  │        │  │           │  │moderation│
    │  └────┬─────┘  └─────────┘  └────────┘  └───────────┘  └──────────┘
    │       │                                                            │
    │  ┌────▼──────────────────────────────────────────────────────────┐ │
    │  │ 11. AUDIT LOG (Merkle-chained SHA-256, SQLite append-only)   │ │
    │  └────┬─────────────────────────────────────────────────────────┘ │
    └───────┼──────────────────────────────────────────────────────────┘
            │
    ┌───────▼────────┐
    │ 12. RETURN     │
    │ ToolResult     │──────────► back to Agent (loop continues)
    └────────────────┘


    ═══════════════════════════════════════════════════════════════
     PARALLEL SUBSYSTEM: MEMORY STORE (@sentinel/memory)
    ═══════════════════════════════════════════════════════════════

    Agent observe() / search() calls flow through the memory pipeline:

    ┌─────────────┐     ┌───────────┐     ┌────────────┐     ┌──────────┐
    │ Validate    │────►│ Scrub     │────►│ Dedup      │────►│ Quota    │
    │ (Zod schema)│     │ Creds+PII │     │ (SHA-256   │     │ (100MB   │
    │             │     │ from types│     │  30s window│     │  global) │
    │ →reject     │     │           │     │  →existing │     │ →reject  │
    └─────────────┘     │ →reject   │     │   ID)      │     └────┬─────┘
                        │  if only  │     └────────────┘          │
                        │  redacted │                       ┌─────▼──────┐
                        └───────────┘                       │ SQLite     │
                                                            │ INSERT     │
                              ┌──────────────────────┐      │ (WAL mode) │
                              │ Embed (optional)     │      └─────┬──────┘
                              │ bge-small-en-v1.5    │            │
                              │ 384-dim, local       │      ┌─────▼──────┐
                              │ →observations_vec    │◄─────┤ FTS5 index │
                              └──────────────────────┘      │ (Porter    │
                                                            │  stemming) │
                                                            └────────────┘

    Search: FTS5 keyword + sqlite-vec KNN → Reciprocal Rank Fusion → top N

    ┌───────────┐     ┌───────────┐     ┌──────────┐     ┌───────────┐
    │ Session   │────►│ Daily     │────►│ Prune    │────►│ Context   │
    │ Summary   │     │ Consolidate    │ (retain  │     │ Builder   │
    │ (per-     │     │ (merge+  │     │  only if │     │ (→system  │
    │  session) │     │  dedup)  │     │  in summ)│     │  prompt)  │
    └───────────┘     └───────────┘     └──────────┘     └───────────┘
```

---

## Three-Layer Security Model

The current architecture enforces security at three independent layers. Each layer operates without knowledge of the others — a compromise at one layer is contained by the remaining two.

```
┌──────────────────────────────────────────────────────────────────────┐
│ LAYER 1: RAMPART (Host Boundary)                                     │
│ What: YAML policy engine, launchd daemon, PreToolUse hook            │
│ Where: Intercepts ALL Claude Code tool calls BEFORE Docker           │
│ Scope: Host-wide — applies to Claude Code, OpenClaw, Cline, etc.    │
│ Audit: Separate hash-chained log (independent of Sentinel)           │
├──────────────────────────────────────────────────────────────────────┤
│ LAYER 2: SENTINEL EXECUTOR (Application Boundary)                    │
│ What: Guard pipeline, policy classifier, rate/loop guards            │
│ Where: HTTP :3141 inside Docker — agent → executor trust boundary    │
│ Scope: Per-agent, per-session — session-scoped isolation             │
│ Audit: Merkle-chained SQLite append-only log                         │
├──────────────────────────────────────────────────────────────────────┤
│ LAYER 3: SENTINEL OUTPUT FILTERS (Data Boundary)                     │
│ What: Credential filter, PII scrubber, content moderation            │
│ Where: Post-execution, before ToolResult returns to agent            │
│ Scope: Per-response — every tool output sanitized                    │
│ Audit: Part of Merkle audit log entry                                │
└──────────────────────────────────────────────────────────────────────┘
```

### What Rampart Provides On Top of Sentinel

Sentinel's executor guards operate **inside Docker** — they protect against a compromised or misbehaving agent process. Rampart operates **outside Docker at the host boundary** and addresses a different threat surface:

| Capability | Sentinel (App Layer) | Rampart (Host Layer) | Why Both Matter |
|------------|---------------------|---------------------|-----------------|
| **Scope** | Agent → executor HTTP boundary | ALL tool calls (Bash, Read, Write, Edit, Glob, Grep) | Rampart catches threats that never reach the executor |
| **Data file protection** | Path whitelist per-agent (`allowedRoots`) | Deny rules for `vault.enc`, `audit.db`, `memory.db`, `*.tfstate` | Rampart blocks direct file reads that bypass executor |
| **Security code gating** | N/A (executor doesn't gate its own source edits) | `ask` on 19 security-critical paths (crypto, policy, audit, guards, validator) | Prevents agent from weakening its own sandbox |
| **Self-modification** | N/A | Blocks `rampart allow`, `rampart setup`, `.rampart/` writes | Policy changes are human-only |
| **Credential files** | Credential filter regex on output | Deny on `.ssh/id_rsa`, `.env`, AWS/GCP creds, macOS Keychain | Rampart prevents the read; Sentinel scrubs if read succeeds |
| **Destructive commands** | Bash deny-list in executor tool handler | Deny on `rm -rf /`, `fdisk`, fork bombs, `halt`, `poweroff` | Rampart blocks before shell spawns; Sentinel blocks at tool handler |
| **Env injection** | N/A | Deny on `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `BASH_ENV` | Host-level process hijack prevention Sentinel can't detect |
| **Evasion** | N/A | Blocks backslash tricks (`\rm -rf /`), multi-agent bypass | Rampart's pattern engine catches shell-level evasions |
| **Hot-reload** | Requires restart (frozen config) | Edit `.rampart/policy.yaml` → instant enforcement | Operators can tighten policy without redeploying executor |
| **Multi-agent** | Per-agent via `agentId` in executor | Same policies for Claude Code, OpenClaw, Cline, etc. | Host-wide consistency across all AI tool callers |
| **Response scanning** | Credential filter + PII scrubber in executor | Response scanning (deny known patterns) | Redundant defense-in-depth for credential leakage |

**Key insight**: Rampart is the only layer that can prevent a tool call from ever executing. Sentinel's executor sees the request *after* the shell/filesystem operation is already permitted by the host. Rampart denies at the intent level — before bytes hit disk or network.

---

## Pipeline Phase Breakdown

### Phase 0: Rampart Host Firewall (New)

Before any tool call reaches Docker or the executor, the Rampart daemon (`/opt/homebrew/bin/rampart`) intercepts it via the Claude Code PreToolUse hook. The daemon evaluates the call against two policy layers:

1. **Standard policies** (45 rules) — SSH keys, AWS/GCP/Azure creds, env injection (`LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`), destructive commands (`rm -rf /`, fork bombs), macOS Keychain, browser data, exfiltration domains, backslash evasion, and self-modification protection.

2. **Sentinel project policies** (`.rampart/policy.yaml`, 3 rules):
   - `sentinel-block-tfstate` — denies read/exec on `*.tfstate` files
   - `sentinel-protect-data` — denies read/exec on `vault.enc`, `audit.db*`, `memory.db*`
   - `sentinel-protect-security-code` — requires user confirmation (`ask`) before write/edit on 19 security-critical source paths

Rampart returns `deny` (tool call blocked), `ask` (user must confirm in terminal), or `allow` (proceed). Denied calls never reach the executor. Rampart maintains its own hash-chained audit log independent of Sentinel's Merkle chain.

### Phase 1: User Input → Agent Context

The CLI (`packages/cli/src/commands/chat.ts`) orchestrates startup: unlocks the encrypted vault, starts the executor on `:3141`, spawns a confirmation poller (long-polls every 500ms), and launches the agent loop. User messages are added to `ConversationContext`, which auto-trims at ~100k tokens to stay within LLM limits.

If the memory store is configured, `buildSessionContext()` injects a "Yesterday's work" section into the system prompt with next steps from the most recent daily summary (~200 tokens budget).

### Phase 2: LLM Call (via Proxy)

The agent has **no internet access** (Docker `internal: true`). All LLM calls route through the executor's `/proxy/llm/*` endpoint, which:
- Validates the target host against an allowlist (Anthropic, OpenAI, Google)
- Runs the **SSRF guard** to block private IPs and cloud metadata endpoints
- Injects API keys from the executor's environment (the agent never sees them)

The LLM proxy is a key security primitive — it means the agent process literally cannot exfiltrate data to arbitrary URLs. Even if the LLM is prompt-injected into trying to call a malicious endpoint, the proxy's host allowlist blocks it.

### Phase 3: Action Manifest Construction

When the LLM decides to use a tool, the agent builds an **ActionManifest** — a typed JSON envelope with UUID, timestamp, tool name, parameters, sessionId, and agentId. This is the only way the agent can request side effects.

### Phase 4: Guard Pipeline (Steps 1-4)

The executor runs four sequential guards, failing fast on any block:

| Step | Guard | What it does |
|------|-------|-------------|
| 1 | **Manifest Validation** | Zod schema parse — rejects malformed requests (400) |
| 2 | **Rate Limiter** | GCRA algorithm, 60 req/min per agentId — prevents runaway agents |
| 3 | **Loop Guard** | SHA-256 fingerprints `(tool, params)` pairs — warn at 3, block at 5 in 60s window |
| 4 | **Policy Classifier** | Categorizes as `read`/`write`/`dangerous` via bash command parsing + config lookup |

### Phase 5: Decision Routing

The policy classification maps to one of three actions:

- **`block`** → immediate rejection + audit entry (e.g., `rm -rf /`)
- **`auto_approve`** → skip confirmation, proceed to execution (read-only ops when configured)
- **`confirm`** → enter the human-in-the-loop confirmation state

### Phase 6: Content Moderation (Pre-Execute)

If `SENTINEL_MODERATION_MODE=enforce`, the scanner checks serialized parameters for prompt injection and data exfiltration patterns **before** the tool runs. In `warn` mode it logs but doesn't block. Scanner covers 11 regex rules: prompt injection (ignore instructions, DAN mode, jailbreak) and data exfiltration (base64 secrets, curl/wget with credentials).

### Phase 7: Tool Execution

The executor runs the tool handler:
- **`bash`** — shell execution with deny-list checks, optional firejail sandboxing (Linux), output truncated at 50KB
- **`read_file`** — path allowlist + `O_NOFOLLOW` symlink protection
- **`write_file`** — path allowlist + `O_NOFOLLOW` + TOCTOU mitigation
- **`edit_file`** — path allowlist + substring replacement
- **MCP tools** — forwarded to registered MCP servers

### Phases 8-10: Output Sanitization

Three filters clean the tool output before it reaches the agent:

| Step | Filter | Protects against |
|------|--------|-----------------|
| 8 | **Credential Filter** | API keys (Anthropic, OpenAI, GitHub, AWS, Slack, etc.) → `[REDACTED]` |
| 9 | **PII Scrubber** | SSN, phone, email, salary, LinkedIn URLs → `[PII_REDACTED]` |
| 10 | **Post-execute Moderation** | Prompt injection in tool output |

All patterns come from a single source of truth in `packages/types/src/credential-patterns.ts`.

### Phase 11: Audit Logging (Merkle Chain)

Every request — regardless of outcome — gets an append-only SQLite record with:
- Full provenance: `manifestId`, `sessionId`, `agentId`, `tool`, `category`
- Outcome: `decision`, `result` (success/failure/denied/blocked), `duration_ms`
- **Merkle chain**: each entry's `entry_hash` = SHA-256 of `[prev_hash, id, timestamp, ...]`, creating a tamper-evident log

### Phase 12: Return to Agent

The `ToolResult` (sanitized output, success flag, duration) returns to the agent, which adds it to the conversation context and loops back to the LLM for the next reasoning step.

---

## Memory Store Subsystem (`@sentinel/memory`)

The memory store operates as a **parallel subsystem** — it does not sit in the main execution pipeline but is called by the agent to persist and retrieve observations across sessions.

### Memory Entry Lifecycle

```
┌────────────────────────────────────────────────────────────┐
│ WRITE PATH: observe() / observeWithEmbedding()             │
│                                                            │
│  Input ──► Zod validate ──► Credential scrub ──► PII scrub │
│                                    │                       │
│                              content-only                  │
│                              sensitive? ──► REJECT          │
│                                    │                       │
│                              SHA-256 hash                  │
│                                    │                       │
│                              dedup check ◄── 30s window    │
│                              (same hash?) ──► return       │
│                                    │         existing ID   │
│                              quota check ◄── 100MB global  │
│                              (over?) ──► REJECT             │
│                                    │                       │
│                              INSERT observations           │
│                              INSERT observations_fts       │
│                                    │                       │
│                              [if embedder configured]      │
│                              embed(title + content)        │
│                              INSERT observations_vec       │
│                                    │                       │
│                              UPDATE storage_stats          │
│                              return UUID                   │
└────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────┐
│ READ PATH: search() / hybridSearch()                       │
│                                                            │
│  Query ──► parse filters (project, agent, type, dates)     │
│                    │                                       │
│         ┌──────────┴──────────┐                            │
│         │                     │                            │
│    FTS5 keyword          Vector KNN                        │
│    (Porter stemming)     (embed query →                    │
│    title + content +      384-dim cosine                   │
│    concepts               similarity)                      │
│         │                     │                            │
│         └──────────┬──────────┘                            │
│                    │                                       │
│         Reciprocal Rank Fusion                             │
│         score = 1/(K + rank + 1), K=60                     │
│         merge by document ID                               │
│                    │                                       │
│         top N results (limit + offset)                     │
└────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────┐
│ CONSOLIDATION PATH (periodic)                              │
│                                                            │
│  End of session:                                           │
│    observations ──► generateSessionSummary()               │
│      type mapping: context→investigated, learning→learned, │
│      decision/tool_call→completed, error→investigated      │
│    summary written to summaries table                      │
│                                                            │
│  Nightly rollup:                                           │
│    session summaries ──► consolidateDay()                  │
│      idempotency check (skip if daily exists)              │
│      merge + Set dedup across sessions                     │
│    daily summary written                                   │
│                                                            │
│  Pruning:                                                  │
│    pruneObservations(retentionDays)                         │
│      delete observations older than N days                 │
│      KEEP any observation referenced by a summary          │
│      decrement storage_stats                               │
│                                                            │
│  Next session:                                             │
│    buildSessionContext(store, project, agentId)             │
│      latest daily summary → "Yesterday:" system prompt     │
│      ≤200 tokens budget, next_steps only                   │
└────────────────────────────────────────────────────────────┘
```

### Memory Security Invariants

The memory store enforces three security invariants independently of the executor pipeline:

| # | Invariant | Enforcement |
|---|-----------|-------------|
| 4 | **Memory size caps** | Per-entry: 10KB content. Global: 100MB quota tracked in `storage_stats`. Reject with `MemoryQuotaError` on overflow. |
| 5 | **No credential storage** | `validateObservation()` runs `redactAllCredentials()` + `redactPII()` from `@sentinel/types`. If content after scrubbing is *only* redaction markers, reject with `ContentOnlySensitiveError`. |
| — | **Deduplication** | SHA-256 content hash + 30-second dedup window prevents identical writes from flooding the store. |

### Memory Store Data Model

**Three SQLite tables + two virtual tables:**

| Table | Type | Purpose |
|-------|------|---------|
| `observations` | Regular | Core storage — project, session, agent, type, title, content, content_hash, concepts (JSON), files_involved (JSON) |
| `summaries` | Regular | Consolidated summaries — scope (session/daily/weekly), period range, investigated/learned/completed/next_steps arrays |
| `storage_stats` | Regular | Single-row quota tracker — `total_bytes` updated on insert/prune |
| `observations_fts` | FTS5 virtual | Full-text index on title + content + concepts, Porter stemming tokenizer |
| `observations_vec` | vec0 virtual | Vector index — 384-dim float embeddings, KNN via `WHERE embedding MATCH ? AND k = ?` |

---

## Confirmation Subsystem (Parallel State Machine)

```
     CLI Host Terminal                    Executor
     ─────────────────                    ────────
     ┌─────────────────┐
     │ Poller (500ms)  │
     │ GET /pending-   │───────────►  returns pending[]
     │ confirmations   │
     └────────┬────────┘
              │ for each new manifestId:
     ┌────────▼────────┐
     │ Display tool,   │
     │ category, params│
     │ "Approve? (y/n)"│
     └────────┬────────┘
              │ user answers
     ┌────────▼────────┐
     │ POST /confirm/  │───────────►  resolves Promise
     │ {manifestId}    │              executor resumes
     │ {approved: bool}│              /execute handler
     └─────────────────┘
```

This runs as a concurrent process on the **host** (not inside Docker), ensuring the trust anchor for confirmation decisions is outside the agent's reach. The executor's `/execute` handler blocks on a Promise until the confirmation arrives — there is no timeout (waits indefinitely).

---

## Executor Endpoints

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/health` | GET | No | Liveness probe (`{ status: "ok", version: "0.1.0" }`) |
| `/agent-card` | GET | Yes | AgentCard metadata for orchestration |
| `/tools` | GET | Yes | List registered tools (builtin + MCP) |
| `/pending-confirmations` | GET | Yes | Query pending user confirmations |
| `/proxy/llm/*` | ALL | Yes | SSRF-protected LLM proxy (Anthropic, OpenAI, Google) |
| `/execute` | POST | Yes | Main tool execution — guard pipeline + tool handler |
| `/confirm/:manifestId` | POST | Yes | Approve/deny pending confirmation |

Auth is constant-time SHA-256 bearer token comparison. The `/health` endpoint is exempt.

---

## Changes from Phase 1

| Area | Phase 1 (PR #8) | Current (PR #9+) |
|------|-----------------|-------------------|
| **Tests** | 490 | 542 (+52 memory store tests) |
| **Packages** | 7 (`types`, `crypto`, `policy`, `audit`, `executor`, `agent`, `cli`) | 8 (+`memory`) |
| **Host firewall** | None | Rampart v0.8.3 — 48 policies, PreToolUse hook, independent audit log |
| **Memory** | None | `@sentinel/memory` — SQLite + FTS5 + sqlite-vec, hybrid search, consolidation |
| **Data protection** | Path whitelist only | Path whitelist + Rampart deny rules on `vault.enc`, `audit.db`, `memory.db` |
| **Security code gating** | None | Rampart `ask` on 19 security-critical source paths |
| **Embeddings** | None | Local `bge-small-en-v1.5` (384-dim), no external API calls |
| **Observation scrubbing** | Executor-only (output filters) | Memory validator also scrubs credentials + PII before storage |
| **Rate limiter** | Token bucket | GCRA (Generic Cell Rate Algorithm) — functionally equivalent, cleaner semantics |
