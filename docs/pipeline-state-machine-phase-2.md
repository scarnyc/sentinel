# Sentinel Pipeline State Machine — Phase 2

> **Snapshot**: Post-Wave 2.2c (847 tests, 9 packages) — Ed25519 manifest signing, `write-irreversible` classification, GWS CLI integration, credential zeroization (`useCredential()`), HMAC response signing, body size limits, ReDoS-hardened classifier, dual audit entries (pending + final).
>
> **Master plan**: [`docs/plans/path-a-v2-adopt-openfang-primitives.md`](plans/path-a-v2-adopt-openfang-primitives.md)
>
> **Previous**: [`docs/pipeline-state-machine-phase-1.5.md`](pipeline-state-machine-phase-1.5.md) — Phase 1.5 pipeline (542 tests, 8 packages).

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
    ┌──────────────────────────────▼──────────────────────────────────┐
    │                     HTTP MIDDLEWARE (NEW)                        │
    │                     (applied before route handlers)             │
    │                                                                 │
    │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐   │
    │  │ 1.Request│  │ 2.Body   │  │ 3.HMAC   │  │ 4.Auth       │   │
    │  │ ID       │→│ Size     │→│ Response │→│ Middleware    │   │
    │  │ (UUID v4)│  │ Limits   │  │ Signer   │  │ (SHA-256     │   │
    │  │          │  │ (10/25MB)│  │ (SHA-256)│  │  const-time) │   │
    │  │          │  │ →413     │  │          │  │ →401         │   │
    │  └──────────┘  └──────────┘  └──────────┘  └──────────────┘   │
    │                                                                 │
    └──────────────────────────────┬──────────────────────────────────┘
                                   │
    ┌──────────────────────────────▼──────────────────────────────────┐
    │                     GUARD PIPELINE                              │
    │                     (fail-fast, sequential)                     │
    │                                                                 │
    │  ┌──────────┐  ┌───────────┐  ┌──────────┐  ┌──────────────┐  │
    │  │ 5.Validate│→│ 6.Rate    │→│ 7.Loop   │→│ 8.Policy     │  │
    │  │ Manifest │  │ Limiter   │  │ Guard    │  │ Classify     │  │
    │  │ (Zod)    │  │ (GCRA     │  │ (SHA-256 │  │ (bash parse  │  │
    │  │          │  │  per-agent)│  │  fingerp)│  │  + GWS +     │  │
    │  │ →400     │  │ →422+audit│  │ →422+aud │  │  config +    │  │
    │  │          │  │           │  │          │  │  ReDoS)      │  │
    │  └──────────┘  └───────────┘  └──────────┘  └──────┬───────┘  │
    │                                                     │          │
    │                                            ┌────────▼────────┐ │
    │                                            │ DECISION        │ │
    │                                            │ ROUTING         │ │
    │                                            └──┬──────┬────┬──┘ │
    │                                    ┌──────────┘      │    └──────────┐
    │                                    │                 │               │
    │                               ┌────▼───┐    ┌───────▼──────┐  ┌─────▼──────────┐
    │                               │ BLOCK  │    │ AUTO_APPROVE │  │ CONFIRM        │
    │                               │→error  │    │ (read ops)   │  │ (write/        │
    │                               │+audit  │    │              │  │  write-irrevers│
    │                               └────────┘    └───────┬──────┘  │  /dangerous)   │
    │                                                     │         └─────┬──────────┘
    │                                                     │               │
    │                                                     │    ┌──────────▼──────────┐
    │                                                     │    │ AWAITING            │
    │                                                     │    │ CONFIRMATION        │
    │                                                     │    │ (5-min timeout)     │
    │                                                     │    └───┬────────┬────┬───┘
    │                                                     │       │        │    │
    │                                                     │ ┌─────▼──┐ ┌──▼───┐│
    │                                                     │ │APPROVED│ │DENIED││
    │                                                     │ └─────┬──┘ │→error││
    │                                                     │       │    │+audit││
    │                                                     │       │    └──────┘│
    │                                                     │       │    ┌──▼────┘
    │                                                     │       │    │TIMEOUT
    │                                                     │       │    │→auto-deny
    │                                                     │       │    │+audit
    │                                                     │       │    └───────┘
    │                                                     ├───────┘
    │                                                     │
    │  ┌──────────┐  ┌───────────┐  ┌────────────────────▼──┐  ┌──────────┐   │
    │  │ 9.Pre-   │  │10.Audit:  │  │ 11.TOOL EXECUTE       │  │12.Cred   │   │
    │  │execute   │→│ Pending   │→│ (bash/gws/read/write/ │→│ Filter   │   │
    │  │moderation│  │ (Merkle + │  │  MCP)                 │  │          │   │
    │  │          │  │  Ed25519) │  │                       │  │          │   │
    │  └──────────┘  └───────────┘  └───────────────────────┘  └────┬─────┘   │
    │                                                                │         │
    │  ┌──────────────────────────────────────────────────────────┐  │         │
    │  │ 15. AUDIT LOG (Merkle + Ed25519, pending + final)       │  │         │
    │  └────┬────────────────────────────────────────────────────┘  │         │
    │       │  ┌──────────┐  ┌──────────┐                           │         │
    │       │  │14.Post-  │←│13.PII    │◄──────────────────────────┘         │
    │       │  │execute   │  │ Scrub    │                                     │
    │       │  │moderation│  │          │                                     │
    │       │  └────┬─────┘  └──────────┘                                     │
    │       │       │                                                         │
    └───────┼───────┼─────────────────────────────────────────────────────────┘
            │       │
            ├───────┘
            │
    ┌───────▼────────┐
    │ RETURN         │
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
│ What: HTTP middleware + guard pipeline + policy classifier            │
│       Body size limits, HMAC signing, ReDoS-hardened classifier      │
│       5-min confirmation timeout, write-irreversible category        │
│ Where: HTTP :3141 inside Docker — agent → executor trust boundary    │
│ Scope: Per-agent, per-session — session-scoped isolation             │
│ Audit: Merkle-chained + Ed25519 signed SQLite append-only log        │
├──────────────────────────────────────────────────────────────────────┤
│ LAYER 3: SENTINEL OUTPUT FILTERS (Data Boundary)                     │
│ What: Credential filter (21 patterns, 3-pass encoding-aware),        │
│       PII scrubber (9 patterns), content moderation,                 │
│       SSE credential filter, email injection scanner                 │
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
| **Response integrity** | HMAC-SHA256 signing on all responses | N/A | Agent can verify response hasn't been tampered with between containers |
| **Request size limits** | Body size limits per-route (10/25MB) | N/A | Prevents memory exhaustion from oversized payloads |
| **GWS scoping** | Per-agent service allow/deny lists | N/A | Limits which Google Workspace services each agent can access |
| **Email defense** | Email injection scanner + pre-send credential gate | N/A | Prevents credential exfiltration via email body/subject |
| **Streaming defense** | SSE credential filter on LLM proxy | N/A | Scrubs credentials from streaming LLM responses in real-time |

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

### Phase 2: LLM Call (via Proxy) — UPDATED

The agent has **no internet access** (Docker `internal: true`). All LLM calls route through the executor's `/proxy/llm/*` endpoint, which:
- Validates the target host against an allowlist (Anthropic, OpenAI, Google)
- Runs the **SSRF guard** to block private IPs and cloud metadata endpoints
- Injects API keys from the encrypted vault via the `useCredential()` callback pattern (`packages/crypto/src/use-credential.ts`), not raw env vars. The Buffer is zeroed in `finally`; credential strings become GC-eligible after the callback returns.
- Runs the **SSE credential filter** (`packages/executor/src/sse-credential-filter.ts`) on streaming LLM responses, scrubbing credentials from Server-Sent Events in real-time before they reach the agent.

The LLM proxy handler is created via a factory pattern: `createLlmProxyHandler(vault?, auditLogger?)` — this avoids global state and enables test mocking with dependency injection.

The LLM proxy is a key security primitive — it means the agent process literally cannot exfiltrate data to arbitrary URLs. Even if the LLM is prompt-injected into trying to call a malicious endpoint, the proxy's host allowlist blocks it.

### Phase 3: Action Manifest Construction

When the LLM decides to use a tool, the agent builds an **ActionManifest** — a typed JSON envelope with UUID, timestamp, tool name, parameters, sessionId, and agentId. This is the only way the agent can request side effects.

### Phase 4: HTTP Middleware (NEW)

Before the guard pipeline evaluates the action manifest, four HTTP middleware layers process every inbound request to the executor. These run sequentially on all routes (not just `/execute`):

1. **Request ID** (`packages/executor/src/request-id.ts`) — Assigns a UUID v4 to every inbound request and stores it in the Hono context. The ID is returned as the `X-Request-ID` response header, enabling end-to-end request tracing across audit log entries, error responses, and debug logs.

2. **Body Size Limits** (`packages/executor/src/server.ts`) — Two-layer defense against oversized payloads. First, the `Content-Length` header is checked for fast rejection without reading the body. Second, the actual body bytes are verified to catch chunked transfer encoding bypass attempts that omit `Content-Length`. Limits are route-specific: 10MB for `/execute`, 25MB for `/proxy/llm/*`. Oversized requests receive `413 Payload Too Large`. This middleware is gated behind `SENTINEL_DOCKER=true` to avoid breaking the Hono test client, which doesn't always set `Content-Length`.

3. **HMAC Response Signer** (`packages/executor/src/response-signer.ts`) — Computes HMAC-SHA256 over the response body and sets the `X-Sentinel-Signature` header. This enables the agent to verify that responses haven't been tampered with in transit between containers (e.g., by a compromised network proxy). SSE (streaming) responses receive a `"streaming"` marker since their body is generated incrementally and cannot be pre-signed.

4. **Auth Middleware** (`packages/executor/src/auth-middleware.ts`) — Authenticates requests using constant-time SHA-256 hash comparison of Bearer tokens. The `/health` endpoint is exempted for container orchestration probes. When running in Docker (`SENTINEL_DOCKER=true`) with no auth token configured, requests are rejected with `401 Unauthorized` — this is a fail-safe default that prevents accidentally running an unauthenticated executor in production.
