import type { AuditLogger } from "@sentinel/audit";
import { redactCredentials } from "@sentinel/audit";
import { classify, type DepthGuard, type LoopGuard, type RateLimiter } from "@sentinel/policy";
import type {
	ActionManifest,
	AuditEntry,
	PolicyDecision,
	SentinelConfig,
	ToolResult,
} from "@sentinel/types";
import { ActionManifestSchema } from "@sentinel/types";
import type { ContextBudgetTracker } from "./context-budget.js";
import { filterCredentials } from "./credential-filter.js";
import { moderate } from "./moderation/scanner.js";
import { scrubPII } from "./pii-scrubber.js";
import type { ToolRegistry } from "./tools/registry.js";

export type ConfirmFn = (manifest: ActionManifest, decision: PolicyDecision) => Promise<boolean>;

function summarizeParams(params: Record<string, unknown>): string {
	const entries = Object.entries(params);
	const parts = entries.map(([k, v]) => {
		const s = typeof v === "string" ? v : JSON.stringify(v);
		return `${k}=${s && s.length > 100 ? `${s.slice(0, 100)}...` : s}`;
	});
	return parts.join(", ");
}

export interface PipelineGuards {
	rateLimiter?: RateLimiter;
	loopGuard?: LoopGuard;
	depthGuard?: DepthGuard;
	budgetTracker?: ContextBudgetTracker;
}

export async function handleExecute(
	rawManifest: unknown,
	config: SentinelConfig,
	auditLogger: AuditLogger,
	registry: ToolRegistry,
	confirmFn: ConfirmFn,
	guards?: PipelineGuards,
): Promise<ToolResult> {
	// 1. Validate manifest
	const parsed = ActionManifestSchema.safeParse(rawManifest);
	if (!parsed.success) {
		throw new ManifestValidationError(parsed.error.message);
	}
	const manifest = parsed.data;

	// 2. Rate limit check (Phase 1)
	if (guards?.rateLimiter) {
		const rateResult = guards.rateLimiter.check(manifest.agentId);
		if (!rateResult.allowed) {
			auditLogger.log({
				id: crypto.randomUUID(),
				timestamp: new Date().toISOString(),
				manifestId: manifest.id,
				sessionId: manifest.sessionId,
				agentId: manifest.agentId,
				tool: manifest.tool,
				category: "dangerous",
				decision: "block",
				parameters_summary: redactCredentials(summarizeParams(manifest.parameters)),
				result: "blocked_by_rate_limit",
				duration_ms: 0,
			});
			return {
				manifestId: manifest.id,
				success: false,
				error: `Rate limit exceeded. Retry after ${Math.ceil(rateResult.retryAfter ?? 0)}ms`,
				duration_ms: 0,
			};
		}
	}

	// 3. Loop guard check (Phase 1)
	if (guards?.loopGuard) {
		const loopResult = guards.loopGuard.check(manifest.agentId, manifest.tool, manifest.parameters);
		if (loopResult.action === "warn") {
			auditLogger.log({
				id: crypto.randomUUID(),
				timestamp: new Date().toISOString(),
				manifestId: manifest.id,
				sessionId: manifest.sessionId,
				agentId: manifest.agentId,
				tool: manifest.tool,
				category: "dangerous",
				decision: "allow",
				parameters_summary: redactCredentials(summarizeParams(manifest.parameters)),
				result: "loop_guard_warning",
				duration_ms: 0,
			});
		}
		if (loopResult.action === "block") {
			auditLogger.log({
				id: crypto.randomUUID(),
				timestamp: new Date().toISOString(),
				manifestId: manifest.id,
				sessionId: manifest.sessionId,
				agentId: manifest.agentId,
				tool: manifest.tool,
				category: "dangerous",
				decision: "block",
				parameters_summary: redactCredentials(summarizeParams(manifest.parameters)),
				result: "blocked_by_loop_guard",
				duration_ms: 0,
			});
			return {
				manifestId: manifest.id,
				success: false,
				error: loopResult.reason ?? "Loop detected — action blocked",
				duration_ms: 0,
			};
		}
	}

	// 4. Classify via policy engine
	const decision = classify(manifest, config);

	// 5. Decide
	const auditBase: Omit<AuditEntry, "result" | "duration_ms"> = {
		id: crypto.randomUUID(),
		timestamp: new Date().toISOString(),
		manifestId: manifest.id,
		sessionId: manifest.sessionId,
		agentId: manifest.agentId,
		tool: manifest.tool,
		category: decision.category,
		decision: decision.action,
		parameters_summary: redactCredentials(summarizeParams(manifest.parameters)),
	};

	// 4b. Depth guard check — reject deeply-nested agent chains before confirmation
	if (guards?.depthGuard) {
		const depthResult = guards.depthGuard.check(
			manifest.agentId,
			manifest.parentAgentId,
			manifest.depth,
		);
		if (!depthResult.allowed) {
			auditLogger.log({
				...auditBase,
				result: "blocked_by_depth_guard",
				duration_ms: 0,
			});
			return {
				manifestId: manifest.id,
				success: false,
				error: depthResult.reason ?? "Max recursion depth exceeded",
				duration_ms: 0,
			};
		}
	}

	if (decision.action === "block") {
		auditLogger.log({
			...auditBase,
			result: "blocked_by_policy",
			duration_ms: 0,
		});
		return {
			manifestId: manifest.id,
			success: false,
			error: `Blocked by policy: ${decision.reason}`,
			duration_ms: 0,
		};
	}

	if (decision.action === "confirm") {
		const approved = await confirmFn(manifest, decision);
		if (!approved) {
			auditLogger.log({
				...auditBase,
				result: "denied_by_user",
				duration_ms: 0,
			});
			return {
				manifestId: manifest.id,
				success: false,
				error: "Denied by user",
				duration_ms: 0,
			};
		}
	}

	// 6. Pre-execute moderation: scan request parameters
	const paramText = summarizeParams(manifest.parameters);
	const preModeration = moderate(paramText);
	if (preModeration.blocked) {
		auditLogger.log({
			...auditBase,
			result: "blocked_by_policy",
			duration_ms: 0,
		});
		return {
			manifestId: manifest.id,
			success: false,
			error: "Blocked by content moderation",
			duration_ms: 0,
		};
	}

	// 7. Execute
	const handler = registry.get(manifest.tool);
	if (!handler) {
		auditLogger.log({
			...auditBase,
			result: "failure",
			duration_ms: 0,
		});
		return {
			manifestId: manifest.id,
			success: false,
			error: `Unknown tool: ${manifest.tool}`,
			duration_ms: 0,
		};
	}

	// SENTINEL: H1 — Write pending audit entry BEFORE execution (Invariant #2).
	// If the tool crashes or hangs, the pending record proves it was attempted.
	// Append-only Merkle chain: we do NOT mutate this row; a second entry follows.
	const start = Date.now();
	auditLogger.log({
		...auditBase,
		id: crypto.randomUUID(),
		result: "pending",
		duration_ms: 0,
	});

	// SENTINEL: H1 — try/catch around handler to audit failures before re-throwing
	let rawResult: ToolResult;
	try {
		rawResult = await handler(manifest.parameters, manifest.id, manifest.agentId);
	} catch (handlerError) {
		auditLogger.log({
			...auditBase,
			id: crypto.randomUUID(),
			result: "failure",
			duration_ms: Date.now() - start,
		});
		throw handlerError;
	}

	// 8. Filter credentials from tool output before it reaches the agent
	const credFiltered = filterCredentials(rawResult);

	// 9. PII scrub (Phase 1)
	let result = scrubPII(credFiltered);

	// 9b. Context budget enforcement — truncate after redaction (redact-before-truncate ordering)
	if (guards?.budgetTracker && result.output) {
		const budgeted = guards.budgetTracker.enforce(manifest.sessionId, result.output);
		if (budgeted.truncated) {
			result = { ...result, output: budgeted.output };
		}
	}

	// 10. Post-execute moderation: scan tool output
	if (result.output) {
		const postModeration = moderate(result.output);
		if (postModeration.blocked) {
			auditLogger.log({
				...auditBase,
				result: "blocked_by_policy",
				duration_ms: result.duration_ms,
			});
			return {
				manifestId: manifest.id,
				success: false,
				error: "Output blocked by content moderation",
				duration_ms: result.duration_ms,
			};
		}
	}

	// 11. Audit
	auditLogger.log({
		...auditBase,
		result: result.success ? "success" : "failure",
		duration_ms: result.duration_ms,
	});

	return result;
}

export class ManifestValidationError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "ManifestValidationError";
	}
}
