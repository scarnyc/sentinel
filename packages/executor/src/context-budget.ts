export interface ContextBudgetConfig {
	contextWindowTokens: number;
	perResultCapPct: number;
	globalCapPct: number;
	maxSessions: number;
}

export interface BudgetResult {
	output: string;
	truncated: boolean;
	outputTokens: number;
	sessionCumulativeTokens: number;
}

const DEFAULT_CONFIG: ContextBudgetConfig = {
	contextWindowTokens: 100_000,
	perResultCapPct: 0.3,
	globalCapPct: 0.75,
	maxSessions: 1000,
};

const TRUNCATION_NOTICE = "\n\n[OUTPUT TRUNCATED — exceeded context budget]";

/** Estimate token count from character length (project convention: ~4 chars per token). */
function estimateTokens(chars: number): number {
	return Math.ceil(chars / 4);
}

/**
 * Enforces per-result and global context budget caps.
 *
 * Per-result cap prevents any single tool output from dominating the context window.
 * Global cap prevents cumulative outputs from exhausting the context window.
 * Sessions are tracked independently with LRU eviction.
 */
export class ContextBudgetTracker {
	private readonly config: Readonly<ContextBudgetConfig>;
	private readonly sessions: Map<string, number> = new Map();

	constructor(config?: Partial<ContextBudgetConfig>) {
		this.config = Object.freeze({ ...DEFAULT_CONFIG, ...config });
	}

	enforce(sessionId: string, output: string | undefined): BudgetResult {
		if (!output || output.length === 0) {
			return {
				output: "",
				truncated: false,
				outputTokens: 0,
				sessionCumulativeTokens: this.sessions.get(sessionId) ?? 0,
			};
		}

		const perResultCap = Math.floor(this.config.contextWindowTokens * this.config.perResultCapPct);
		const globalCap = Math.floor(this.config.contextWindowTokens * this.config.globalCapPct);
		const cumulative = this.sessions.get(sessionId) ?? 0;
		const remaining = globalCap - cumulative;
		const effectiveCap = Math.min(perResultCap, remaining);

		if (effectiveCap <= 0) {
			// Global budget exhausted — return only the notice
			return {
				output: TRUNCATION_NOTICE,
				truncated: true,
				outputTokens: 0,
				sessionCumulativeTokens: cumulative,
			};
		}

		const inputTokens = estimateTokens(output.length);

		if (inputTokens <= effectiveCap) {
			// Within budget — pass through unchanged
			const newCumulative = cumulative + inputTokens;
			this.sessions.set(sessionId, newCumulative);
			this.evictIfNeeded();

			return {
				output,
				truncated: false,
				outputTokens: inputTokens,
				sessionCumulativeTokens: newCumulative,
			};
		}

		// Exceeds cap — truncate to effectiveCap tokens worth of chars
		const truncatedChars = effectiveCap * 4;
		const truncatedOutput = output.slice(0, truncatedChars) + TRUNCATION_NOTICE;
		const newCumulative = cumulative + effectiveCap;
		this.sessions.set(sessionId, newCumulative);
		this.evictIfNeeded();

		return {
			output: truncatedOutput,
			truncated: true,
			outputTokens: effectiveCap,
			sessionCumulativeTokens: newCumulative,
		};
	}

	/** Returns remaining token budget for a session (full global cap if untracked). */
	getRemainingBudget(sessionId: string): number {
		const globalCap = Math.floor(this.config.contextWindowTokens * this.config.globalCapPct);
		const cumulative = this.sessions.get(sessionId) ?? 0;
		return Math.max(0, globalCap - cumulative);
	}

	/** Clear tracking for a specific session, or all sessions. */
	reset(sessionId?: string): void {
		if (sessionId !== undefined) {
			this.sessions.delete(sessionId);
		} else {
			this.sessions.clear();
		}
	}

	/** Evict oldest sessions when exceeding maxSessions (LRU by insertion order). */
	private evictIfNeeded(): void {
		while (this.sessions.size > this.config.maxSessions) {
			const oldest = this.sessions.keys().next().value;
			if (oldest !== undefined) this.sessions.delete(oldest);
		}
	}
}
