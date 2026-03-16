export interface DepthGuardConfig {
	maxDepth: number;
	maxAgents: number;
}

export interface DepthCheckResult {
	allowed: boolean;
	depth: number;
	reason?: string;
}

const DEFAULT_CONFIG: DepthGuardConfig = {
	maxDepth: 5,
	maxAgents: 1000,
};

export class DepthGuard {
	private readonly config: DepthGuardConfig;
	private readonly parentMap: Map<string, string> = new Map();

	constructor(config?: Partial<DepthGuardConfig>) {
		const merged = { ...DEFAULT_CONFIG, ...config };
		if (merged.maxDepth < 1) {
			throw new Error("maxDepth must be positive");
		}
		if (merged.maxAgents < 1) {
			throw new Error("maxAgents must be positive");
		}
		this.config = Object.freeze(merged);
	}

	check(agentId: string, parentAgentId?: string, declaredDepth?: number): DepthCheckResult {
		// Register parent relationship if provided
		if (parentAgentId !== undefined) {
			this.parentMap.set(agentId, parentAgentId);
		}

		this.evictIfNeeded();

		// Compute depth by walking parentMap chain
		const computedDepth = this.computeDepth(agentId);

		// Cycle detected
		if (computedDepth === -1) {
			return {
				allowed: false,
				depth: -1,
				reason: `Cycle detected in agent chain for "${agentId}"`,
			};
		}

		// Use more restrictive of declared vs computed
		const depth = Math.max(declaredDepth ?? 0, computedDepth);

		if (depth >= this.config.maxDepth) {
			return {
				allowed: false,
				depth,
				reason: `Agent "${agentId}" at depth ${depth} exceeds max recursion depth ${this.config.maxDepth}`,
			};
		}

		return { allowed: true, depth };
	}

	private computeDepth(agentId: string): number {
		const visited = new Set<string>();
		let current: string | undefined = agentId;
		let hops = 0;

		while (current !== undefined) {
			if (visited.has(current)) {
				// Cycle detected
				return -1;
			}
			visited.add(current);
			const parent = this.parentMap.get(current);
			if (parent === undefined) {
				// Reached root
				break;
			}
			hops++;
			current = parent;

			// Fail-safe: if chain exceeds maxDepth * 2, treat as cycle
			if (hops > this.config.maxDepth * 2) {
				return -1;
			}
		}

		return hops;
	}

	private evictIfNeeded(): void {
		while (this.parentMap.size > this.config.maxAgents) {
			const oldest = this.parentMap.keys().next().value;
			if (oldest !== undefined) this.parentMap.delete(oldest);
		}
	}

	reset(agentId?: string): void {
		if (agentId !== undefined) {
			this.parentMap.delete(agentId);
		} else {
			this.parentMap.clear();
		}
	}
}
