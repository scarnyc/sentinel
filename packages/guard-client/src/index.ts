import type {
	ClassifyResponse,
	ConfirmResponse,
	FilterResponse,
	GuardClientOptions,
	HealthResponse,
	PendingConfirmation,
} from "./types.js";

export type {
	ClassifyResponse,
	ConfirmResponse,
	FilterResponse,
	GuardClientOptions,
	HealthResponse,
	PendingConfirmation,
};

const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_CONFIRMATION_TIMEOUT_MS = 330_000;
const POLL_INTERVAL_MS = 2_000;

export class SentinelGuard {
	private readonly baseUrl: string;
	private readonly authToken?: string;
	private readonly timeoutMs: number;
	private readonly confirmationTimeoutMs: number;

	constructor(options: GuardClientOptions) {
		this.baseUrl = options.executorUrl.replace(/\/+$/, "");
		this.authToken = options.authToken;
		this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
		this.confirmationTimeoutMs = options.confirmationTimeoutMs ?? DEFAULT_CONFIRMATION_TIMEOUT_MS;
	}

	/** Classify a tool call without execution. */
	async classify(
		tool: string,
		params: Record<string, unknown>,
		agentId: string,
		sessionId?: string,
	): Promise<ClassifyResponse> {
		return this.post("/classify", {
			tool,
			params,
			agentId,
			sessionId: sessionId ?? "default",
			source: "guard-client",
		});
	}

	/** Filter output for credentials and PII. */
	async filterOutput(output: string, agentId?: string, tool?: string): Promise<FilterResponse> {
		return this.post("/filter-output", { output, agentId, tool });
	}

	/** Classify + confirm (blocks until user approves/denies or timeout). */
	async confirmOnly(
		tool: string,
		params: Record<string, unknown>,
		agentId: string,
		sessionId?: string,
	): Promise<ConfirmResponse> {
		return this.post(
			"/confirm-only",
			{
				tool,
				params,
				agentId,
				sessionId: sessionId ?? "default",
				source: "guard-client",
			},
			this.confirmationTimeoutMs,
		);
	}

	/**
	 * Poll /pending-confirmations until a specific manifest is resolved.
	 * Returns true if the manifest is no longer pending (resolved), false on timeout.
	 */
	async awaitConfirmation(manifestId: string, timeoutMs?: number): Promise<boolean> {
		const deadline = Date.now() + (timeoutMs ?? this.confirmationTimeoutMs);

		while (Date.now() < deadline) {
			const pending = await this.pendingConfirmations();
			const found = pending.some((p) => p.manifestId === manifestId);
			if (!found) {
				return true;
			}
			await sleep(POLL_INTERVAL_MS);
		}
		return false;
	}

	/** List all pending confirmations. */
	async pendingConfirmations(): Promise<PendingConfirmation[]> {
		return this.get("/pending-confirmations");
	}

	/** Proxy an LLM request through the executor. */
	async proxyLlm(provider: string, path: string, body: unknown): Promise<Response> {
		const url = `${this.baseUrl}/proxy/llm/${provider}/${path}`;
		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), this.timeoutMs);
		try {
			const res = await fetch(url, {
				method: "POST",
				headers: this.headers(),
				body: JSON.stringify(body),
				signal: controller.signal,
			});
			if (!res.ok) {
				const text = await res.text();
				throw new SentinelGuardError(`LLM proxy returned ${res.status}: ${text}`, res.status);
			}
			return res;
		} finally {
			clearTimeout(timer);
		}
	}

	/** Check executor health. */
	async health(): Promise<HealthResponse> {
		try {
			return await this.get("/health");
		} catch {
			return { status: "unreachable" };
		}
	}

	private async post<T>(path: string, body: unknown, timeoutOverrideMs?: number): Promise<T> {
		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), timeoutOverrideMs ?? this.timeoutMs);
		try {
			const res = await fetch(`${this.baseUrl}${path}`, {
				method: "POST",
				headers: this.headers(),
				body: JSON.stringify(body),
				signal: controller.signal,
			});
			if (!res.ok) {
				const text = await res.text();
				throw new SentinelGuardError(`Executor returned ${res.status}: ${text}`, res.status);
			}
			return (await res.json()) as T;
		} finally {
			clearTimeout(timer);
		}
	}

	private async get<T>(path: string): Promise<T> {
		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), this.timeoutMs);
		try {
			const res = await fetch(`${this.baseUrl}${path}`, {
				method: "GET",
				headers: this.headers(),
				signal: controller.signal,
			});
			if (!res.ok) {
				const text = await res.text();
				throw new SentinelGuardError(`Executor returned ${res.status}: ${text}`, res.status);
			}
			return (await res.json()) as T;
		} finally {
			clearTimeout(timer);
		}
	}

	private headers(): Record<string, string> {
		const h: Record<string, string> = { "Content-Type": "application/json" };
		if (this.authToken) {
			h.Authorization = `Bearer ${this.authToken}`;
		}
		return h;
	}
}

export class SentinelGuardError extends Error {
	readonly status: number;
	constructor(message: string, status: number) {
		super(message);
		this.name = "SentinelGuardError";
		this.status = status;
	}
}

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}
