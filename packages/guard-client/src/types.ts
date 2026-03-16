/** Classification response from /classify */
export interface ClassifyResponse {
	action: "auto_approve" | "confirm" | "block";
	category: string;
	reason?: string;
}

/** Filter output response from /filter-output */
export interface FilterResponse {
	filtered: string;
	redactedCount: number;
}

/** Confirmation response from /confirm-only */
export interface ConfirmResponse {
	decision: "auto_approve" | "confirm" | "block" | "approved" | "denied";
	category?: string;
	reason?: string;
	manifestId: string;
}

/** Pending confirmation entry from /pending-confirmations */
export interface PendingConfirmation {
	manifestId: string;
	tool: string;
	parameters: Record<string, unknown>;
	category: string;
	reason?: string;
}

/** Health check response */
export interface HealthResponse {
	status: string;
	version?: string;
}

/** Guard client configuration */
export interface GuardClientOptions {
	/** Executor base URL (e.g., "http://localhost:3141") */
	executorUrl: string;
	/** Bearer auth token for executor API */
	authToken?: string;
	/** Request timeout in milliseconds (default: 30000) */
	timeoutMs?: number;
	/** Confirmation poll timeout (default: 330000 — matches executor's 5-min + buffer) */
	confirmationTimeoutMs?: number;
}
