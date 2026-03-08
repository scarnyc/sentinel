import type { ToolResult } from "@sentinel/types";
import { redactPII } from "@sentinel/types";

/**
 * Scrub PII from tool results.
 * Applied as a dedicated pipeline stage for visibility and auditability.
 * Note: credential-filter.ts also applies redactAll (which includes PII),
 * but this stage makes PII scrubbing explicit and allows independent configuration.
 */
export function scrubPII(result: ToolResult): ToolResult {
	return {
		...result,
		output: result.output ? redactPII(result.output) : result.output,
		error: result.error ? redactPII(result.error) : result.error,
	};
}

/**
 * Check if text contains PII patterns (for pre-execution scanning).
 * Returns true if PII was found.
 */
export function containsPII(text: string): boolean {
	const scrubbed = redactPII(text);
	return scrubbed !== text;
}
