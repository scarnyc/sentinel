import type { FilterOutputResponse } from "@sentinel/types";
import { FilterOutputRequestSchema, redactAll, redactPII } from "@sentinel/types";
import type { Context } from "hono";
import { moderate } from "./moderation/scanner.js";

export async function handleFilterOutput(c: Context): Promise<Response> {
	const raw = await c.req.json();
	const parsed = FilterOutputRequestSchema.safeParse(raw);
	if (!parsed.success) {
		return c.json({ error: `Invalid request: ${parsed.error.message}` }, 400);
	}

	const { output } = parsed.data;

	// 1. Filter credentials
	let filtered = redactAll(output);
	const credentialRedacted = filtered !== output;

	// 2. Scrub PII
	const afterPII = redactPII(filtered);
	const piiRedacted = afterPII !== filtered;
	filtered = afterPII;

	// 3. Content moderation
	const moderation = moderate(filtered);

	const response: FilterOutputResponse = {
		filtered: moderation.blocked ? "[CONTENT_BLOCKED]" : filtered,
		redacted: credentialRedacted || piiRedacted,
		moderationFlagged: moderation.scanResult.flagged,
		moderationBlocked: moderation.blocked,
	};

	return c.json(response, 200);
}
