import { z } from "zod";
import { ActionCategorySchema } from "./manifest.js";

export const ClassifyRequestSchema = z.object({
	tool: z
		.string()
		.min(1)
		.max(256)
		.regex(
			/^[a-zA-Z][a-zA-Z0-9_.-]*$/,
			"Tool name must start with a letter and contain only alphanumeric, underscore, dot, or hyphen",
		),
	params: z.record(z.unknown()),
	agentId: z.string().min(1),
	sessionId: z.string().min(1),
	source: z.enum(["sentinel", "openclaw", "claude-code"]).optional(),
});
export type ClassifyRequest = z.infer<typeof ClassifyRequestSchema>;

export const ClassifyResponseSchema = z.object({
	decision: z.enum(["auto_approve", "confirm", "block"]),
	category: ActionCategorySchema,
	reason: z.string(),
	manifestId: z.string().uuid(),
});
export type ClassifyResponse = z.infer<typeof ClassifyResponseSchema>;
