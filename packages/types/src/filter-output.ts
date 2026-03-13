import { z } from "zod";

export const FilterOutputRequestSchema = z.object({
	output: z.string().max(1_048_576),
	tool: z.string().min(1).optional(),
	agentId: z.string().min(1),
});
export type FilterOutputRequest = z.infer<typeof FilterOutputRequestSchema>;

export const FilterOutputResponseSchema = z.object({
	filtered: z.string(),
	redacted: z.boolean(),
	moderationFlagged: z.boolean(),
	moderationBlocked: z.boolean(),
});
export type FilterOutputResponse = z.infer<typeof FilterOutputResponseSchema>;
