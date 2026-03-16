import { z } from "zod";

export const BUILTIN_TOOLS = ["bash", "read_file", "write_file", "edit_file", "gws"] as const;

export const BuiltinToolNameSchema = z.enum(BUILTIN_TOOLS);
export type BuiltinToolName = z.infer<typeof BuiltinToolNameSchema>;

export const ActionCategorySchema = z.enum(["read", "write", "write-irreversible", "dangerous"]);
export type ActionCategory = z.infer<typeof ActionCategorySchema>;

export const ActionManifestSchema = z.object({
	id: z
		.string()
		.uuid()
		.default(() => crypto.randomUUID()),
	timestamp: z
		.string()
		.datetime()
		.default(() => new Date().toISOString()),
	tool: z
		.string()
		.min(1)
		.max(256)
		.regex(
			/^[a-zA-Z][a-zA-Z0-9_.-]*$/,
			"Tool name must start with a letter and contain only alphanumeric, underscore, dot, or hyphen",
		),
	parameters: z.record(z.unknown()),
	category: ActionCategorySchema.optional(),
	sessionId: z.string().min(1),
	agentId: z.string().min(1),
	parentAgentId: z.string().min(1).optional(),
	depth: z.number().int().nonnegative().optional(),
});
export type ActionManifest = z.infer<typeof ActionManifestSchema>;

export const ToolResultSchema = z.object({
	manifestId: z.string().uuid(),
	success: z.boolean(),
	output: z.string().optional(),
	error: z.string().optional(),
	duration_ms: z.number().nonnegative(),
});
export type ToolResult = z.infer<typeof ToolResultSchema>;
