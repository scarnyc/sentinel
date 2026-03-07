import { z } from "zod";

export const WorkspaceScopeSchema = z.object({
	root: z.string().min(1),
	access: z.enum(["ro", "rw"]),
});
export type WorkspaceScope = z.infer<typeof WorkspaceScopeSchema>;

export const ApprovalPatternSchema = z.object({
	pattern: z.string().min(1),
});
export type ApprovalPattern = z.infer<typeof ApprovalPatternSchema>;

export const ApprovalConfigSchema = z.object({
	ask: z.enum(["always", "on-miss", "never"]),
	allowlist: z.array(ApprovalPatternSchema).optional(),
});
export type ApprovalConfig = z.infer<typeof ApprovalConfigSchema>;

export const ToolPolicySchema = z.object({
	allow: z.array(z.string()),
	deny: z.array(z.string()),
});

export const DefaultPolicySchema = z.object({
	tools: ToolPolicySchema,
	workspace: WorkspaceScopeSchema,
	approval: ApprovalConfigSchema,
});
export type DefaultPolicy = z.infer<typeof DefaultPolicySchema>;

export const AgentPolicySchema = z.object({
	tools: z.object({
		allow: z.array(z.string()).optional(),
		deny: z.array(z.string()).optional(),
	}),
	workspace: WorkspaceScopeSchema,
	approval: ApprovalConfigSchema.optional(),
});
export type AgentPolicy = z.infer<typeof AgentPolicySchema>;

export const PolicyDocumentSchema = z.object({
	version: z.literal(1),
	toolGroups: z.record(z.array(z.string())),
	defaults: DefaultPolicySchema,
	agents: z.record(AgentPolicySchema),
});
export type PolicyDocument = z.infer<typeof PolicyDocumentSchema>;
