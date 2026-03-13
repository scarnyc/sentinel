import { z } from "zod";

export const DelegateCodeParamsSchema = z.object({
	task: z.string().min(1).max(10_000),
	worktreeName: z
		.string()
		.min(1)
		.max(128)
		.regex(/^[a-zA-Z0-9_-]+$/, "Worktree name must be alphanumeric with dashes/underscores")
		.optional(),
	allowedTools: z
		.array(z.string().min(1))
		.default(["Read", "Write", "Edit", "Bash", "Glob", "Grep"]),
	maxBudgetUsd: z.number().positive().max(100).default(5),
	timeoutSeconds: z.number().positive().max(3600).default(900),
});
export type DelegateCodeParams = z.infer<typeof DelegateCodeParamsSchema>;
