import { z } from "zod";

export const PluginConfigSchema = z.object({
	executorUrl: z
		.string()
		.url()
		.default("http://localhost:3141"),
	authToken: z.string().min(1).optional(),
	failMode: z.enum(["closed", "open"]).default("closed"),
	healthCheckIntervalMs: z.number().positive().default(30_000),
	connectionTimeoutMs: z.number().positive().default(5_000),
});
export type PluginConfig = z.infer<typeof PluginConfigSchema>;

export function loadConfigFromEnv(): PluginConfig {
	return PluginConfigSchema.parse({
		executorUrl: process.env.SENTINEL_EXECUTOR_URL || undefined,
		authToken: process.env.SENTINEL_AUTH_TOKEN || undefined,
		failMode: process.env.SENTINEL_FAIL_MODE || undefined,
	});
}
