import { randomBytes } from "node:crypto";
import type { SentinelConfig } from "@sentinel/types";

/**
 * Auto-generates a cryptographically random auth token in Docker mode
 * when no authToken is configured. This prevents the executor from
 * running without authentication inside a container.
 */
export function ensureDockerAuth(config: SentinelConfig): SentinelConfig {
	if (process.env.SENTINEL_DOCKER !== "true") return config;
	if (config.authToken) return config;

	const generated = randomBytes(32).toString("hex");
	console.log(
		"[sentinel] Docker mode: auto-generated auth token (set authToken in config to use a fixed token)",
	);
	return { ...config, authToken: generated };
}
