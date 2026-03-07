import { serve } from "@hono/node-server";
import { AuditLogger } from "@sentinel/audit";
import { getDefaultConfig } from "@sentinel/policy";
import { loadPolicy } from "./policy-loader.js";
import { createApp } from "./server.js";
import { createToolRegistry } from "./tools/index.js";

const config = getDefaultConfig();
config.auditLogPath = process.env.SENTINEL_AUDIT_PATH ?? "/app/data/audit.db";
config.vaultPath = process.env.SENTINEL_VAULT_PATH ?? "/app/data/vault.enc";

// Fail-closed: crash if policy is missing or invalid (no fallback)
const policyPath = process.env.SENTINEL_POLICY_PATH ?? "./config/policy.json";
const policy = loadPolicy(policyPath);
console.log(
	`Policy v${policy.version} loaded: ${Object.keys(policy.agents).length} agents, ${Object.keys(policy.toolGroups).length} groups`,
);

const auditLogger = new AuditLogger(config.auditLogPath);
const registry = createToolRegistry();
const app = createApp(config, policy, auditLogger, registry);

const port = config.executor.port;
const host = "0.0.0.0";

serve({ fetch: app.fetch, port, hostname: host }, () => {
	console.log(`Sentinel Executor listening on http://${host}:${port}`);
});
