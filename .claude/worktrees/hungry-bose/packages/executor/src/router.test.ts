import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLogger } from "@sentinel/audit";
import { getDefaultConfig, validateConfig } from "@sentinel/policy";
import type { ActionManifest, AuditEntry, SentinelConfig } from "@sentinel/types";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type ConfirmFn, handleExecute } from "./router.js";
import { ToolRegistry } from "./tools/registry.js";

let tempDir: string;
let auditLogger: AuditLogger;
let config: SentinelConfig;

function makeManifest(overrides: Partial<ActionManifest> = {}): ActionManifest {
	return {
		id: crypto.randomUUID(),
		timestamp: new Date().toISOString(),
		tool: "test-tool",
		parameters: { value: "hello" },
		sessionId: "test-session",
		agentId: "test-agent",
		...overrides,
	};
}

const autoApproveConfirm: ConfirmFn = async () => true;

beforeEach(() => {
	tempDir = realpathSync(mkdtempSync(join(tmpdir(), "sentinel-router-test-")));
	const dbPath = join(tempDir, "audit.db");
	auditLogger = new AuditLogger(dbPath);

	const mutableConfig = getDefaultConfig();
	mutableConfig.auditLogPath = dbPath;
	mutableConfig.autoApproveReadOps = true;
	config = Object.freeze(structuredClone(validateConfig(mutableConfig)));
});

afterEach(() => {
	auditLogger.close();
	rmSync(tempDir, { recursive: true, force: true });
});

describe("H1: pending audit entry before execution", () => {
	it("writes pending audit entry before handler runs", async () => {
		const registry = new ToolRegistry();
		let auditCountDuringHandler = -1;

		registry.registerBuiltin("test-tool", async (_params, manifestId) => {
			// Check how many audit entries exist DURING handler execution
			const entries = auditLogger.query({});
			auditCountDuringHandler = entries.filter((e: AuditEntry) => e.result === "pending").length;
			return { manifestId, success: true, duration_ms: 1 };
		});

		const manifest = makeManifest();
		await handleExecute(manifest, config, auditLogger, registry, autoApproveConfirm);

		// During handler execution, there should have been a pending entry
		expect(auditCountDuringHandler).toBe(1);
	});

	it("writes pending entry even if handler throws", async () => {
		const registry = new ToolRegistry();

		registry.registerBuiltin("test-tool", async () => {
			throw new Error("Handler exploded");
		});

		const manifest = makeManifest();
		await expect(
			handleExecute(manifest, config, auditLogger, registry, autoApproveConfirm),
		).rejects.toThrow("Handler exploded");

		const entries = auditLogger.query({});
		const pendingEntries = entries.filter((e: AuditEntry) => e.result === "pending");
		expect(pendingEntries.length).toBe(1);
	});

	it("logs failure audit entry when handler throws", async () => {
		const registry = new ToolRegistry();

		registry.registerBuiltin("test-tool", async () => {
			throw new Error("Handler exploded");
		});

		const manifest = makeManifest();
		await expect(
			handleExecute(manifest, config, auditLogger, registry, autoApproveConfirm),
		).rejects.toThrow("Handler exploded");

		const entries = auditLogger.query({});
		const failureEntries = entries.filter((e: AuditEntry) => e.result === "failure");
		expect(failureEntries.length).toBe(1);
	});

	it("maintains valid Merkle chain with pending + completion entries", async () => {
		const registry = new ToolRegistry();

		registry.registerBuiltin("test-tool", async (_params, manifestId) => {
			return { manifestId, success: true, duration_ms: 1 };
		});

		const manifest = makeManifest();
		await handleExecute(manifest, config, auditLogger, registry, autoApproveConfirm);

		// Verify chain integrity with the signing public key
		const publicKey = auditLogger.getSigningPublicKey();
		const result = auditLogger.verifyChain(publicKey);
		expect(result.valid).toBe(true);

		// Should have at least 2 entries: pending + success
		const entries = auditLogger.query({});
		expect(entries.length).toBeGreaterThanOrEqual(2);
		expect(entries.some((e: AuditEntry) => e.result === "pending")).toBe(true);
		expect(entries.some((e: AuditEntry) => e.result === "success")).toBe(true);
	});
});
