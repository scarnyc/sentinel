import { describe, expect, it } from "vitest";
import { createSentinelPlugin } from "../index.js";

describe("createSentinelPlugin", () => {
	it("creates a plugin with all required hooks", () => {
		const plugin = createSentinelPlugin({
			executorUrl: "http://localhost:9999",
		});
		expect(plugin.beforeToolCall).toBeTypeOf("function");
		expect(plugin.afterToolCall).toBeTypeOf("function");
		expect(plugin.sanitizeOutput).toBeTypeOf("function");
		expect(plugin.stop).toBeTypeOf("function");
		plugin.stop();
	});

	it("sanitizeOutput redacts credentials (pure function)", () => {
		const plugin = createSentinelPlugin({
			executorUrl: "http://localhost:9999",
		});
		const key = ["sk", "ant", "api03", "abc123def456"].join("-");
		const result = plugin.sanitizeOutput(`Key: ${key}`);
		expect(result).not.toContain("sk-ant");
		expect(result).toContain("[REDACTED]");
		plugin.stop();
	});

	it("sanitizeOutput redacts PII (pure function)", () => {
		const plugin = createSentinelPlugin({
			executorUrl: "http://localhost:9999",
		});
		const result = plugin.sanitizeOutput("SSN: 123-45-6789");
		expect(result).not.toContain("123-45-6789");
		plugin.stop();
	});

	it("beforeToolCall blocks when executor unreachable in fail-closed mode", async () => {
		const plugin = createSentinelPlugin({
			executorUrl: "http://127.0.0.1:1", // unreachable
			failMode: "closed",
			connectionTimeoutMs: 500,
		});

		const result = await plugin.beforeToolCall({
			toolName: "bash",
			params: { command: "ls" },
			runId: "run-1",
			session: { sessionId: "s1" },
		});
		expect(result.block).toBe(true);
		expect(result.blockReason).toContain("Sentinel");
		plugin.stop();
	});

	it("beforeToolCall allows through when executor unreachable in fail-open mode", async () => {
		const plugin = createSentinelPlugin({
			executorUrl: "http://127.0.0.1:1",
			failMode: "open",
			connectionTimeoutMs: 500,
		});

		const result = await plugin.beforeToolCall({
			toolName: "bash",
			params: { command: "ls" },
			runId: "run-1",
			session: { sessionId: "s1" },
		});
		expect(result.block).toBe(false);
		plugin.stop();
	});

	it("stop cleans up health monitor", () => {
		const plugin = createSentinelPlugin({
			executorUrl: "http://localhost:9999",
		});
		// Should not throw
		plugin.stop();
		plugin.stop(); // idempotent
	});
});
