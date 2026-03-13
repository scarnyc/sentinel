import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ExecutorClient } from "../executor-client.js";

const mockFetch = vi.fn();

beforeEach(() => {
	vi.stubGlobal("fetch", mockFetch);
});

afterEach(() => {
	vi.restoreAllMocks();
});

describe("ExecutorClient", () => {
	it("sends classify request to /classify", async () => {
		const classifyResponse = {
			decision: "auto_approve",
			category: "read",
			reason: "Read operation",
			manifestId: "00000000-0000-0000-0000-000000000001",
		};

		mockFetch.mockResolvedValueOnce({
			ok: true,
			json: () => Promise.resolve(classifyResponse),
		});

		const client = new ExecutorClient({
			executorUrl: "http://127.0.0.1:3141",
			timeoutMs: 5000,
		});
		const result = await client.classify("read_file", { path: "/tmp" }, "agent-1", "session-1");

		expect(mockFetch).toHaveBeenCalledOnce();
		const [url, options] = mockFetch.mock.calls[0] as [string, RequestInit];
		expect(url).toBe("http://127.0.0.1:3141/classify");
		expect(options.method).toBe("POST");
		const parsed = JSON.parse(options.body as string);
		expect(parsed.source).toBe("openclaw");
		expect(parsed.tool).toBe("read_file");
		expect(parsed.agentId).toBe("agent-1");
		expect(parsed.sessionId).toBe("session-1");
		expect(result.decision).toBe("auto_approve");
	});

	it("sends filter request to /filter-output", async () => {
		const filterResponse = {
			filtered: "clean text",
			redacted: false,
			moderationFlagged: false,
			moderationBlocked: false,
		};

		mockFetch.mockResolvedValueOnce({
			ok: true,
			json: () => Promise.resolve(filterResponse),
		});

		const client = new ExecutorClient({
			executorUrl: "http://127.0.0.1:3141",
			timeoutMs: 5000,
		});
		const result = await client.filterOutput("clean text", "agent-1");

		expect(mockFetch).toHaveBeenCalledOnce();
		const [url] = mockFetch.mock.calls[0] as [string, RequestInit];
		expect(url).toBe("http://127.0.0.1:3141/filter-output");
		expect(result.filtered).toBe("clean text");
	});

	it("sends execute request to /execute", async () => {
		const executeResponse = { success: true, manifestId: "test-id", output: "ok", duration_ms: 10 };

		mockFetch.mockResolvedValueOnce({
			ok: true,
			json: () => Promise.resolve(executeResponse),
		});

		const client = new ExecutorClient({
			executorUrl: "http://127.0.0.1:3141",
			timeoutMs: 5000,
		});
		const result = await client.execute({ tool: "bash", parameters: { command: "ls" } });

		expect(mockFetch).toHaveBeenCalledOnce();
		const [url] = mockFetch.mock.calls[0] as [string, RequestInit];
		expect(url).toBe("http://127.0.0.1:3141/execute");
		expect(result.success).toBe(true);
	});

	it("health returns true when status is ok", async () => {
		mockFetch.mockResolvedValueOnce({
			ok: true,
			json: () => Promise.resolve({ status: "ok", version: "0.1.0" }),
		});

		const client = new ExecutorClient({
			executorUrl: "http://127.0.0.1:3141",
			timeoutMs: 5000,
		});
		const healthy = await client.health();
		expect(healthy).toBe(true);
	});

	it("health returns false when server returns error", async () => {
		mockFetch.mockResolvedValueOnce({
			ok: false,
			status: 500,
			json: () => Promise.resolve({ error: "internal" }),
		});

		const client = new ExecutorClient({
			executorUrl: "http://127.0.0.1:3141",
			timeoutMs: 5000,
		});
		const healthy = await client.health();
		expect(healthy).toBe(false);
	});

	it("health returns false when server unreachable", async () => {
		mockFetch.mockRejectedValueOnce(new TypeError("fetch failed"));

		const client = new ExecutorClient({
			executorUrl: "http://127.0.0.1:1",
			timeoutMs: 1000,
		});
		const healthy = await client.health();
		expect(healthy).toBe(false);
	});

	it("includes auth token in header when provided", async () => {
		mockFetch.mockResolvedValueOnce({
			ok: true,
			json: () => Promise.resolve({ status: "ok", version: "0.1.0" }),
		});

		const client = new ExecutorClient({
			executorUrl: "http://127.0.0.1:3141",
			authToken: "test-token-123",
			timeoutMs: 5000,
		});
		await client.health();

		expect(mockFetch).toHaveBeenCalledOnce();
		const [, options] = mockFetch.mock.calls[0] as [string, RequestInit];
		const headers = options.headers as Record<string, string>;
		expect(headers.Authorization).toBe("Bearer test-token-123");
	});

	it("strips trailing slash from URL", async () => {
		mockFetch.mockResolvedValueOnce({
			ok: true,
			json: () => Promise.resolve({ status: "ok", version: "0.1.0" }),
		});

		const client = new ExecutorClient({
			executorUrl: "http://127.0.0.1:3141/",
			timeoutMs: 5000,
		});
		const healthy = await client.health();
		expect(healthy).toBe(true);

		const [url] = mockFetch.mock.calls[0] as [string, RequestInit];
		expect(url).toBe("http://127.0.0.1:3141/health");
	});
});
