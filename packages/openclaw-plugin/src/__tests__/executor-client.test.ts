import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ExecutorClient } from "../executor-client.js";

let server: Server;
let port: number;
let lastPath: string;
let lastBody: string;
let responseStatus: number;
let responseBody: Record<string, unknown>;

function startServer(): Promise<number> {
	return new Promise((resolve) => {
		server = createServer((req: IncomingMessage, res: ServerResponse) => {
			lastPath = req.url ?? "";
			let body = "";
			req.on("data", (chunk: Buffer) => {
				body += chunk.toString();
			});
			req.on("end", () => {
				lastBody = body;
				res.writeHead(responseStatus, { "Content-Type": "application/json" });
				res.end(JSON.stringify(responseBody));
			});
		});
		server.listen(0, "127.0.0.1", () => {
			const addr = server.address();
			if (addr && typeof addr === "object") {
				resolve(addr.port);
			}
		});
	});
}

beforeEach(async () => {
	responseStatus = 200;
	responseBody = {};
	lastPath = "";
	lastBody = "";
	port = await startServer();
});

afterEach(() => {
	server.close();
});

describe("ExecutorClient", () => {
	it("sends classify request to /classify", async () => {
		responseBody = {
			decision: "auto_approve",
			category: "read",
			reason: "Read operation",
			manifestId: "00000000-0000-0000-0000-000000000001",
		};

		const client = new ExecutorClient({
			executorUrl: `http://127.0.0.1:${port}`,
			timeoutMs: 5000,
		});
		const result = await client.classify("read_file", { path: "/tmp" }, "agent-1", "session-1");
		expect(lastPath).toBe("/classify");
		expect(result.decision).toBe("auto_approve");
		const parsed = JSON.parse(lastBody);
		expect(parsed.source).toBe("openclaw");
	});

	it("sends filter request to /filter-output", async () => {
		responseBody = {
			filtered: "clean text",
			redacted: false,
			moderationFlagged: false,
			moderationBlocked: false,
		};

		const client = new ExecutorClient({
			executorUrl: `http://127.0.0.1:${port}`,
			timeoutMs: 5000,
		});
		const result = await client.filterOutput("clean text", "agent-1");
		expect(lastPath).toBe("/filter-output");
		expect(result.filtered).toBe("clean text");
	});

	it("sends execute request to /execute", async () => {
		responseBody = { success: true, manifestId: "test-id", output: "ok", duration_ms: 10 };

		const client = new ExecutorClient({
			executorUrl: `http://127.0.0.1:${port}`,
			timeoutMs: 5000,
		});
		const result = await client.execute({ tool: "bash", parameters: { command: "ls" } });
		expect(lastPath).toBe("/execute");
		expect(result.success).toBe(true);
	});

	it("health returns true when status is ok", async () => {
		responseBody = { status: "ok", version: "0.1.0" };

		const client = new ExecutorClient({
			executorUrl: `http://127.0.0.1:${port}`,
			timeoutMs: 5000,
		});
		const healthy = await client.health();
		expect(healthy).toBe(true);
	});

	it("health returns false when server returns error", async () => {
		responseStatus = 500;
		responseBody = { error: "internal" };

		const client = new ExecutorClient({
			executorUrl: `http://127.0.0.1:${port}`,
			timeoutMs: 5000,
		});
		const healthy = await client.health();
		expect(healthy).toBe(false);
	});

	it("health returns false when server unreachable", async () => {
		const client = new ExecutorClient({
			executorUrl: "http://127.0.0.1:1",
			timeoutMs: 1000,
		});
		const healthy = await client.health();
		expect(healthy).toBe(false);
	});

	it("includes auth token in header when provided", async () => {
		responseBody = { status: "ok", version: "0.1.0" };
		let authHeader: string | undefined;
		server.close();

		await new Promise<void>((resolve) => {
			server = createServer((req: IncomingMessage, res: ServerResponse) => {
				authHeader = req.headers.authorization;
				res.writeHead(200, { "Content-Type": "application/json" });
				res.end(JSON.stringify(responseBody));
			});
			server.listen(port, "127.0.0.1", () => resolve());
		});

		const client = new ExecutorClient({
			executorUrl: `http://127.0.0.1:${port}`,
			authToken: "test-token-123",
			timeoutMs: 5000,
		});
		await client.health();
		expect(authHeader).toBe("Bearer test-token-123");
	});

	it("strips trailing slash from URL", async () => {
		responseBody = { status: "ok", version: "0.1.0" };

		const client = new ExecutorClient({
			executorUrl: `http://127.0.0.1:${port}/`,
			timeoutMs: 5000,
		});
		const healthy = await client.health();
		expect(healthy).toBe(true);
		expect(lastPath).toBe("/health");
	});
});
