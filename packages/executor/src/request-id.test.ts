import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { type RequestIdEnv, requestIdMiddleware } from "./request-id.js";

function createTestApp(): Hono<RequestIdEnv> {
	const app = new Hono<RequestIdEnv>();
	app.use("*", requestIdMiddleware);
	app.get("/test", (c) => {
		const requestId = c.get("requestId");
		return c.json({ requestId });
	});
	app.post("/execute", (c) => {
		const requestId = c.get("requestId");
		return c.json({ requestId });
	});
	return app;
}

describe("requestIdMiddleware", () => {
	it("sets X-Request-ID response header", async () => {
		const app = createTestApp();
		const res = await app.request("/test");
		const header = res.headers.get("X-Request-ID");
		expect(header).toBeTruthy();
		expect(header).toMatch(
			/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
		);
	});

	it("stores requestId in Hono context", async () => {
		const app = createTestApp();
		const res = await app.request("/test");
		const body = (await res.json()) as { requestId: string };
		expect(body.requestId).toMatch(
			/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
		);
	});

	it("context requestId matches X-Request-ID header", async () => {
		const app = createTestApp();
		const res = await app.request("/test");
		const header = res.headers.get("X-Request-ID");
		const body = (await res.json()) as { requestId: string };
		expect(header).toBe(body.requestId);
	});

	it("generates unique IDs per request", async () => {
		const app = createTestApp();
		const res1 = await app.request("/test");
		const res2 = await app.request("/test");
		const id1 = res1.headers.get("X-Request-ID");
		const id2 = res2.headers.get("X-Request-ID");
		expect(id1).not.toBe(id2);
	});

	it("works on POST routes", async () => {
		const app = createTestApp();
		const res = await app.request("/execute", { method: "POST" });
		const header = res.headers.get("X-Request-ID");
		expect(header).toBeTruthy();
		expect(header).toMatch(
			/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
		);
	});
});
