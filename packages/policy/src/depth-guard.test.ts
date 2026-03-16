import { describe, expect, it } from "vitest";
import { DepthGuard } from "./depth-guard.js";

describe("DepthGuard", () => {
	it("allows root agent (no parentAgentId, depth 0)", () => {
		const guard = new DepthGuard();
		const result = guard.check("agent-root");
		expect(result.allowed).toBe(true);
		expect(result.depth).toBe(0);
		expect(result.reason).toBeUndefined();
	});

	it("allows agent within limit (depth 4, max 5)", () => {
		const guard = new DepthGuard({ maxDepth: 5 });
		const result = guard.check("agent-child", "agent-parent", 4);
		expect(result.allowed).toBe(true);
		expect(result.depth).toBe(4);
	});

	it("blocks agent at max depth (depth 5, max 5)", () => {
		const guard = new DepthGuard({ maxDepth: 5 });
		const result = guard.check("agent-deep", "agent-parent", 5);
		expect(result.allowed).toBe(false);
		expect(result.depth).toBe(5);
		expect(result.reason).toBeDefined();
	});

	it("blocks agent exceeding max depth", () => {
		const guard = new DepthGuard({ maxDepth: 5 });
		const result = guard.check("agent-too-deep", "agent-parent", 7);
		expect(result.allowed).toBe(false);
		expect(result.depth).toBe(7);
		expect(result.reason).toBeDefined();
	});

	it("tracks depth via parentAgentId chain", () => {
		const guard = new DepthGuard();
		// A is root
		const rA = guard.check("agent-A");
		expect(rA.allowed).toBe(true);
		expect(rA.depth).toBe(0);

		// B is child of A → depth 1
		const rB = guard.check("agent-B", "agent-A");
		expect(rB.allowed).toBe(true);
		expect(rB.depth).toBe(1);

		// C is child of B → depth 2
		const rC = guard.check("agent-C", "agent-B");
		expect(rC.allowed).toBe(true);
		expect(rC.depth).toBe(2);
	});

	it("returns descriptive block reason", () => {
		const guard = new DepthGuard({ maxDepth: 2 });
		guard.check("agent-A");
		guard.check("agent-B", "agent-A");
		const result = guard.check("agent-C", "agent-B");
		expect(result.allowed).toBe(false);
		expect(result.reason).toContain("agent-C");
		expect(result.reason).toContain("2");
	});

	it("independent agent trees don't interfere", () => {
		const guard = new DepthGuard({ maxDepth: 3 });

		// Tree 1: A → B → C (depth 2)
		guard.check("A");
		guard.check("B", "A");
		const rC = guard.check("C", "B");
		expect(rC.allowed).toBe(true);
		expect(rC.depth).toBe(2);

		// Tree 2: X → Y (depth 1)
		guard.check("X");
		const rY = guard.check("Y", "X");
		expect(rY.allowed).toBe(true);
		expect(rY.depth).toBe(1);
	});

	it("missing depth + missing parentAgentId → depth 0 (root)", () => {
		const guard = new DepthGuard();
		const result = guard.check("agent-orphan", undefined, undefined);
		expect(result.allowed).toBe(true);
		expect(result.depth).toBe(0);
	});

	it("cycle detection (A→B→A) → fail-safe block", () => {
		const guard = new DepthGuard({ maxDepth: 5 });
		// Register A as child of B
		guard.check("agent-A", "agent-B");
		// Register B as child of A — creates cycle
		const result = guard.check("agent-B", "agent-A");
		expect(result.allowed).toBe(false);
		expect(result.depth).toBe(-1);
		expect(result.reason).toContain("Cycle detected");
	});

	it("LRU eviction at maxAgents (default 1000)", () => {
		const guard = new DepthGuard({ maxAgents: 3 });

		guard.check("agent-1");
		guard.check("agent-2", "agent-1");
		guard.check("agent-3", "agent-2");
		// This should evict agent-1 (oldest)
		guard.check("agent-4", "agent-3");

		// agent-1 is evicted — re-registering as root should work fresh
		const result = guard.check("agent-1");
		expect(result.allowed).toBe(true);
		expect(result.depth).toBe(0);
	});

	it("reset() clears all state", () => {
		const guard = new DepthGuard({ maxDepth: 3 });
		guard.check("A");
		guard.check("B", "A");
		guard.check("C", "B");

		guard.reset();

		// C should now be a root agent (no parent chain)
		const result = guard.check("C");
		expect(result.allowed).toBe(true);
		expect(result.depth).toBe(0);
	});

	it("reset(agentId) clears only that agent", () => {
		const guard = new DepthGuard();
		guard.check("A");
		guard.check("B", "A");

		guard.reset("B");

		// A still registered as root
		const rA = guard.check("A");
		expect(rA.depth).toBe(0);

		// B is now fresh — treated as root
		const rB = guard.check("B");
		expect(rB.depth).toBe(0);
	});

	it("configurable maxDepth, defaults to 5", () => {
		const defaultGuard = new DepthGuard();
		// Depth 4 → allowed
		const r4 = defaultGuard.check("d4", "parent", 4);
		expect(r4.allowed).toBe(true);

		// Depth 5 → blocked (>= maxDepth of 5)
		const r5 = defaultGuard.check("d5", "parent2", 5);
		expect(r5.allowed).toBe(false);

		// Custom maxDepth of 10
		const customGuard = new DepthGuard({ maxDepth: 10 });
		const r9 = customGuard.check("d9", "parent", 9);
		expect(r9.allowed).toBe(true);

		const r10 = customGuard.check("d10", "parent2", 10);
		expect(r10.allowed).toBe(false);
	});

	it("rejects maxDepth < 1 in constructor", () => {
		expect(() => new DepthGuard({ maxDepth: 0 })).toThrow();
		expect(() => new DepthGuard({ maxDepth: -1 })).toThrow();
	});
});
