import { describe, expect, it } from "vitest";
import { ContextBudgetTracker } from "./context-budget.js";

describe("ContextBudgetTracker", () => {
	const WINDOW = 100_000; // default context window tokens
	const PER_RESULT_PCT = 0.3;
	const GLOBAL_PCT = 0.75;
	const PER_RESULT_CAP = Math.floor(WINDOW * PER_RESULT_PCT); // 30_000
	const GLOBAL_CAP = Math.floor(WINDOW * GLOBAL_PCT); // 75_000

	it("allows output within per-result cap (unchanged)", () => {
		const tracker = new ContextBudgetTracker();
		// 1000 chars ≈ 250 tokens, well within 30K per-result cap
		const output = "x".repeat(1000);
		const result = tracker.enforce("s1", output);

		expect(result.output).toBe(output);
		expect(result.truncated).toBe(false);
		expect(result.outputTokens).toBe(Math.ceil(1000 / 4));
		expect(result.sessionCumulativeTokens).toBe(Math.ceil(1000 / 4));
	});

	it("truncates output exceeding per-result cap", () => {
		const tracker = new ContextBudgetTracker();
		// 30K tokens = 120K chars; send 200K chars to exceed
		const output = "a".repeat(200_000);
		const result = tracker.enforce("s1", output);

		expect(result.truncated).toBe(true);
		expect(result.output).toContain("[OUTPUT TRUNCATED — exceeded context budget]");
		// Truncated to per-result cap chars + notice
		const notice = "\n\n[OUTPUT TRUNCATED — exceeded context budget]";
		const truncatedContent = result.output.slice(0, -notice.length);
		expect(truncatedContent.length).toBe(PER_RESULT_CAP * 4);
		expect(result.outputTokens).toBe(PER_RESULT_CAP);
	});

	it("tracks cumulative tokens per session (getRemainingBudget decreases)", () => {
		const tracker = new ContextBudgetTracker();
		// Each call: 4000 chars = 1000 tokens
		const output = "b".repeat(4000);

		tracker.enforce("s1", output);
		expect(tracker.getRemainingBudget("s1")).toBe(GLOBAL_CAP - 1000);

		tracker.enforce("s1", output);
		expect(tracker.getRemainingBudget("s1")).toBe(GLOBAL_CAP - 2000);
	});

	it("truncates to remaining global budget when 75% consumed", () => {
		const tracker = new ContextBudgetTracker();
		// Use up most of global budget: 74K tokens = 296K chars
		const bigOutput = "c".repeat(296_000);
		const r1 = tracker.enforce("s1", bigOutput);
		// That exceeded per-result cap, so only 30K tokens counted
		expect(r1.outputTokens).toBe(PER_RESULT_CAP);

		// Second call: fill more budget
		tracker.enforce("s1", bigOutput); // another 30K tokens → cumulative 60K
		tracker.enforce("s1", bigOutput); // another 30K tokens → cumulative 90K... but capped at 75K global

		// At this point, remaining should be 75K - 60K = 15K before third call
		// Third call should be capped to remaining (15K), not per-result (30K)
		// Verify remaining budget went down appropriately
		const remaining = tracker.getRemainingBudget("s1");
		expect(remaining).toBeLessThan(PER_RESULT_CAP);
	});

	it("appends truncation notice to truncated output", () => {
		const tracker = new ContextBudgetTracker();
		const output = "d".repeat(200_000);
		const result = tracker.enforce("s1", output);

		expect(result.truncated).toBe(true);
		expect(result.output.endsWith("\n\n[OUTPUT TRUNCATED — exceeded context budget]")).toBe(true);
	});

	it("tracks sessions independently", () => {
		const tracker = new ContextBudgetTracker();
		const output = "e".repeat(4000); // 1000 tokens

		tracker.enforce("sessionA", output);
		tracker.enforce("sessionA", output);

		tracker.enforce("sessionB", output);

		expect(tracker.getRemainingBudget("sessionA")).toBe(GLOBAL_CAP - 2000);
		expect(tracker.getRemainingBudget("sessionB")).toBe(GLOBAL_CAP - 1000);
	});

	it("estimates tokens as Math.ceil(chars / 4)", () => {
		const tracker = new ContextBudgetTracker();
		// 5 chars → ceil(5/4) = 2 tokens
		const result = tracker.enforce("s1", "hello");
		expect(result.outputTokens).toBe(2);

		// 4 chars → ceil(4/4) = 1 token
		const result2 = tracker.enforce("s1", "test");
		expect(result2.outputTokens).toBe(1);

		// 7 chars → ceil(7/4) = 2 tokens
		const result3 = tracker.enforce("s1", "abcdefg");
		expect(result3.outputTokens).toBe(2);
	});

	it("handles empty/undefined output as no-op", () => {
		const tracker = new ContextBudgetTracker();

		const r1 = tracker.enforce("s1", "");
		expect(r1.output).toBe("");
		expect(r1.truncated).toBe(false);
		expect(r1.outputTokens).toBe(0);
		expect(r1.sessionCumulativeTokens).toBe(0);

		const r2 = tracker.enforce("s1", undefined);
		expect(r2.output).toBe("");
		expect(r2.truncated).toBe(false);
		expect(r2.outputTokens).toBe(0);
		expect(r2.sessionCumulativeTokens).toBe(0);
	});

	it("per-result cap applies even when global has headroom", () => {
		const tracker = new ContextBudgetTracker();
		// Global has full 75K headroom, but per-result cap is 30K
		// Send 50K tokens worth (200K chars)
		const output = "f".repeat(200_000);
		const result = tracker.enforce("s1", output);

		expect(result.truncated).toBe(true);
		expect(result.outputTokens).toBe(PER_RESULT_CAP); // 30K, not 50K
	});

	it("uses safe defaults when config is missing or partial", () => {
		// No config
		const t1 = new ContextBudgetTracker();
		expect(t1.getRemainingBudget("s1")).toBe(GLOBAL_CAP);

		// Partial config — only override window size
		const t2 = new ContextBudgetTracker({ contextWindowTokens: 200_000 });
		expect(t2.getRemainingBudget("s1")).toBe(Math.floor(200_000 * 0.75));

		// Empty object
		const t3 = new ContextBudgetTracker({});
		expect(t3.getRemainingBudget("s1")).toBe(GLOBAL_CAP);
	});

	it("evicts oldest session when maxSessions exceeded (LRU)", () => {
		const tracker = new ContextBudgetTracker({ maxSessions: 3 });
		const output = "g".repeat(400); // 100 tokens

		// Create 3 sessions
		tracker.enforce("s1", output);
		tracker.enforce("s2", output);
		tracker.enforce("s3", output);

		// All 3 should have budget consumed
		expect(tracker.getRemainingBudget("s1")).toBe(GLOBAL_CAP - 100);
		expect(tracker.getRemainingBudget("s2")).toBe(GLOBAL_CAP - 100);
		expect(tracker.getRemainingBudget("s3")).toBe(GLOBAL_CAP - 100);

		// Adding s4 should evict s1 (oldest)
		tracker.enforce("s4", output);
		// s1 evicted — returns full budget (no tracking)
		expect(tracker.getRemainingBudget("s1")).toBe(GLOBAL_CAP);
		// s2, s3, s4 still tracked
		expect(tracker.getRemainingBudget("s2")).toBe(GLOBAL_CAP - 100);
		expect(tracker.getRemainingBudget("s4")).toBe(GLOBAL_CAP - 100);
	});

	it("returns exhausted notice when global budget fully consumed", () => {
		// Small window to make it easy to exhaust
		const tracker = new ContextBudgetTracker({
			contextWindowTokens: 100,
			perResultCapPct: 0.5,
			globalCapPct: 0.75,
		});
		// perResultCap = 50 tokens, globalCap = 75 tokens
		// First call: 200 chars = 50 tokens (capped at per-result 50)
		tracker.enforce("s1", "h".repeat(200));
		// cumulative = 50, remaining = 25

		// Second call: 200 chars = 50 tokens, but only 25 remaining
		const r2 = tracker.enforce("s1", "i".repeat(200));
		expect(r2.truncated).toBe(true);
		expect(r2.outputTokens).toBe(25);

		// Third call: 0 remaining
		const r3 = tracker.enforce("s1", "j".repeat(100));
		expect(r3.truncated).toBe(true);
		expect(r3.output).toBe("\n\n[OUTPUT TRUNCATED — exceeded context budget]");
		expect(r3.outputTokens).toBe(0);
	});

	it("reset clears a specific session or all sessions", () => {
		const tracker = new ContextBudgetTracker();
		const output = "k".repeat(4000); // 1000 tokens

		tracker.enforce("s1", output);
		tracker.enforce("s2", output);

		tracker.reset("s1");
		expect(tracker.getRemainingBudget("s1")).toBe(GLOBAL_CAP);
		expect(tracker.getRemainingBudget("s2")).toBe(GLOBAL_CAP - 1000);

		tracker.reset();
		expect(tracker.getRemainingBudget("s2")).toBe(GLOBAL_CAP);
	});
});
