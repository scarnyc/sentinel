import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { PendingConfirmation } from "./confirmation-tui.js";

// Mock @clack/prompts before importing the module under test
vi.mock("@clack/prompts", () => ({
	confirm: vi.fn().mockResolvedValue(true),
	isCancel: vi.fn().mockReturnValue(false),
}));

const { startConfirmationPoller } = await import("./confirmation-tui.js");

const SAMPLE: PendingConfirmation = {
	manifestId: "poller-test-001",
	tool: "bash",
	parameters: { command: "ls" },
	category: "safe",
	reason: "Read-only",
};

const mockFetch = vi.fn();
const executorUrl = "http://localhost:9999";

beforeEach(() => {
	vi.stubGlobal("fetch", mockFetch);
	// Default: return empty pending list
	mockFetch.mockImplementation(async () => ({
		ok: true,
		status: 200,
		json: async () => [],
	}));
});

afterEach(() => {
	vi.unstubAllGlobals();
});

describe("startConfirmationPoller", () => {
	it("aborts cleanly when signal is already aborted", async () => {
		const ctrl = new AbortController();
		ctrl.abort();
		await expect(startConfirmationPoller(executorUrl, ctrl.signal)).resolves.toBeUndefined();
	});

	it("deduplicates confirmations by manifestId", async () => {
		const confirmCalls: string[] = [];

		mockFetch.mockImplementation(async (url: string) => {
			if (url.includes("/pending-confirmations")) {
				return {
					ok: true,
					status: 200,
					json: async () => [SAMPLE, SAMPLE],
				};
			}
			if (url.includes("/confirm/")) {
				const id = url.split("/confirm/")[1];
				confirmCalls.push(id);
				return {
					ok: true,
					status: 200,
					json: async () => ({ status: "approved" }),
				};
			}
			return { ok: false, status: 404 };
		});

		const ctrl = new AbortController();
		const promise = startConfirmationPoller(executorUrl, ctrl.signal);

		await new Promise((r) => setTimeout(r, 300));
		ctrl.abort();
		await promise;

		expect(confirmCalls.filter((id) => id === "poller-test-001")).toHaveLength(1);
	});

	it("handles non-ok poll response without crashing", async () => {
		const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});

		mockFetch.mockImplementation(async () => ({
			ok: false,
			status: 503,
		}));

		const ctrl = new AbortController();
		const promise = startConfirmationPoller(executorUrl, ctrl.signal);

		await new Promise((r) => setTimeout(r, 300));
		ctrl.abort();
		await promise;

		expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining("503"));
		consoleSpy.mockRestore();
	});

	it("handles invalid poll response format gracefully", async () => {
		const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});

		mockFetch.mockImplementation(async () => ({
			ok: true,
			status: 200,
			json: async () => ({ notAnArray: true }),
		}));

		const ctrl = new AbortController();
		const promise = startConfirmationPoller(executorUrl, ctrl.signal);

		await new Promise((r) => setTimeout(r, 300));
		ctrl.abort();
		await promise;

		expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining("Invalid poll response"));
		consoleSpy.mockRestore();
	});

	it("retries confirmation POST on failure by removing from seenIds", async () => {
		const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});
		let postAttempts = 0;

		mockFetch.mockImplementation(async (url: string) => {
			if (url.includes("/pending-confirmations")) {
				return {
					ok: true,
					status: 200,
					json: async () => [SAMPLE],
				};
			}
			if (url.includes("/confirm/")) {
				postAttempts++;
				if (postAttempts === 1) {
					throw new Error("Connection reset");
				}
				return {
					ok: true,
					status: 200,
					json: async () => ({ status: "approved" }),
				};
			}
			return { ok: false, status: 404 };
		});

		const ctrl = new AbortController();
		const promise = startConfirmationPoller(executorUrl, ctrl.signal);

		// Give enough time for two poll cycles
		await new Promise((r) => setTimeout(r, 1500));
		ctrl.abort();
		await promise;

		expect(postAttempts).toBeGreaterThanOrEqual(2);
		consoleSpy.mockRestore();
	});

	it("posts correct approval decision to executor", async () => {
		mockFetch.mockImplementation(async (url: string | URL | Request, _init?: RequestInit) => {
			const urlStr = String(url);
			if (urlStr.includes("/pending-confirmations")) {
				return {
					ok: true,
					status: 200,
					json: async () => [SAMPLE],
				};
			}
			if (urlStr.includes("/confirm/")) {
				return {
					ok: true,
					status: 200,
					json: async () => ({ status: "approved" }),
				};
			}
			return { ok: false, status: 404 };
		});

		const ctrl = new AbortController();
		const promise = startConfirmationPoller(executorUrl, ctrl.signal);

		await new Promise((r) => setTimeout(r, 300));
		ctrl.abort();
		await promise;

		// Find the confirm POST call and inspect its body
		const confirmCall = mockFetch.mock.calls.find((args: unknown[]) =>
			String(args[0]).includes("/confirm/"),
		);
		expect(confirmCall).toBeDefined();
		const init = (confirmCall as unknown[])[1] as RequestInit;
		const parsed = JSON.parse(init.body as string);
		expect(parsed).toEqual({ approved: true });
	});
});
