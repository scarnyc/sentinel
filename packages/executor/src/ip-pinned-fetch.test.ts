import { describe, expect, it, vi } from "vitest";

vi.mock("undici", () => {
	const mockAgent = { connect: {} };
	return {
		Agent: vi.fn().mockReturnValue(mockAgent),
		fetch: vi.fn().mockResolvedValue(new Response("{}", { status: 200 })),
	};
});

import { Agent, fetch as undiciFetch } from "undici";
import { createIpPinnedFetch } from "./ip-pinned-fetch.js";

describe("createIpPinnedFetch", () => {
	it("returns a callable function", () => {
		const pinnedFetch = createIpPinnedFetch("1.2.3.4", "api.anthropic.com");
		expect(typeof pinnedFetch).toBe("function");
	});

	it("creates Agent with correct connect options", () => {
		createIpPinnedFetch("93.184.216.34", "api.openai.com");
		expect(Agent).toHaveBeenCalledWith({
			connect: {
				host: "93.184.216.34",
				servername: "api.openai.com",
			},
		});
	});

	it("calls undici fetch with dispatcher agent", async () => {
		const pinnedFetch = createIpPinnedFetch("1.2.3.4", "api.anthropic.com");
		await pinnedFetch("https://api.anthropic.com/v1/messages", {
			method: "POST",
			headers: new Headers({ "Content-Type": "application/json" }),
		});

		expect(undiciFetch).toHaveBeenCalledOnce();
		const [url, opts] = (undiciFetch as ReturnType<typeof vi.fn>).mock.calls[0];
		expect(url).toBe("https://api.anthropic.com/v1/messages");
		expect(opts.method).toBe("POST");
		expect(opts.dispatcher).toBeDefined();
	});
});
