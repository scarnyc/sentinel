import { afterEach, describe, expect, it, vi } from "vitest";
import { loadConfigFromEnv } from "../config.js";

describe("loadConfigFromEnv", () => {
	afterEach(() => {
		vi.unstubAllEnvs();
		vi.restoreAllMocks();
	});

	it("defaults failMode to 'closed'", () => {
		const config = loadConfigFromEnv();
		expect(config.failMode).toBe("closed");
	});

	it("overrides failMode='open' to 'closed' when SENTINEL_DOCKER=true", () => {
		const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
		vi.stubEnv("SENTINEL_DOCKER", "true");
		vi.stubEnv("SENTINEL_FAIL_MODE", "open");

		const config = loadConfigFromEnv();

		expect(config.failMode).toBe("closed");
		expect(warnSpy).toHaveBeenCalledWith(
			"[openclaw-plugin] failMode='open' overridden to 'closed' in Docker mode",
		);
	});

	it("allows failMode='open' when not in Docker mode", () => {
		vi.stubEnv("SENTINEL_FAIL_MODE", "open");

		const config = loadConfigFromEnv();

		expect(config.failMode).toBe("open");
	});

	it("keeps failMode='closed' in Docker mode without override", () => {
		const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
		vi.stubEnv("SENTINEL_DOCKER", "true");
		vi.stubEnv("SENTINEL_FAIL_MODE", "closed");

		const config = loadConfigFromEnv();

		expect(config.failMode).toBe("closed");
		expect(warnSpy).not.toHaveBeenCalled();
	});
});
