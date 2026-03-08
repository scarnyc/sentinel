import { describe, expect, it } from "vitest";
import { getDefaultConfig, validateConfig } from "./rules.js";

describe("validateConfig", () => {
	it("accepts valid config", () => {
		const config = getDefaultConfig();
		const result = validateConfig(config);
		expect(result.executor.port).toBe(3141);
		expect(result.classifications.length).toBeGreaterThan(0);
	});

	it("throws ZodError on empty object", () => {
		expect(() => validateConfig({})).toThrow();
	});

	it("throws on empty classifications array", () => {
		const config = {
			...getDefaultConfig(),
			classifications: [],
		};
		expect(() => validateConfig(config)).toThrow("at least one tool classification");
	});

	it("throws ZodError on missing auditLogPath", () => {
		const config = getDefaultConfig();
		const { auditLogPath, ...incomplete } = config;
		expect(() => validateConfig(incomplete)).toThrow();
	});

	it("throws ZodError on invalid port", () => {
		const config = getDefaultConfig();
		const invalid = { ...config, executor: { ...config.executor, port: -1 } };
		expect(() => validateConfig(invalid)).toThrow();
	});
});
