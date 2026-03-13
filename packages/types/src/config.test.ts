import { describe, expect, it } from "vitest";
import { GwsIntegrityConfigSchema } from "./config.js";

describe("GwsIntegrityConfigSchema", () => {
	it("defaults gwsDefaultDeny to false when not provided", () => {
		const result = GwsIntegrityConfigSchema.parse({});
		expect(result.gwsDefaultDeny).toBe(false);
	});

	it("accepts gwsDefaultDeny: true", () => {
		const result = GwsIntegrityConfigSchema.parse({ gwsDefaultDeny: true });
		expect(result.gwsDefaultDeny).toBe(true);
	});

	it("accepts gwsDefaultDeny: false explicitly", () => {
		const result = GwsIntegrityConfigSchema.parse({ gwsDefaultDeny: false });
		expect(result.gwsDefaultDeny).toBe(false);
	});

	it("preserves other fields alongside gwsDefaultDeny", () => {
		const result = GwsIntegrityConfigSchema.parse({
			verifyBinary: true,
			expectedSha256: "a".repeat(64),
			gwsDefaultDeny: true,
		});
		expect(result.verifyBinary).toBe(true);
		expect(result.expectedSha256).toBe("a".repeat(64));
		expect(result.gwsDefaultDeny).toBe(true);
	});
});
