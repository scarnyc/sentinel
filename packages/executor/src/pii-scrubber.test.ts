import type { ToolResult } from "@sentinel/types";
import { describe, expect, it } from "vitest";
import { containsPII, scrubPII } from "./pii-scrubber.js";

function makeResult(output?: string, error?: string): ToolResult {
	return {
		manifestId: "test-id",
		success: !error,
		output,
		error,
		duration_ms: 0,
	};
}

describe("scrubPII", () => {
	it("redacts SSN from output", () => {
		const result = makeResult("SSN: 123-45-6789");
		const scrubbed = scrubPII(result);
		expect(scrubbed.output).not.toContain("123-45-6789");
		expect(scrubbed.output).toContain("[PII_REDACTED]");
	});

	it("redacts phone (XXX) XXX-XXXX from output", () => {
		const result = makeResult("Call (555) 123-4567");
		const scrubbed = scrubPII(result);
		expect(scrubbed.output).not.toContain("(555) 123-4567");
		expect(scrubbed.output).toContain("[PII_REDACTED]");
	});

	it("redacts phone XXX-XXX-XXXX from output", () => {
		const result = makeResult("Phone: 555-123-4567");
		const scrubbed = scrubPII(result);
		expect(scrubbed.output).not.toContain("555-123-4567");
		expect(scrubbed.output).toContain("[PII_REDACTED]");
	});

	it("redacts email address from output", () => {
		const result = makeResult("Contact: user@example.com");
		const scrubbed = scrubPII(result);
		expect(scrubbed.output).not.toContain("user@example.com");
		expect(scrubbed.output).toContain("[PII_REDACTED]");
	});

	it("redacts salary $150,000 from output", () => {
		const result = makeResult("Expected: $150,000");
		const scrubbed = scrubPII(result);
		expect(scrubbed.output).not.toContain("$150,000");
		expect(scrubbed.output).toContain("[PII_REDACTED]");
	});

	it("redacts salary shorthand $85K from output", () => {
		const result = makeResult("Range: $85K");
		const scrubbed = scrubPII(result);
		expect(scrubbed.output).not.toContain("$85K");
		expect(scrubbed.output).toContain("[PII_REDACTED]");
	});

	it("redacts LinkedIn URL from output", () => {
		const result = makeResult("Profile: https://linkedin.com/in/johndoe");
		const scrubbed = scrubPII(result);
		expect(scrubbed.output).not.toContain("linkedin.com/in/johndoe");
		expect(scrubbed.output).toContain("[PII_REDACTED]");
	});

	it("redacts GitHub profile URL from output", () => {
		const result = makeResult("Code: https://github.com/johndoe");
		const scrubbed = scrubPII(result);
		expect(scrubbed.output).not.toContain("github.com/johndoe");
		expect(scrubbed.output).toContain("[PII_REDACTED]");
	});

	it("redacts multiple PII types in one string", () => {
		const result = makeResult("SSN: 123-45-6789, Email: test@example.com, Phone: (555) 123-4567");
		const scrubbed = scrubPII(result);
		expect(scrubbed.output).not.toContain("123-45-6789");
		expect(scrubbed.output).not.toContain("test@example.com");
		expect(scrubbed.output).not.toContain("(555) 123-4567");
		expect(scrubbed.output).toContain("[PII_REDACTED]");
	});

	it("passes through output without PII unchanged", () => {
		const result = makeResult("hello world, no PII here");
		const scrubbed = scrubPII(result);
		expect(scrubbed.output).toBe("hello world, no PII here");
	});

	it("redacts PII in error field", () => {
		const result = makeResult(undefined, "Error for user@example.com");
		const scrubbed = scrubPII(result);
		expect(scrubbed.error).not.toContain("user@example.com");
		expect(scrubbed.error).toContain("[PII_REDACTED]");
	});

	it("preserves undefined output and error", () => {
		const result = makeResult(undefined, undefined);
		const scrubbed = scrubPII(result);
		expect(scrubbed.output).toBeUndefined();
		expect(scrubbed.error).toBeUndefined();
	});

	it("preserves other ToolResult fields", () => {
		const result = makeResult("clean output");
		const scrubbed = scrubPII(result);
		expect(scrubbed.manifestId).toBe("test-id");
		expect(scrubbed.success).toBe(true);
		expect(scrubbed.duration_ms).toBe(0);
	});
});

describe("containsPII", () => {
	it("returns true when text contains SSN", () => {
		expect(containsPII("SSN: 123-45-6789")).toBe(true);
	});

	it("returns true when text contains email", () => {
		expect(containsPII("contact user@example.com")).toBe(true);
	});

	it("returns true when text contains phone", () => {
		expect(containsPII("call (555) 123-4567")).toBe(true);
	});

	it("returns false when text has no PII", () => {
		expect(containsPII("hello world, no PII here")).toBe(false);
	});

	it("returns false for empty string", () => {
		expect(containsPII("")).toBe(false);
	});
});
