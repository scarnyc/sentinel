import { describe, expect, it } from "vitest";
import { ActionManifestSchema } from "./manifest.js";

const base = { sessionId: "s1", agentId: "a1", parameters: {} };

describe("ActionManifestSchema tool validation", () => {
	it("accepts standard tool names", () => {
		expect(() => ActionManifestSchema.parse({ ...base, tool: "bash" })).not.toThrow();
		expect(() => ActionManifestSchema.parse({ ...base, tool: "read_file" })).not.toThrow();
		expect(() => ActionManifestSchema.parse({ ...base, tool: "gws" })).not.toThrow();
	});

	it("accepts MCP tool names with double underscores", () => {
		expect(() =>
			ActionManifestSchema.parse({ ...base, tool: "mcp__slack__send_message" }),
		).not.toThrow();
	});

	it("accepts tool names with dots and hyphens", () => {
		expect(() => ActionManifestSchema.parse({ ...base, tool: "my-tool.v2" })).not.toThrow();
	});

	it("rejects tool names longer than 256 chars", () => {
		expect(() => ActionManifestSchema.parse({ ...base, tool: "a".repeat(257) })).toThrow();
	});

	it("rejects tool names with special characters", () => {
		expect(() => ActionManifestSchema.parse({ ...base, tool: "tool;rm -rf" })).toThrow();
		expect(() => ActionManifestSchema.parse({ ...base, tool: "../../path" })).toThrow();
	});

	it("rejects tool names starting with a number", () => {
		expect(() => ActionManifestSchema.parse({ ...base, tool: "123tool" })).toThrow();
	});

	it("rejects empty tool names", () => {
		expect(() => ActionManifestSchema.parse({ ...base, tool: "" })).toThrow();
	});

	it("rejects tool names with spaces", () => {
		expect(() => ActionManifestSchema.parse({ ...base, tool: "my tool" })).toThrow();
	});
});
