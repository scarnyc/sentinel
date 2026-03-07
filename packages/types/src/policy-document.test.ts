import { describe, expect, it } from "vitest";
import { PolicyDocumentSchema } from "./policy-document.js";

const VALID_POLICY = {
	version: 1,
	toolGroups: {
		fs: ["read", "write", "edit", "apply_patch"],
		runtime: ["exec", "process"],
	},
	defaults: {
		tools: { allow: ["*"], deny: ["group:network"] },
		workspace: { root: "~/.openclaw/workspace", access: "rw" },
		approval: { ask: "on-miss" },
	},
	agents: {
		main: {
			tools: { allow: ["group:fs"], deny: [] },
			workspace: { root: "~/Code", access: "rw" },
			approval: {
				ask: "on-miss",
				allowlist: [{ pattern: "/opt/homebrew/bin/rg" }],
			},
		},
	},
};

describe("PolicyDocumentSchema", () => {
	it("accepts a valid policy document", () => {
		const result = PolicyDocumentSchema.safeParse(VALID_POLICY);
		expect(result.success).toBe(true);
	});

	it("rejects unknown version", () => {
		const result = PolicyDocumentSchema.safeParse({ ...VALID_POLICY, version: 2 });
		expect(result.success).toBe(false);
	});

	it("rejects missing defaults", () => {
		const { defaults: _, ...noDefaults } = VALID_POLICY;
		const result = PolicyDocumentSchema.safeParse(noDefaults);
		expect(result.success).toBe(false);
	});

	it("rejects empty workspace root", () => {
		const bad = structuredClone(VALID_POLICY);
		bad.defaults.workspace.root = "";
		const result = PolicyDocumentSchema.safeParse(bad);
		expect(result.success).toBe(false);
	});

	it("rejects invalid access mode", () => {
		const bad = structuredClone(VALID_POLICY);
		(bad.defaults.workspace as any).access = "execute";
		const result = PolicyDocumentSchema.safeParse(bad);
		expect(result.success).toBe(false);
	});

	it("rejects invalid ask mode", () => {
		const bad = structuredClone(VALID_POLICY);
		(bad.defaults.approval as any).ask = "sometimes";
		const result = PolicyDocumentSchema.safeParse(bad);
		expect(result.success).toBe(false);
	});

	it("accepts agent without optional fields (inherits from defaults)", () => {
		const policy = structuredClone(VALID_POLICY) as Record<string, any>;
		policy.agents.minimal = {
			tools: { allow: ["read"] },
			workspace: { root: "~/minimal", access: "ro" },
		};
		const result = PolicyDocumentSchema.safeParse(policy);
		expect(result.success).toBe(true);
	});

	it("accepts agent with empty allowlist", () => {
		const policy = structuredClone(VALID_POLICY);
		policy.agents.main.approval = { ask: "always", allowlist: [] };
		const result = PolicyDocumentSchema.safeParse(policy);
		expect(result.success).toBe(true);
	});

	it("rejects empty allowlist pattern", () => {
		const policy = structuredClone(VALID_POLICY);
		policy.agents.main.approval = { ask: "on-miss", allowlist: [{ pattern: "" }] };
		const result = PolicyDocumentSchema.safeParse(policy);
		expect(result.success).toBe(false);
	});

	it("accepts empty agents map", () => {
		const policy = { ...VALID_POLICY, agents: {} };
		const result = PolicyDocumentSchema.safeParse(policy);
		expect(result.success).toBe(true);
	});
});
