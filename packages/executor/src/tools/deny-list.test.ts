import { describe, expect, it } from "vitest";
import { isDeniedPath } from "./deny-list.js";

describe("isDeniedPath", () => {
	it("denies .env files", () => {
		expect(isDeniedPath(".env")).toBe(true);
		expect(isDeniedPath(".env.local")).toBe(true);
	});

	it("denies .dev.vars", () => {
		expect(isDeniedPath(".dev.vars")).toBe(true);
	});

	it("denies .git/config and .git/credentials", () => {
		expect(isDeniedPath("/repo/.git/config")).toBe(true);
		expect(isDeniedPath("/repo/.git/credentials")).toBe(true);
	});

	it("denies .pem and .key files", () => {
		expect(isDeniedPath("server.pem")).toBe(true);
		expect(isDeniedPath("private.key")).toBe(true);
	});

	it("denies .enc extension (LOW-16)", () => {
		expect(isDeniedPath("/some/path/secrets.enc")).toBe(true);
		expect(isDeniedPath("/app/data/vault.enc")).toBe(true);
	});

	it("denies paths containing 'vault' (LOW-16)", () => {
		expect(isDeniedPath("/app/data/vault/keys")).toBe(true);
		expect(isDeniedPath("/app/Vault/config")).toBe(true);
	});

	it("denies paths containing 'secret' or 'credential'", () => {
		expect(isDeniedPath("/app/secrets/key.txt")).toBe(true);
		expect(isDeniedPath("/app/credentials/auth.json")).toBe(true);
	});

	it("allows normal files", () => {
		expect(isDeniedPath("/app/data/notes.txt")).toBe(false);
		expect(isDeniedPath("/app/data/config.json")).toBe(false);
		expect(isDeniedPath("/app/src/index.ts")).toBe(false);
	});
});
