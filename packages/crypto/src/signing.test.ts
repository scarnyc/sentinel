import { describe, expect, it } from "vitest";
import { generateKeyPair, sign, verify } from "./signing.js";

describe("Ed25519 manifest signing", () => {
	it("sign/verify roundtrip — sign data, verify returns true", () => {
		const { publicKey, privateKey } = generateKeyPair();
		const data = "manifest-hash-abc123def456";

		const signature = sign(data, privateKey);
		const valid = verify(data, signature, publicKey);

		expect(valid).toBe(true);
		expect(typeof signature).toBe("string");
		// Ed25519 signature is 64 bytes = 128 hex chars
		expect(signature).toMatch(/^[0-9a-f]{128}$/);
	});

	it("tampered data fails verification", () => {
		const { publicKey, privateKey } = generateKeyPair();
		const data = "original-manifest-data";

		const signature = sign(data, privateKey);
		const valid = verify("tampered-manifest-data", signature, publicKey);

		expect(valid).toBe(false);
	});

	it("wrong key fails verification", () => {
		const keyPair1 = generateKeyPair();
		const keyPair2 = generateKeyPair();
		const data = "manifest-hash-xyz";

		const signature = sign(data, keyPair1.privateKey);
		const valid = verify(data, signature, keyPair2.publicKey);

		expect(valid).toBe(false);
	});
});
