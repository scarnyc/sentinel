import {
	createPrivateKey,
	createPublicKey,
	sign as cryptoSign,
	verify as cryptoVerify,
	generateKeyPairSync,
} from "node:crypto";

export class SigningError extends Error {
	constructor(
		message: string,
		public readonly cause?: unknown,
	) {
		super(message);
		this.name = "SigningError";
	}
}

/**
 * Generate an Ed25519 key pair for audit entry signing.
 */
export function generateKeyPair(): { publicKey: Buffer; privateKey: Buffer } {
	try {
		const { publicKey, privateKey } = generateKeyPairSync("ed25519", {
			publicKeyEncoding: { type: "spki", format: "der" },
			privateKeyEncoding: { type: "pkcs8", format: "der" },
		});
		return { publicKey: Buffer.from(publicKey), privateKey: Buffer.from(privateKey) };
	} catch (err) {
		throw new SigningError(
			`Ed25519 key generation failed: ${err instanceof Error ? err.message : String(err)}`,
			err,
		);
	}
}

/**
 * Sign data with an Ed25519 private key. Returns hex-encoded signature.
 */
export function sign(data: string, privateKey: Buffer): string {
	try {
		const key = createPrivateKey({ key: privateKey, format: "der", type: "pkcs8" });
		const signature = cryptoSign(null, Buffer.from(data), key);
		return signature.toString("hex");
	} catch (err) {
		throw new SigningError(
			`Ed25519 signing failed: ${err instanceof Error ? err.message : String(err)}`,
			err,
		);
	}
}

const HEX_PATTERN = /^[0-9a-f]*$/;

/**
 * Verify an Ed25519 signature. Expects hex-encoded signature string. Returns true if valid.
 */
export function verify(data: string, signature: string, publicKey: Buffer): boolean {
	if (!HEX_PATTERN.test(signature)) {
		throw new SigningError("Invalid signature format: expected hex string");
	}
	try {
		const key = createPublicKey({ key: publicKey, format: "der", type: "spki" });
		return cryptoVerify(null, Buffer.from(data), key, Buffer.from(signature, "hex"));
	} catch (err) {
		throw new SigningError(
			`Ed25519 verification failed: ${err instanceof Error ? err.message : String(err)}`,
			err,
		);
	}
}
