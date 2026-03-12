import type { CredentialVault } from "./vault.js";

/**
 * Callback-scoped credential accessor that minimizes V8 string lifetime.
 *
 * Retrieves a credential as a Buffer, parses it, passes the parsed object to `fn`,
 * then deterministically zeroes the Buffer in `finally`. The parsed credential strings
 * become unreachable after `fn` returns — eligible for GC.
 *
 * Callbacks MUST NOT store credential values outside their scope.
 */
export async function useCredential<T>(
	vault: CredentialVault,
	serviceId: string,
	fn: (cred: Record<string, string>) => T | Promise<T>,
): Promise<T> {
	const buf = vault.retrieveBuffer(serviceId);
	try {
		const parsed: Record<string, string> = JSON.parse(buf.toString("utf8"));
		return await fn(parsed);
	} finally {
		buf.fill(0);
	}
}
