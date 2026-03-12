import type { CredentialVault } from "@sentinel/crypto";
import { useCredential } from "@sentinel/crypto";

/**
 * Retrieve a valid Google Workspace access token from the vault.
 * Refreshes via OAuth2 if the token is expired or expiring within 60s.
 */
export async function getGwsAccessToken(vault: CredentialVault): Promise<string> {
	return useCredential(vault, "google/oauth", async (creds) => {
		const expiresAt = Number(creds.expiresAt);
		if (expiresAt && Date.now() < expiresAt - 60_000) {
			return creds.accessToken;
		}

		// Token expired or expiring soon — refresh
		const body = new URLSearchParams({
			client_id: creds.clientId,
			client_secret: creds.clientSecret,
			refresh_token: creds.refreshToken,
			grant_type: "refresh_token",
		});

		const resp = await fetch("https://oauth2.googleapis.com/token", {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: body.toString(),
		});

		if (!resp.ok) {
			// Never include response body — may contain credential hints
			throw new Error(`OAuth token refresh failed: HTTP ${resp.status}`);
		}

		const data = (await resp.json()) as { access_token: string; expires_in: number };
		if (!data.access_token) {
			throw new Error("OAuth token refresh returned no access_token");
		}

		// Store updated token back to vault
		await vault.store("google/oauth", "oauth", {
			...creds,
			accessToken: data.access_token,
			expiresAt: String(Date.now() + data.expires_in * 1000),
		});

		return data.access_token;
	});
}
