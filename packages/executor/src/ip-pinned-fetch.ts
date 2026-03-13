import { Agent, fetch as undiciFetch } from "undici";

/** Creates a fetch function that pins TCP connections to a pre-resolved IP address.
 *  TLS SNI still uses the original hostname for certificate validation. */
export function createIpPinnedFetch(pinnedIp: string, hostname: string) {
	const agent = new Agent({
		connect: {
			host: pinnedIp,
			servername: hostname,
		},
	});
	return (url: string | URL, init?: RequestInit) =>
		undiciFetch(url, { ...init, dispatcher: agent } as Parameters<typeof undiciFetch>[1]);
}
