import { realpath } from "node:fs/promises";
import { resolve } from "node:path";

/**
 * Check if a file path is within one of the allowed root directories.
 * Uses realpath to resolve symlinks (defense against symlink-based traversal).
 * If allowedRoots is undefined or empty, all paths are allowed.
 */
export async function isPathAllowed(
	filePath: string,
	allowedRoots: readonly string[] | undefined,
): Promise<{ allowed: boolean; resolved: string; reason?: string }> {
	if (!allowedRoots || allowedRoots.length === 0) {
		return { allowed: true, resolved: resolve(filePath) };
	}

	// Resolve symlinks; fall back to lexical resolve for new paths
	const resolved = await realpath(resolve(filePath)).catch(() => resolve(filePath));

	for (const root of allowedRoots) {
		const resolvedRoot = await realpath(resolve(root)).catch(() => resolve(root));
		if (resolved === resolvedRoot || resolved.startsWith(`${resolvedRoot}/`)) {
			return { allowed: true, resolved };
		}
	}

	return {
		allowed: false,
		resolved,
		reason: "Path outside allowed roots",
	};
}
