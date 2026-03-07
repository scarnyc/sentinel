import * as fs from "node:fs";
import * as path from "node:path";

export const PATH_PARAMS: Record<string, string> = {
	read: "path",
	read_file: "path",
	write: "path",
	write_file: "path",
	edit: "path",
	edit_file: "path",
	apply_patch: "path",
	exec: "cwd",
	bash: "cwd",
};

export function resolveAgentPath(targetPath: string, workspaceRoot: string): string {
	if (targetPath.startsWith("~/")) {
		return path.join(workspaceRoot, targetPath.slice(2));
	}
	if (targetPath === "~") {
		return workspaceRoot;
	}
	if (path.isAbsolute(targetPath)) {
		return targetPath;
	}
	return path.join(workspaceRoot, targetPath);
}

function startsWithDir(target: string, root: string): boolean {
	if (target === root) return true;
	// Avoid double-separator when root is "/" (filesystem root)
	const prefix = root.endsWith(path.sep) ? root : root + path.sep;
	return target.startsWith(prefix);
}

export function isWithinWorkspace(targetPath: string, workspaceRoot: string): boolean {
	const resolvedRoot = safeRealpath(workspaceRoot);
	if (!resolvedRoot) {
		// Workspace root doesn't exist on disk — fall back to normalized path comparison
		const normalRoot = path.resolve(workspaceRoot);
		const normalTarget = path.resolve(targetPath);
		return startsWithDir(normalTarget, normalRoot);
	}

	const resolvedTarget = safeRealpath(targetPath);
	if (resolvedTarget) {
		return startsWithDir(resolvedTarget, resolvedRoot);
	}

	// Path doesn't exist yet — check nearest existing ancestor
	let current = path.resolve(targetPath);
	while (current !== path.dirname(current)) {
		const parent = path.dirname(current);
		const resolvedParent = safeRealpath(parent);
		if (resolvedParent) {
			const remainder = path.relative(parent, path.resolve(targetPath));
			if (remainder.startsWith("..")) return false;
			const full = path.join(resolvedParent, remainder);
			return startsWithDir(full, resolvedRoot);
		}
		current = parent;
	}

	return false;
}

export function checkWorkspaceAccess(
	targetPath: string,
	workspaceRoot: string,
	access: "ro" | "rw",
	operation: "read" | "write",
): { allowed: boolean; reason?: string } {
	if (!isWithinWorkspace(targetPath, workspaceRoot)) {
		return { allowed: false, reason: `Path outside workspace: ${targetPath}` };
	}

	if (access === "ro" && operation === "write") {
		return { allowed: false, reason: "Write denied: read-only workspace" };
	}

	return { allowed: true };
}

function safeRealpath(p: string): string | null {
	try {
		return fs.realpathSync(p);
	} catch {
		return null;
	}
}

/**
 * Extract absolute paths from a bash command string.
 * Used to enforce workspace containment on bash commands,
 * since paths are embedded in the command rather than in named parameters.
 */
export function extractPathsFromCommand(command: string): string[] {
	const paths: string[] = [];
	// Match argument tokens that look like absolute paths (start with /)
	// Skip the first token (the command binary) — binaries like /usr/bin/rg
	// are always outside workspace but aren't file targets.
	const tokens = tokenizeCommand(command);
	for (let i = 1; i < tokens.length; i++) {
		const token = tokens[i];
		// Skip flags (e.g., -rf, --verbose)
		if (token.startsWith("-")) continue;
		if (token.startsWith("/") && !token.startsWith("//")) {
			paths.push(token);
		}
	}
	return paths;
}

/**
 * Simple shell tokenizer that splits on whitespace while respecting quotes.
 * Does not handle all shell edge cases, but catches the common patterns.
 */
function tokenizeCommand(command: string): string[] {
	const tokens: string[] = [];
	let current = "";
	let inSingle = false;
	let inDouble = false;

	for (let i = 0; i < command.length; i++) {
		const ch = command[i];

		if (ch === "'" && !inDouble) {
			inSingle = !inSingle;
		} else if (ch === '"' && !inSingle) {
			inDouble = !inDouble;
		} else if (/\s/.test(ch) && !inSingle && !inDouble) {
			if (current.length > 0) {
				tokens.push(current);
				current = "";
			}
		} else {
			current += ch;
		}
	}

	if (current.length > 0) {
		tokens.push(current);
	}

	return tokens;
}
