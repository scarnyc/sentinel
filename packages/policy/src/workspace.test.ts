import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	checkWorkspaceAccess,
	extractPathsFromCommand,
	isWithinWorkspace,
	resolveAgentPath,
} from "./workspace.js";

describe("resolveAgentPath", () => {
	it("expands ~ to workspace root, not $HOME", () => {
		const result = resolveAgentPath("~/foo/bar.txt", "/workspace/agent-a");
		expect(result).toBe("/workspace/agent-a/foo/bar.txt");
	});

	it("resolves relative paths against workspace root", () => {
		const result = resolveAgentPath("src/index.ts", "/workspace/agent-a");
		expect(result).toBe("/workspace/agent-a/src/index.ts");
	});

	it("keeps absolute paths as-is", () => {
		const result = resolveAgentPath("/etc/passwd", "/workspace/agent-a");
		expect(result).toBe("/etc/passwd");
	});
});

describe("isWithinWorkspace", () => {
	let tmpDir: string;

	beforeEach(() => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-ws-test-"));
		fs.mkdirSync(path.join(tmpDir, "sub"), { recursive: true });
		fs.writeFileSync(path.join(tmpDir, "sub", "file.txt"), "test");
	});

	afterEach(() => {
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it("allows path within workspace", () => {
		expect(isWithinWorkspace(path.join(tmpDir, "sub", "file.txt"), tmpDir)).toBe(true);
	});

	it("allows workspace root itself", () => {
		expect(isWithinWorkspace(tmpDir, tmpDir)).toBe(true);
	});

	it("blocks path outside workspace", () => {
		expect(isWithinWorkspace("/etc/passwd", tmpDir)).toBe(false);
	});

	it("blocks ../ traversal escaping workspace", () => {
		expect(isWithinWorkspace(path.join(tmpDir, "sub", "..", "..", "etc", "passwd"), tmpDir)).toBe(
			false,
		);
	});

	it("blocks symlink pointing outside workspace", () => {
		const linkPath = path.join(tmpDir, "sneaky-link");
		fs.symlinkSync("/etc", linkPath);
		expect(isWithinWorkspace(path.join(linkPath, "passwd"), tmpDir)).toBe(false);
	});

	it("allows symlink pointing within workspace", () => {
		const linkPath = path.join(tmpDir, "internal-link");
		fs.symlinkSync(path.join(tmpDir, "sub"), linkPath);
		expect(isWithinWorkspace(path.join(linkPath, "file.txt"), tmpDir)).toBe(true);
	});

	it("handles non-existent path by checking parent", () => {
		expect(isWithinWorkspace(path.join(tmpDir, "sub", "new-file.txt"), tmpDir)).toBe(true);
	});

	it("blocks non-existent path outside workspace", () => {
		expect(isWithinWorkspace("/nonexistent/path/file.txt", tmpDir)).toBe(false);
	});
});

describe("checkWorkspaceAccess", () => {
	let tmpDir: string;

	beforeEach(() => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-ws-test-"));
		fs.mkdirSync(path.join(tmpDir, "sub"), { recursive: true });
	});

	afterEach(() => {
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it("allows read in ro workspace", () => {
		const result = checkWorkspaceAccess(path.join(tmpDir, "sub", "file.txt"), tmpDir, "ro", "read");
		expect(result.allowed).toBe(true);
	});

	it("blocks write in ro workspace", () => {
		const result = checkWorkspaceAccess(
			path.join(tmpDir, "sub", "file.txt"),
			tmpDir,
			"ro",
			"write",
		);
		expect(result.allowed).toBe(false);
		expect(result.reason).toContain("read-only");
	});

	it("allows write in rw workspace", () => {
		const result = checkWorkspaceAccess(
			path.join(tmpDir, "sub", "file.txt"),
			tmpDir,
			"rw",
			"write",
		);
		expect(result.allowed).toBe(true);
	});

	it("blocks path outside workspace regardless of access", () => {
		const result = checkWorkspaceAccess("/etc/passwd", tmpDir, "rw", "read");
		expect(result.allowed).toBe(false);
		expect(result.reason).toContain("outside workspace");
	});
});

describe("isWithinWorkspace with root /", () => {
	it("allows any absolute path when workspace is /", () => {
		expect(isWithinWorkspace("/app/.env", "/")).toBe(true);
		expect(isWithinWorkspace("/etc/passwd", "/")).toBe(true);
		expect(isWithinWorkspace("/", "/")).toBe(true);
	});
});

describe("extractPathsFromCommand", () => {
	it("extracts absolute path arguments from command", () => {
		expect(extractPathsFromCommand("cat /etc/passwd")).toEqual(["/etc/passwd"]);
	});

	it("skips the command binary (first token)", () => {
		expect(extractPathsFromCommand("/usr/bin/cat /etc/passwd")).toEqual(["/etc/passwd"]);
	});

	it("skips flags", () => {
		expect(extractPathsFromCommand("rm -rf /home/user/data")).toEqual(["/home/user/data"]);
	});

	it("extracts multiple paths", () => {
		expect(extractPathsFromCommand("cp /src/file.txt /dst/file.txt")).toEqual([
			"/src/file.txt",
			"/dst/file.txt",
		]);
	});

	it("returns empty for commands with no absolute paths", () => {
		expect(extractPathsFromCommand("ls -la")).toEqual([]);
		expect(extractPathsFromCommand("echo hello")).toEqual([]);
	});

	it("handles quoted paths", () => {
		expect(extractPathsFromCommand('cat "/etc/passwd"')).toEqual(["/etc/passwd"]);
	});

	it("returns empty for empty command", () => {
		expect(extractPathsFromCommand("")).toEqual([]);
	});
});
