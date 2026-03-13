import { mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { HeartbeatMonitor } from "./heartbeat.js";

let tempDir: string;

beforeEach(() => {
	tempDir = realpathSync(mkdtempSync(join(tmpdir(), "sentinel-heartbeat-test-")));
});

afterEach(() => {
	rmSync(tempDir, { recursive: true, force: true });
});

describe("HeartbeatMonitor", () => {
	it("returns empty when no active delegations file", () => {
		const monitor = new HeartbeatMonitor({
			dataDir: tempDir,
			intervalMs: 60_000,
		});
		const dead = monitor.check();
		expect(dead).toHaveLength(0);
	});

	it("detects dead processes", () => {
		writeFileSync(
			join(tempDir, "active-delegations.json"),
			JSON.stringify([
				{
					delegationId: "d-1",
					pid: 999999999, // unlikely to be a real process
					startedAt: new Date().toISOString(),
					task: "Test task",
				},
			]),
		);

		const monitor = new HeartbeatMonitor({
			dataDir: tempDir,
			intervalMs: 60_000,
		});
		const dead = monitor.check();
		expect(dead).toHaveLength(1);
		expect(dead[0].delegationId).toBe("d-1");
	});

	it("detects alive processes (current process)", () => {
		writeFileSync(
			join(tempDir, "active-delegations.json"),
			JSON.stringify([
				{
					delegationId: "d-2",
					pid: process.pid, // current process is alive
					startedAt: new Date().toISOString(),
					task: "Running task",
				},
			]),
		);

		const monitor = new HeartbeatMonitor({
			dataDir: tempDir,
			intervalMs: 60_000,
		});
		const dead = monitor.check();
		expect(dead).toHaveLength(0);
	});

	it("calls onDeadProcess callback", () => {
		writeFileSync(
			join(tempDir, "active-delegations.json"),
			JSON.stringify([
				{
					delegationId: "d-3",
					pid: 999999999,
					startedAt: new Date().toISOString(),
					task: "Dead task",
				},
			]),
		);

		const callback = vi.fn();
		const monitor = new HeartbeatMonitor({
			dataDir: tempDir,
			intervalMs: 60_000,
			onDeadProcess: callback,
		});
		monitor.check();
		expect(callback).toHaveBeenCalledOnce();
		expect(callback.mock.calls[0][0].delegationId).toBe("d-3");
	});
});
