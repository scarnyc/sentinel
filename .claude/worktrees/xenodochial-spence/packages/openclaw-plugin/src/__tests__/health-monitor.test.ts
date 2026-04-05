import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ExecutorClient } from "../executor-client.js";
import { HealthMonitor } from "../health-monitor.js";

function createMockClient(healthy: boolean): ExecutorClient {
	return {
		health: vi.fn().mockResolvedValue(healthy),
	} as unknown as ExecutorClient;
}

describe("HealthMonitor", () => {
	let monitor: HealthMonitor;

	afterEach(() => {
		monitor?.stop();
	});

	it("starts healthy by default", () => {
		const client = createMockClient(true);
		monitor = new HealthMonitor({ client, intervalMs: 1000, unhealthyThreshold: 3 });
		expect(monitor.isHealthy()).toBe(true);
	});

	it("becomes unhealthy after threshold consecutive failures", async () => {
		const client = createMockClient(false);
		monitor = new HealthMonitor({ client, intervalMs: 1000, unhealthyThreshold: 2 });

		await monitor.check(); // failure 1
		expect(monitor.isHealthy()).toBe(true);

		await monitor.check(); // failure 2 — threshold reached
		expect(monitor.isHealthy()).toBe(false);
	});

	it("recovers after a successful check", async () => {
		const client = createMockClient(false);
		monitor = new HealthMonitor({ client, intervalMs: 1000, unhealthyThreshold: 1 });

		await monitor.check(); // fail
		expect(monitor.isHealthy()).toBe(false);

		(client.health as ReturnType<typeof vi.fn>).mockResolvedValue(true);
		await monitor.check(); // recover
		expect(monitor.isHealthy()).toBe(true);
	});

	it("resets failure count on success", async () => {
		const client = createMockClient(false);
		monitor = new HealthMonitor({ client, intervalMs: 1000, unhealthyThreshold: 3 });

		await monitor.check(); // failure 1
		await monitor.check(); // failure 2

		(client.health as ReturnType<typeof vi.fn>).mockResolvedValue(true);
		await monitor.check(); // success — resets count

		(client.health as ReturnType<typeof vi.fn>).mockResolvedValue(false);
		await monitor.check(); // failure 1 again
		expect(monitor.isHealthy()).toBe(true); // still healthy (only 1 failure after reset)
	});
});
