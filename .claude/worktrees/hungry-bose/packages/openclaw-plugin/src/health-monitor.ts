import type { ExecutorClient } from "./executor-client.js";

export interface HealthMonitorOptions {
	client: ExecutorClient;
	intervalMs: number;
	unhealthyThreshold: number;
}

export class HealthMonitor {
	private readonly client: ExecutorClient;
	private readonly intervalMs: number;
	private readonly unhealthyThreshold: number;
	private consecutiveFailures: number = 0;
	private healthy: boolean = true;
	private timer: ReturnType<typeof setInterval> | null = null;

	constructor(options: HealthMonitorOptions) {
		this.client = options.client;
		this.intervalMs = options.intervalMs;
		this.unhealthyThreshold = options.unhealthyThreshold;
	}

	start(): void {
		if (this.timer) return;
		this.timer = setInterval(() => this.check(), this.intervalMs);
		// Don't keep process alive just for health checks
		this.timer.unref();
	}

	stop(): void {
		if (this.timer) {
			clearInterval(this.timer);
			this.timer = null;
		}
	}

	isHealthy(): boolean {
		return this.healthy;
	}

	async check(): Promise<boolean> {
		const ok = await this.client.health();
		if (ok) {
			this.consecutiveFailures = 0;
			this.healthy = true;
		} else {
			this.consecutiveFailures++;
			if (this.consecutiveFailures >= this.unhealthyThreshold) {
				this.healthy = false;
			}
		}
		return this.healthy;
	}
}
