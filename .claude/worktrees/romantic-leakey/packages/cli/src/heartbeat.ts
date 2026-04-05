import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { ActiveDelegation } from "./delegation-poller.js";

export interface HeartbeatOptions {
	dataDir: string;
	intervalMs: number;
	onDeadProcess?: (delegation: ActiveDelegation) => void;
}

export class HeartbeatMonitor {
	private readonly options: HeartbeatOptions;
	private timer: ReturnType<typeof setInterval> | null = null;

	constructor(options: HeartbeatOptions) {
		this.options = options;
	}

	start(): void {
		if (this.timer) return;
		this.timer = setInterval(() => this.check(), this.options.intervalMs);
		this.timer.unref();
	}

	stop(): void {
		if (this.timer) {
			clearInterval(this.timer);
			this.timer = null;
		}
	}

	check(): ActiveDelegation[] {
		const active = this.loadActive();
		const dead: ActiveDelegation[] = [];

		for (const delegation of active) {
			if (!this.isProcessAlive(delegation.pid)) {
				dead.push(delegation);
				this.options.onDeadProcess?.(delegation);
			}
		}

		return dead;
	}

	private isProcessAlive(pid: number): boolean {
		try {
			process.kill(pid, 0);
			return true;
		} catch {
			return false;
		}
	}

	private loadActive(): ActiveDelegation[] {
		const path = resolve(this.options.dataDir, "active-delegations.json");
		try {
			return JSON.parse(readFileSync(path, "utf-8")) as ActiveDelegation[];
		} catch {
			return [];
		}
	}
}
