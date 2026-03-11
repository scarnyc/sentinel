import type { ToolResult } from "@sentinel/types";
import { execa } from "execa";
import { moderateEmail } from "../moderation/email-scanner.js";
import { truncateBashOutput } from "../output-truncation.js";

const STRIPPED_ENV_PREFIXES = ["SENTINEL_", "ANTHROPIC_", "OPENAI_", "GEMINI_"];
const STRIPPED_ENV_KEYS = new Set([
	"MOLTBOT_GATEWAY_TOKEN",
	"CF_ACCESS_AUD",
	"R2_ACCESS_KEY_ID",
	"R2_SECRET_ACCESS_KEY",
	"CF_ACCOUNT_ID",
]);

function stripSensitiveEnv(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
	const cleaned: NodeJS.ProcessEnv = {};
	for (const [key, value] of Object.entries(env)) {
		if (STRIPPED_ENV_KEYS.has(key)) continue;
		if (STRIPPED_ENV_PREFIXES.some((p) => key.startsWith(p))) continue;
		cleaned[key] = value;
	}
	return cleaned;
}

export interface GwsParams {
	service: string;
	method: string;
	args?: Record<string, unknown>;
	sanitize?: boolean;
}

export const GWS_READ_PATTERNS = /\b(list|get|search|watch)\b/;

export async function executeGws(params: GwsParams, manifestId: string): Promise<ToolResult> {
	const start = Date.now();

	const cliArgs = [params.service, params.method];

	if (params.args && Object.keys(params.args).length > 0) {
		cliArgs.push("--json", JSON.stringify(params.args));
	}

	if (params.sanitize) {
		cliArgs.push("--sanitize");
	}

	try {
		const result = await execa("gws", cliArgs, {
			timeout: 30_000,
			killSignal: "SIGKILL",
			env: stripSensitiveEnv(process.env),
			extendEnv: false,
			reject: false,
		});

		if (result.exitCode !== 0) {
			// Never include raw stderr — may contain credentials
			return {
				manifestId,
				success: false,
				error: `gws exited with code ${result.exitCode}`,
				duration_ms: Date.now() - start,
			};
		}

		let output = result.stdout ? truncateBashOutput(result.stdout) : undefined;

		// Email scanning: only scan gmail read operations (inbound email is untrusted)
		if (output && params.service === "gmail" && GWS_READ_PATTERNS.test(params.method)) {
			const emailModeration = moderateEmail(output);
			if (emailModeration.blocked && emailModeration.sanitizedOutput) {
				output = emailModeration.sanitizedOutput;
			}
		}

		return {
			manifestId,
			success: true,
			output,
			duration_ms: Date.now() - start,
		};
	} catch (error) {
		// Handle missing binary gracefully
		if (
			error instanceof Error &&
			"code" in error &&
			(error as NodeJS.ErrnoException).code === "ENOENT"
		) {
			return {
				manifestId,
				success: false,
				error: "gws CLI not found — install @googleworkspace/cli",
				duration_ms: Date.now() - start,
			};
		}

		return {
			manifestId,
			success: false,
			error: error instanceof Error ? error.message : "Unknown error",
			duration_ms: Date.now() - start,
		};
	}
}
