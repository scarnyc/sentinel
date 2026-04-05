import type { ToolResult } from "@sentinel/types";
import { redactAll } from "@sentinel/types";

export function filterCredentials(result: ToolResult): ToolResult {
	return {
		...result,
		output: result.output ? redactAll(result.output) : result.output,
		error: result.error ? redactAll(result.error) : result.error,
	};
}
