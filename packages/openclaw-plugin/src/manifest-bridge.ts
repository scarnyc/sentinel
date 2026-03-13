import type { ActionManifest } from "@sentinel/types";

const TOOL_NAME_REGEX = /^[a-zA-Z][a-zA-Z0-9_.-]*$/;

export interface SessionContext {
	sessionId: string;
	agentId?: string;
}

/**
 * Builds a Sentinel ActionManifest from OpenClaw tool call parameters.
 * Maps OpenClaw's runId to Sentinel's agentId for audit correlation.
 */
export function buildManifest(
	toolName: string,
	params: Record<string, unknown>,
	runId: string,
	context: SessionContext,
): ActionManifest {
	if (!toolName || toolName.length > 256 || !TOOL_NAME_REGEX.test(toolName)) {
		throw new Error(
			`Invalid tool name: "${toolName}". Must start with a letter and contain only alphanumeric, underscore, dot, or hyphen.`,
		);
	}

	return {
		id: crypto.randomUUID(),
		timestamp: new Date().toISOString(),
		tool: toolName,
		parameters: params,
		sessionId: context.sessionId,
		agentId: context.agentId ?? runId,
	};
}
