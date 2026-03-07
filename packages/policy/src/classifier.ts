import type {
	ActionCategory,
	ActionManifest,
	AgentPolicy,
	ApprovalConfig,
	PolicyDecision,
	PolicyDocument,
	SentinelConfig,
	ToolClassification,
} from "@sentinel/types";
import { resolveApproval } from "./approval.js";
import { classifyBashCommand } from "./bash-parser.js";
import { expandGroups } from "./groups.js";
import {
	checkWorkspaceAccess,
	extractPathsFromCommand,
	isWithinWorkspace,
	PATH_PARAMS,
	resolveAgentPath,
} from "./workspace.js";

function findClassification(
	tool: string,
	classifications: ToolClassification[],
): ToolClassification | undefined {
	return classifications.find((c) => c.tool === tool);
}

function matchOverride(condition: string, parameters: Record<string, unknown>): boolean {
	const eqMatch = condition.match(/^(\w+)=(.+)$/);
	if (eqMatch) {
		const [, key, value] = eqMatch;
		return String(parameters[key]) === value;
	}

	const reMatch = condition.match(/^(\w+)~(.+)$/);
	if (reMatch) {
		const [, key, pattern] = reMatch;
		try {
			return new RegExp(pattern).test(String(parameters[key]));
		} catch {
			return false;
		}
	}

	return false;
}

function categoryToDecision(category: ActionCategory, autoApproveReadOps: boolean): PolicyDecision {
	switch (category) {
		case "read":
			return {
				action: autoApproveReadOps ? "auto_approve" : "confirm",
				category,
				reason: autoApproveReadOps
					? "Read operation auto-approved"
					: "Read operation requires confirmation",
			};
		case "write":
			return {
				action: "confirm",
				category,
				reason: "Write operation requires confirmation",
			};
		case "dangerous":
			return {
				action: "confirm",
				category,
				reason: "Dangerous operation requires confirmation",
			};
	}
}

function classifyLegacy(manifest: ActionManifest, config: SentinelConfig): PolicyDecision {
	const { tool, parameters } = manifest;

	if (tool === "bash") {
		const command = typeof parameters.command === "string" ? parameters.command : "";
		const category = classifyBashCommand(command);
		return categoryToDecision(category, config.autoApproveReadOps);
	}

	const classification = findClassification(tool, config.classifications);
	if (classification) {
		let category = classification.defaultCategory;
		if (classification.overrides) {
			for (const override of classification.overrides) {
				if (matchOverride(override.condition, parameters)) {
					category = override.category;
					break;
				}
			}
		}
		return categoryToDecision(category, config.autoApproveReadOps);
	}

	if (tool.includes("__")) {
		return categoryToDecision("write", config.autoApproveReadOps);
	}

	return categoryToDecision("write", config.autoApproveReadOps);
}

function isToolAllowed(
	toolName: string,
	agentPolicy: AgentPolicy,
	defaultsDeny: string[],
	toolGroups: Record<string, string[]>,
): boolean {
	// Expand agent allow/deny lists
	const agentAllow = expandGroups(agentPolicy.tools.allow ?? [], toolGroups);
	const agentDeny = expandGroups(agentPolicy.tools.deny ?? [], toolGroups);
	const globalDeny = expandGroups(defaultsDeny, toolGroups);

	// Deny-wins: check deny lists first
	if (agentDeny.includes(toolName) || globalDeny.includes(toolName)) {
		return false;
	}

	// Check allow: wildcard or explicit
	if (agentAllow.includes("*") || agentAllow.includes(toolName)) {
		return true;
	}

	return false;
}

function getToolOperation(toolName: string): "read" | "write" {
	const readTools = ["read", "read_file"];
	return readTools.includes(toolName) ? "read" : "write";
}

export function classify(
	manifest: ActionManifest,
	policy: PolicyDocument,
	config: SentinelConfig,
): PolicyDecision {
	const { tool, parameters, agentId } = manifest;

	// Step 1: Resolve agent policy — unknown agents are always blocked
	const agentPolicy = policy.agents[agentId];
	if (!agentPolicy) {
		return {
			action: "block",
			category: "dangerous",
			reason: `Unknown agent: ${agentId}`,
		};
	}

	// Step 2-3: Tool gate (deny-wins)
	if (!isToolAllowed(tool, agentPolicy, policy.defaults.tools.deny, policy.toolGroups)) {
		return {
			action: "block",
			category: "dangerous",
			reason: `Tool '${tool}' not allowed for agent '${agentId}'`,
		};
	}

	// Step 4: Workspace gate (for tools with path params)
	const pathParam = PATH_PARAMS[tool];
	if (pathParam) {
		const targetPath = parameters[pathParam];
		if (typeof targetPath === "string" && targetPath.length > 0) {
			const resolvedPath = resolveAgentPath(targetPath, agentPolicy.workspace.root);
			if (!isWithinWorkspace(resolvedPath, agentPolicy.workspace.root)) {
				return {
					action: "block",
					category: "dangerous",
					reason: `Path outside workspace for agent '${agentId}': ${targetPath}`,
				};
			}
			const operation = getToolOperation(tool);
			const access = checkWorkspaceAccess(
				resolvedPath,
				agentPolicy.workspace.root,
				agentPolicy.workspace.access,
				operation,
			);
			if (!access.allowed) {
				return {
					action: "block",
					category: "dangerous",
					reason: access.reason ?? `Workspace access denied for agent '${agentId}'`,
				};
			}
		}
	}

	// Step 4b: Bash command path extraction — check absolute paths in command string
	if (tool === "bash") {
		const command = typeof parameters.command === "string" ? parameters.command : "";
		const paths = extractPathsFromCommand(command);
		for (const cmdPath of paths) {
			const resolvedPath = resolveAgentPath(cmdPath, agentPolicy.workspace.root);
			if (!isWithinWorkspace(resolvedPath, agentPolicy.workspace.root)) {
				return {
					action: "block",
					category: "dangerous",
					reason: `Bash command references path outside workspace for agent '${agentId}': ${cmdPath}`,
				};
			}
		}
	}

	// Step 5: Existing classification (bash parser, category lookup)
	const legacyDecision = classifyLegacy(manifest, config);

	// If legacy says block, respect it
	if (legacyDecision.action === "block") {
		return legacyDecision;
	}

	// Step 6: Approval resolution
	const approvalConfig: ApprovalConfig = agentPolicy.approval ?? policy.defaults.approval;

	// "always" and "never" apply to all tools unconditionally
	if (approvalConfig.ask === "always") {
		return { action: "confirm", category: legacyDecision.category, reason: legacyDecision.reason };
	}
	if (approvalConfig.ask === "never") {
		return {
			action: "auto_approve",
			category: legacyDecision.category,
			reason: legacyDecision.reason,
		};
	}

	// "on-miss": for all tools, if legacy says auto_approve, honor it.
	// For bash commands that legacy confirms (writes/dangerous), check allowlist.
	if (legacyDecision.action === "auto_approve") {
		return legacyDecision;
	}

	if (tool === "bash") {
		const command = typeof parameters.command === "string" ? parameters.command : undefined;
		const approvalResult = resolveApproval(command, approvalConfig);
		return {
			action: approvalResult,
			category: legacyDecision.category,
			reason: legacyDecision.reason,
		};
	}

	return legacyDecision;
}
