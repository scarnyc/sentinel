import type {
	ActionCategory,
	ActionManifest,
	PolicyDecision,
	SentinelConfig,
	ToolClassification,
} from "@sentinel/types";
import { classifyBashCommand } from "./bash-parser.js";

function findClassification(
	tool: string,
	classifications: ToolClassification[],
): ToolClassification | undefined {
	return classifications.find((c) => c.tool === tool);
}

function matchOverride(condition: string, parameters: Record<string, unknown>): boolean {
	// condition format: "key=value" or "key~pattern"
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
		case "write-irreversible":
			return {
				action: "confirm",
				category,
				reason: "Write-irreversible action requires confirmation — cannot be undone",
			};
		case "dangerous":
			return {
				action: "confirm",
				category,
				reason: "Dangerous operation requires confirmation",
			};
	}
}

/** Gmail send/draft-send method patterns */
const GMAIL_SEND_PATTERNS = /\b(send|drafts\.send)\b/;

/** Calendar create/insert method patterns */
const CALENDAR_CREATE_PATTERNS = /\b(insert|create)\b/;

function classifyGwsTool(parameters: Record<string, unknown>): ActionCategory | null {
	const service = typeof parameters.service === "string" ? parameters.service : "";
	const method = typeof parameters.method === "string" ? parameters.method : "";

	if (service === "gmail" && GMAIL_SEND_PATTERNS.test(method)) {
		return "write-irreversible";
	}

	if (service === "calendar" && CALENDAR_CREATE_PATTERNS.test(method)) {
		// Only irreversible if attendees are present (sends invite)
		const attendees = parameters.attendees;
		if (Array.isArray(attendees) && attendees.length > 0) {
			return "write-irreversible";
		}
	}

	return null;
}

export function classify(manifest: ActionManifest, config: SentinelConfig): PolicyDecision {
	const { tool, parameters } = manifest;

	if (tool === "bash") {
		const command = typeof parameters.command === "string" ? parameters.command : "";
		const category = classifyBashCommand(command);
		return categoryToDecision(category, config.autoApproveReadOps);
	}

	if (tool === "gws") {
		const gwsCategory = classifyGwsTool(parameters);
		if (gwsCategory) {
			return categoryToDecision(gwsCategory, config.autoApproveReadOps);
		}
	}

	const classification = findClassification(tool, config.classifications);

	if (classification) {
		let category = classification.defaultCategory;

		// Apply overrides
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
