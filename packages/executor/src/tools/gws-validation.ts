import { GMAIL_CONTENT_PATTERNS, GMAIL_SEND_PATTERNS } from "@sentinel/types";

const EMAIL_REGEX = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const MAX_RECIPIENTS_PER_FIELD = 50;
const MAX_TOTAL_RECIPIENTS = 100;
const MAX_SUBJECT_LENGTH = 998;

export interface ValidationResult {
	valid: boolean;
	errors: string[];
}

function validateEmailArray(value: unknown, fieldName: string, errors: string[]): string[] {
	if (value === undefined || value === null) return [];
	if (!Array.isArray(value)) {
		errors.push(`${fieldName} must be an array`);
		return [];
	}
	if (value.length > MAX_RECIPIENTS_PER_FIELD) {
		errors.push(`${fieldName} exceeds maximum of ${MAX_RECIPIENTS_PER_FIELD} recipients`);
	}
	for (const email of value) {
		if (typeof email !== "string" || !EMAIL_REGEX.test(email)) {
			errors.push(`${fieldName} contains invalid email: ${String(email)}`);
		}
	}
	return value as string[];
}

export function validateGwsSendArgs(
	service: string,
	method: string,
	args: Record<string, unknown>,
): ValidationResult {
	// Non-gmail or non-content methods: passthrough
	GMAIL_CONTENT_PATTERNS.lastIndex = 0;
	if (service !== "gmail" || !GMAIL_CONTENT_PATTERNS.test(method)) {
		return { valid: true, errors: [] };
	}

	const errors: string[] = [];

	// SENTINEL: Block raw MIME — bypasses all email security controls (credential detection, injection scanning)
	if (args.raw !== undefined) {
		errors.push("raw MIME is not allowed — use structured fields (to, subject, body)");
		return { valid: false, errors };
	}

	// Determine if this is a send-class method (requires `to`) or draft-class (to is optional)
	GMAIL_SEND_PATTERNS.lastIndex = 0;
	const isSendMethod = GMAIL_SEND_PATTERNS.test(method);

	// to: required for send, optional for drafts
	if (isSendMethod && !args.to) {
		errors.push("to is required for gmail send");
	}
	const toList = validateEmailArray(args.to, "to", errors);
	const ccList = validateEmailArray(args.cc, "cc", errors);
	const bccList = validateEmailArray(args.bcc, "bcc", errors);

	// Total recipient cap
	const totalRecipients = toList.length + ccList.length + bccList.length;
	if (totalRecipients > MAX_TOTAL_RECIPIENTS) {
		errors.push(`Total recipients (${totalRecipients}) exceeds maximum of ${MAX_TOTAL_RECIPIENTS}`);
	}

	// subject: required, max 998 chars, no CRLF
	if (!args.subject || typeof args.subject !== "string") {
		errors.push("subject is required and must be a string");
	} else {
		if (args.subject.length > MAX_SUBJECT_LENGTH) {
			errors.push(`subject exceeds maximum length of ${MAX_SUBJECT_LENGTH} characters`);
		}
		if (/[\r\n]/.test(args.subject)) {
			errors.push("subject must not contain CR or LF characters");
		}
	}

	return { valid: errors.length === 0, errors };
}

// ── Constants for generic validation ──────────────────────────────────
export const MAX_ARG_STRING_LENGTH = 1_048_576; // 1MB
export const MAX_ARG_ARRAY_LENGTH = 1000;
export const MAX_ARG_DEPTH = 10;
export const MAX_CALENDAR_ATTENDEES = 200;
export const ADMIN_READ_METHODS = new Set([
	"users.list",
	"users.get",
	"groups.list",
	"groups.get",
	"orgunits.list",
]);
export const SENSITIVE_PATH_PATTERN =
	/\.(env|key|pem|p12|pfx)\b|vault\.enc|\.git\/(config|credentials)/;

function checkDepthAndSize(obj: unknown, errors: string[], depth = 0): void {
	if (depth > MAX_ARG_DEPTH) {
		errors.push(`Argument nesting exceeds maximum depth of ${MAX_ARG_DEPTH}`);
		return;
	}
	if (typeof obj === "string" && obj.length > MAX_ARG_STRING_LENGTH) {
		errors.push(`String argument exceeds maximum length of ${MAX_ARG_STRING_LENGTH} bytes`);
		return;
	}
	if (Array.isArray(obj)) {
		if (obj.length > MAX_ARG_ARRAY_LENGTH) {
			errors.push(`Array argument exceeds maximum length of ${MAX_ARG_ARRAY_LENGTH} elements`);
			return;
		}
		for (const item of obj) {
			checkDepthAndSize(item, errors, depth + 1);
		}
		return;
	}
	if (obj !== null && typeof obj === "object") {
		for (const value of Object.values(obj as Record<string, unknown>)) {
			checkDepthAndSize(value, errors, depth + 1);
		}
	}
}

export function validateGwsGenericArgs(args: Record<string, unknown>): ValidationResult {
	const errors: string[] = [];
	checkDepthAndSize(args, errors);
	return { valid: errors.length === 0, errors };
}

export function validateGwsDriveArgs(
	_method: string,
	args: Record<string, unknown>,
): ValidationResult {
	const errors: string[] = [];
	// Check all string values for path traversal and sensitive file targeting
	for (const value of Object.values(args)) {
		if (typeof value === "string") {
			if (value.includes("..")) {
				errors.push("Path traversal (..) is not allowed in drive arguments");
			}
			if (SENSITIVE_PATH_PATTERN.test(value)) {
				errors.push("Targeting sensitive files is not allowed");
			}
		}
	}
	return { valid: errors.length === 0, errors };
}

export function validateGwsCalendarArgs(
	_method: string,
	args: Record<string, unknown>,
): ValidationResult {
	const errors: string[] = [];
	const attendees = args.attendees;
	if (Array.isArray(attendees)) {
		if (attendees.length > MAX_CALENDAR_ATTENDEES) {
			errors.push(
				`Attendee list (${attendees.length}) exceeds maximum of ${MAX_CALENDAR_ATTENDEES}`,
			);
		}
		for (const attendee of attendees) {
			const email =
				typeof attendee === "string"
					? attendee
					: typeof attendee === "object" && attendee !== null && "email" in attendee
						? (attendee as Record<string, unknown>).email
						: undefined;
			if (typeof email !== "string" || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
				errors.push(`Invalid attendee email: ${String(email ?? attendee)}`);
			}
		}
	}
	return { valid: errors.length === 0, errors };
}

export function validateGwsAdminArgs(method: string): ValidationResult {
	if (!ADMIN_READ_METHODS.has(method)) {
		return {
			valid: false,
			errors: [`Admin method "${method}" is not allowed — only read-only methods permitted`],
		};
	}
	return { valid: true, errors: [] };
}

export function validateGwsArgs(
	service: string,
	method: string,
	args: Record<string, unknown>,
): ValidationResult {
	const allErrors: string[] = [];

	// 1. Generic validation (always)
	const generic = validateGwsGenericArgs(args);
	allErrors.push(...generic.errors);

	// 2. Service-specific validation
	switch (service) {
		case "gmail": {
			const gmail = validateGwsSendArgs(service, method, args);
			allErrors.push(...gmail.errors);
			break;
		}
		case "drive": {
			const drive = validateGwsDriveArgs(method, args);
			allErrors.push(...drive.errors);
			break;
		}
		case "calendar": {
			const cal = validateGwsCalendarArgs(method, args);
			allErrors.push(...cal.errors);
			break;
		}
		case "admin": {
			const admin = validateGwsAdminArgs(method);
			allErrors.push(...admin.errors);
			break;
		}
	}

	return { valid: allErrors.length === 0, errors: allErrors };
}
