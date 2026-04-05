import { redactAll } from "@sentinel/types";

const MAX_LENGTH = 500;
const TRUNCATED_SUFFIX = "... [truncated]";

export function redactCredentials(text: string): string {
	let result = redactAll(text);

	if (result.length > MAX_LENGTH) {
		result = result.slice(0, MAX_LENGTH - TRUNCATED_SUFFIX.length) + TRUNCATED_SUFFIX;
	}

	return result;
}
