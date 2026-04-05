import type { MiddlewareHandler } from "hono";

export interface RequestIdEnv {
	Variables: {
		requestId: string;
	};
}

/**
 * Hono middleware that assigns a unique request ID (UUID v4) to each incoming request.
 * Sets X-Request-ID response header and stores the ID in Hono context variables.
 */
export const requestIdMiddleware: MiddlewareHandler<RequestIdEnv> = async (c, next) => {
	const requestId = crypto.randomUUID();
	c.set("requestId", requestId);
	c.header("X-Request-ID", requestId);
	await next();
};
