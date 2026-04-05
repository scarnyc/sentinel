# Build stage
FROM node:22-alpine AS build
RUN corepack enable
WORKDIR /app
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml tsconfig.base.json tsconfig.json ./
COPY packages/ ./packages/
RUN pnpm install --frozen-lockfile
# Clean stale dist/ from COPY (tsup bundles break native ESM imports)
# Remove test files before build — they import devDependencies not available in Docker
RUN find packages -name dist -type d -exec rm -rf {} + 2>/dev/null; true
RUN find packages -name '*.tsbuildinfo' -delete 2>/dev/null; true
RUN find packages -name '*.test.ts' -delete 2>/dev/null; true
RUN npx tsc -b
# Build OpenClaw plugin bundle (self-contained single file with @sentinel/types + zod)
RUN cd packages/openclaw-plugin && npx tsup --config tsup.bundle.config.ts

# Executor stage
FROM node:22-alpine AS executor
# SENTINEL: H2 — container hardening (read_only, cap_drop ALL, no-new-privileges)
# provides defense-in-depth; firejail omitted (not in Alpine repos)
RUN apk add --no-cache dumb-init
WORKDIR /app
COPY --from=build /app/packages/ ./packages/
COPY --from=build /app/node_modules ./node_modules/
# SENTINEL: M9 — Remove dev dependencies and test files from production image
RUN find /app/packages -name "*.test.ts" -delete && \
    find /app/packages -name "*.test.js" -delete && \
    find /app/packages -name "__tests__" -type d -exec rm -rf {} + 2>/dev/null; true
RUN mkdir -p /app/data && chown node:node /app/data
USER node
EXPOSE 3141
ENTRYPOINT ["dumb-init", "--"]
# SENTINEL: --secure-heap mlock()s OpenSSL key material, preventing swap to disk
CMD ["node", "--secure-heap=65536", "--secure-heap-min=64", "packages/executor/dist/entrypoint.js"]

# Agent stage
FROM node:22-alpine AS agent
RUN apk add --no-cache dumb-init
WORKDIR /app
COPY --from=build /app/packages/ ./packages/
COPY --from=build /app/node_modules ./node_modules/
USER node
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "packages/agent/dist/loop.js"]

# OpenClaw Gateway stage
# SENTINEL: Real OpenClaw gateway with Sentinel plugin. All outbound HTTPS traffic
# routes through executor's CONNECT tunnel proxy via HTTPS_PROXY=http://executor:3141.
FROM node:22-alpine AS openclaw-gateway
RUN apk add --no-cache dumb-init git
WORKDIR /app

# Install OpenClaw globally (git required for some transitive dependencies)
RUN npm install -g openclaw@2026.3.13

# Prepare state directory structure (OpenClaw expects these under OPENCLAW_STATE_DIR)
RUN mkdir -p /app/state/extensions/sentinel/dist \
             /app/state/agents /app/state/logs \
             /app/state/workspace /app/state/memory \
             /app/state/credentials /app/state/delivery-queue \
             /app/state/telegram /app/data && \
    chown -R node:node /app/state /app/data

# Stage plugin files for entrypoint to copy into volume on each start
# (volume mount overlays /app/state — can't rely on image layer files)
COPY --from=build /app/packages/openclaw-plugin/dist/bundle/register.js /app/plugin-staging/dist/register.js
COPY --from=build /app/packages/openclaw-plugin/openclaw.plugin.json /app/plugin-staging/openclaw.plugin.json
COPY --from=build /app/packages/openclaw-plugin/package.json /app/plugin-staging/package.json

# Entrypoint script patches host config for Docker networking, then starts gateway
COPY docker/openclaw-entrypoint.sh /app/openclaw-entrypoint.sh
RUN chmod +x /app/openclaw-entrypoint.sh

USER node
EXPOSE 8080
ENTRYPOINT ["dumb-init", "--"]
CMD ["/app/openclaw-entrypoint.sh"]
