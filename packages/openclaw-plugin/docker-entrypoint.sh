#!/bin/sh
set -e

CONFIG_DIR="${HOME}/.openclaw"
CONFIG_FILE="${CONFIG_DIR}/openclaw.json"

# Create required directories (avoids CRITICAL doctor warnings)
mkdir -p "${CONFIG_DIR}/agents/main/sessions" "${CONFIG_DIR}/credentials" "${CONFIG_DIR}/workspace" 2>/dev/null || true
chmod 700 "${CONFIG_DIR}" 2>/dev/null || true

# Generate OpenClaw config from environment variables
# - LLM provider routes through executor's proxy
# - Telegram bot token is a placeholder (egress proxy substitutes real value)
# - Plugin loaded from /app/plugin/
cat > "${CONFIG_FILE}" << EOCFG
{
  "models": {
    "mode": "merge",
    "providers": {
      "sentinel-openai": {
        "baseUrl": "${SENTINEL_EXECUTOR_URL:-http://executor:3141}/proxy/llm/openai/v1",
        "apiKey": "${SENTINEL_AUTH_TOKEN:-}",
        "api": "openai-completions",
        "models": [
          {
            "id": "gpt-5.4",
            "name": "GPT-5.4",
            "contextWindow": 1047576,
            "maxTokens": 32768
          }
        ]
      }
    }
  },
  "agents": {
    "defaults": {
      "model": "sentinel-openai/gpt-5.4",
      "workspace": "/home/node/.openclaw/workspace"
    }
  },
  "channels": {
    "telegram": {
      "botToken": "${SENTINEL_TELEGRAM_BOT_TOKEN:-SENTINEL_PLACEHOLDER_telegram_bot__key}",
      "enabled": true,
      "dmPolicy": "pairing",
      "groupPolicy": "allowlist",
      "streaming": "partial"
    }
  },
  "plugins": {
    "entries": {
      "sentinel": {
        "enabled": true,
        "config": {
          "executorUrl": "${SENTINEL_EXECUTOR_URL:-http://executor:3141}",
          "authToken": "${SENTINEL_AUTH_TOKEN:-}",
          "failMode": "${SENTINEL_FAIL_MODE:-closed}",
          "tier": "Normal"
        }
      }
    },
    "load": {
      "paths": ["/app/plugin"]
    }
  },
  "gateway": {
    "port": 18789,
    "mode": "local",
    "bind": "lan"
  }
}
EOCFG

echo "[openclaw-gateway] Config written to ${CONFIG_FILE}"
echo "[openclaw-gateway] Executor: ${SENTINEL_EXECUTOR_URL:-http://executor:3141}"
echo "[openclaw-gateway] Plugin: /app/plugin"

# Start OpenClaw gateway (no self-respawn in container)
echo "[openclaw-gateway] Starting OpenClaw gateway..."
export OPENCLAW_NO_RESPAWN=1
chmod 600 "${CONFIG_FILE}" 2>/dev/null || true

# SENTINEL: Route outbound HTTPS through executor's CONNECT proxy.
# OpenClaw's resolveProxyFetchFromEnv() reads HTTPS_PROXY and creates an undici
# ProxyAgent that sends CONNECT to the executor. This enables grammY (which uses
# node-fetch, not globalThis.fetch) to reach api.telegram.org through the tunnel.
# NO_PROXY excludes internal hosts that should bypass the proxy.
export HTTPS_PROXY="${SENTINEL_EXECUTOR_URL:-http://executor:3141}"
export HTTP_PROXY="${SENTINEL_EXECUTOR_URL:-http://executor:3141}"
export NO_PROXY="executor,localhost,127.0.0.1,0.0.0.0"
echo "[openclaw-gateway] HTTPS_PROXY=${HTTPS_PROXY} (CONNECT tunnel through executor)"

# SENTINEL: Bridge node-fetch to globalThis.fetch so the Sentinel fetch interceptor
# can catch ALL HTTP requests (including grammY's Telegram API calls).
# node-fetch is a separate module that ignores globalThis.fetch monkey-patching.
# This shim replaces node-fetch's default export with globalThis.fetch, ensuring
# confirmation callbacks in getUpdates responses are intercepted and forwarded.
# Written to /tmp (tmpfs) because the container filesystem is read-only.
FETCH_BRIDGE="/tmp/node-fetch-bridge.cjs"
cat > "${FETCH_BRIDGE}" << 'EOBRIDGE'
// Redirect require("node-fetch") to globalThis.fetch
// so Sentinel's fetch interceptor catches all HTTP traffic.
const Module = require("module");
const origResolve = Module._resolveFilename;
const bridgePath = __filename;
Module._resolveFilename = function(request, parent) {
  if (request === "node-fetch" && parent && !parent.filename?.includes("node-fetch-bridge")) {
    return bridgePath;
  }
  return origResolve.apply(this, arguments);
};
// Export globalThis.fetch as the default, plus standard Web API classes
module.exports = globalThis.fetch;
module.exports.default = globalThis.fetch;
module.exports.Headers = globalThis.Headers;
module.exports.Request = globalThis.Request;
module.exports.Response = globalThis.Response;
EOBRIDGE
echo "[openclaw-gateway] node-fetch bridge installed at ${FETCH_BRIDGE}"

export NODE_OPTIONS="--max-old-space-size=1536 --require ${FETCH_BRIDGE}"

exec openclaw gateway run --port 18789 --bind lan --allow-unconfigured
