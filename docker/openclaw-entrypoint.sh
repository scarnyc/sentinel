#!/bin/sh
set -e

# SENTINEL: Docker entrypoint for OpenClaw gateway container.
# Patches host-mounted config (localhost:3141 → executor:3141) for Docker networking,
# then starts the real OpenClaw gateway with Sentinel plugin.

CONFIG_SRC="${OPENCLAW_CONFIG_MOUNT:-/config/openclaw.json}"
CONFIG_DST="/app/state/openclaw.json"

if [ -f "$CONFIG_SRC" ]; then
  sed -e 's|localhost:3141|executor:3141|g' \
      -e 's|/Users/[^"]*/.openclaw/|/app/state/|g' \
      -e 's|/home/[^"]*/.openclaw/|/app/state/|g' \
      "$CONFIG_SRC" > "$CONFIG_DST"
  echo "[sentinel-docker] Config patched: localhost→executor, ~/.openclaw/→/app/state/"
else
  echo "[sentinel-docker] WARNING: No config found at $CONFIG_SRC — starting with defaults"
fi

# Copy plugin files from image staging into the volume (ensures latest version on each start)
PLUGIN_DIR="/app/state/extensions/sentinel"
mkdir -p "$PLUGIN_DIR/dist"
cp /app/plugin-staging/dist/register.js "$PLUGIN_DIR/dist/register.js"
cp /app/plugin-staging/openclaw.plugin.json "$PLUGIN_DIR/openclaw.plugin.json"
# Patch package.json: rewrite bundle path to match Docker layout (dist/register.js, not dist/bundle/register.js)
sed 's|./dist/bundle/register.js|./dist/register.js|g' /app/plugin-staging/package.json > "$PLUGIN_DIR/package.json"
echo "[sentinel-docker] Plugin deployed to $PLUGIN_DIR"

export OPENCLAW_STATE_DIR=/app/state
export OPENCLAW_CONFIG_PATH="$CONFIG_DST"

# SENTINEL: --use-env-proxy tells Node to respect HTTPS_PROXY for all outbound fetch/undici
# This routes Telegram polling + Brave Search through executor's CONNECT tunnel proxy.
export NODE_OPTIONS="--use-env-proxy"

exec node "$(which openclaw)" gateway run \
  --port 8080 \
  --bind loopback \
  --force \
  --allow-unconfigured
