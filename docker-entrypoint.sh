#!/bin/bash
set -e

echo "=== MyClover.Tech.SentryLog ==="
echo "Starting at $(date) (TZ=${TZ:-UTC})"

# Copy default config if user hasn't mounted one
if [ ! -f /app/sentrylog_config.yaml ]; then
    echo "No sentrylog_config.yaml found — copying default..."
    cp /app/sentrylog_config.yaml.default /app/sentrylog_config.yaml
fi

# Start SentryLog
exec python sentrylog.py
