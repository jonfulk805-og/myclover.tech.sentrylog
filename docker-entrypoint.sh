#!/bin/bash
set -e

echo "=== MyClover.Tech.SentryLog ==="
echo "Starting at $(date) (TZ=${TZ:-UTC})"

DATA_DIR="${SENTRYLOG_DATA_DIR:-/app/data}"
CONFIG_PATH="${SENTRYLOG_CONFIG:-$DATA_DIR/sentrylog_config.yaml}"
BACKUP_DIR="${SENTRYLOG_BACKUP_DIR:-$DATA_DIR/backups}"

mkdir -p "$DATA_DIR" "$BACKUP_DIR"

# Seed the config inside the data volume so edits survive container replacement.
if [ ! -f "$CONFIG_PATH" ]; then
    if [ -f /app/sentrylog_config.yaml ]; then
        echo "Migrating existing /app/sentrylog_config.yaml into $CONFIG_PATH ..."
        cp /app/sentrylog_config.yaml "$CONFIG_PATH"
    else
        echo "No config found - seeding default at $CONFIG_PATH ..."
        cp /app/sentrylog_config.yaml.default "$CONFIG_PATH"
    fi
fi

echo "Data dir: $DATA_DIR | config: $CONFIG_PATH | db: ${SENTRYLOG_DB_PATH:-$DATA_DIR/sentrylog.db} | backups: $BACKUP_DIR"

# Start SentryLog
exec python sentrylog.py
