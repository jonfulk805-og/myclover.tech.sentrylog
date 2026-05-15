# ============================================================
# MyClover.Tech.SentryLog v6.0 — Docker Container
# ============================================================
# Build:  docker build -t myclover/sentrylog .
# Run:    docker run -d -p 8514:8514 -p 514:514/udp -p 514:514/tcp \
#              -v sentrylog-data:/app/data myclover/sentrylog
# ============================================================

FROM python:3.12-slim AS base

LABEL maintainer="MyClover.Tech <support@myclover.tech>"
LABEL description="MyClover.Tech SentryLog — Log Aggregation & Security Alert Platform"
LABEL version="6.0"

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        net-tools \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r sentrylog && useradd -r -g sentrylog -d /app -s /sbin/nologin sentrylog

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir requests gunicorn

# Copy application code
COPY sentrylog.py .
COPY templates/ templates/

# Copy default config (mount your own at runtime to override)
COPY sentrylog_config.yaml sentrylog_config.yaml.default

# Create data directory for SQLite DB and writable config
RUN mkdir -p /app/data \
    && chown -R sentrylog:sentrylog /app

# Startup script
RUN cat > /app/entrypoint.sh << 'ENTRY'
#!/bin/bash
set -e

# If no config in /app/data, copy the default
if [ ! -f /app/data/sentrylog_config.yaml ]; then
    cp /app/sentrylog_config.yaml.default /app/data/sentrylog_config.yaml
    echo "[entrypoint] Created default sentrylog_config.yaml in /app/data/"
fi

# Symlink config from data volume so sentrylog.py finds it
ln -sf /app/data/sentrylog_config.yaml /app/sentrylog_config.yaml

# Ensure DB lives in the data volume
export SENTRYLOG_DB_PATH="/app/data/sentrylog.db"

exec "$@"
ENTRY
RUN chmod +x /app/entrypoint.sh

# Syslog needs to bind to 514 — run as root for port < 1024,
# or use NET_BIND_SERVICE capability. We'll run as root for syslog
# but the Flask dashboard thread runs in-process.
# For rootless: remap port 514 -> 1514 externally.

# Dashboard port
EXPOSE 8514
# Syslog ports (UDP + TCP)
EXPOSE 514/udp
EXPOSE 514/tcp

# Healthcheck — hit the dashboard
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8514/ || exit 1

# Persistent data (DB + configs + logs)
VOLUME ["/app/data"]

ENTRYPOINT ["/app/entrypoint.sh"]

CMD ["python", "sentrylog.py"]
