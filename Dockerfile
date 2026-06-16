FROM python:3.13-slim

LABEL maintainer="MyClover.Tech"
LABEL description="MyClover.Tech.SentryLog - Log Aggregation & Security Alert Platform"
LABEL org.opencontainers.image.source="https://github.com/jonfulk805-og/myclover.tech.sentrylog"
LABEL org.opencontainers.image.title="MyClover.Tech.SentryLog"
LABEL org.opencontainers.image.description="Log aggregation, SIEM-lite, syslog receiver, security alerting, and compliance reporting"
LABEL org.opencontainers.image.vendor="MyClover.Tech"

# Install minimal system deps + timezone data
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

# Default timezone (override with TZ env variable)
ENV TZ=America/Los_Angeles
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

WORKDIR /app

# Copy requirements first for Docker layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt requests

# Copy application code
COPY sentrylog.py .
COPY sentrylog_config.yaml ./sentrylog_config.yaml.default
COPY templates/ ./templates/

# Create data directory for persistent storage
RUN mkdir -p /app/data

# Copy entrypoint
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Default environment
ENV SENTRYLOG_CONFIG=/app/sentrylog_config.yaml
ENV SENTRYLOG_DB_PATH=/app/data/sentrylog.db

# Dashboard port
EXPOSE 8514
# Syslog UDP + TCP
EXPOSE 514/udp
EXPOSE 514/tcp

VOLUME ["/app/data"]

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:8514/ || exit 1

ENTRYPOINT ["/docker-entrypoint.sh"]
