# Upgrading SentryLog

## 6.1 - persistence, authorization and durable ingestion

This release changes where data lives and how credentials are stored. Read this
before replacing a running container.

### 1. Data now lives in the volume (automatic, but verify)

The application previously wrote `sentrylog.db` next to `sentrylog.py`, which
meant the documented `/app/data` volume held nothing and every container
replacement lost the database. It now honours:

| Variable | Default (docker) | Holds |
| --- | --- | --- |
| `SENTRYLOG_DATA_DIR` | `/app/data` | everything below |
| `SENTRYLOG_DB_PATH` | `/app/data/sentrylog.db` | logs, alerts, config tables |
| `SENTRYLOG_CONFIG` | `/app/data/sentrylog_config.yaml` | settings, users |
| `SENTRYLOG_BACKUP_DIR` | `/app/data/backups` | backup zips |
| `SENTRYLOG_SPOOL_DIR` | `/app/data/spool` | batches awaiting retry |
| `SENTRYLOG_SECRET_FILE` | `/app/data/auth_secret.key` | token signing secret |

On first start the old files (`./sentrylog.db`, `./sentrylog_config.yaml`) are
**copied** into the data dir if the new location is empty. Nothing is deleted.

If you mounted your own config at `/app/sentrylog_config.yaml`, move the mount
to `/app/data/sentrylog_config.yaml`.

**Verify after upgrading:** `docker exec <container> ls -la /app/data` should
show `sentrylog.db` and `sentrylog_config.yaml`.

### 2. Everyone is logged out once (breaking)

- The signing secret is now generated per installation instead of being a fixed
  string in the public source. Existing tokens are invalid; log in again.
- Passwords in `sentrylog_config.yaml` are hashed with PBKDF2-SHA256 on first
  load. The plaintext `password:` field is removed from the file. Keep a copy of
  your credentials before upgrading; there is no way to read them back.
- Deleting a user or changing a role/password now invalidates their tokens.

### 3. Authorization is on by default for every route

Previously only user-management routes checked the token. Now every route
requires a permission (`read` / `write` / `config` / `users`), except the login
endpoints, the dashboard shell, static files and the token-authenticated
webhook endpoint `/api/security/webhook/<token>` used by log shippers.

If `auth_enabled: false` the API stays open, as before. You can no longer turn
authentication on without an admin user, delete the last admin while it is on,
or have it silently fall open when the user list is empty.

`/api/config` now masks credential-like values as `__set__`; sending the mask
back leaves the stored value unchanged.

### 4. New settings

```yaml
storage:
  max_db_size_mb: 500          # now actually enforced
  min_retention_hours: 1       # never trim logs newer than this
  notification_retention_days: 90
  incident_retention_days: 180
  report_retention_days: 365
```

`SENTRYLOG_QUEUE_MAX` (default 50000) bounds the in-memory ingest queue.
`/api/ingest-health` reports queue depth, ingestion lag, spool files and
dropped-event counts.
