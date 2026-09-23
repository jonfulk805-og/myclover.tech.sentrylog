# Upgrading SentryLog

Two changes land together: the **hardening release** (persistence,
authorization, durable ingestion, safe storage cleanup) and the **Incident
Timeline** tab, which reads device events from NetMon. Both are below.
Start with the checklist.

## Upgrade checklist

1. **Back up first.** Copy `sentrylog.db` and `sentrylog_config.yaml` from
   wherever your current install keeps them (beside `sentrylog.py`, or
   `/app/data` if you had already moved them). The upgrade rewrites the config
   file (section 2), so this copy is also your rollback.
2. **Write down every user's password.** Plaintext passwords get hashed and
   removed from the file on first start. Hashes can't be turned back into
   passwords.
3. **Install the CI workflow** (once per repo). The new file replaces the
   existing one, so use `-f`:
   ```bash
   git mv -f deploy/github-workflow-publish.yml .github/workflows/docker-publish.yml
   git commit -m "CI: run tests before publishing the image" && git push
   ```
   From then on the Docker image is only published when the test suite passes.
4. **Replace the container**, then check persistence:
   ```bash
   docker compose pull && docker compose up -d
   docker exec <container> ls -la /app/data      # sentrylog.db, sentrylog_config.yaml, auth_secret.key, spool/
   docker compose down && docker compose up -d   # destroy and recreate
   ```
   Your logs, settings and users must still be there after the second `up`.
5. **Log in again** (everyone is logged out once). Existing `X-API-Key` clients
   keep working on the routes they already used (section 3).
6. **Check the storage limit.** `max_db_size_mb` is now actually enforced
   (section 4). If it was set low and ignored until now, the first cleanup run
   trims old logs down to it.
7. **For the Incident Timeline**, upgrade NetMon first, then set the shared
   token on both sides (section 6).

**Never delete `/app/data/auth_secret.key`.** It signs login tokens, and
deleting it logs everyone out again. Don't delete `/app/data/spool/` while
the container is running: it holds log batches that haven't been written to
the database yet.

### Rolling back

Older builds read `sentrylog.db` / `sentrylog_config.yaml` from beside
`sentrylog.py`, not from `/app/data`, and they can't read hashed passwords. To
roll back, restore the files you backed up in step 1 to the old location and
start the old image. Logs received after the upgrade stay in `/app/data`,
untouched.

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

**Scoped API keys keep working.** The backup routes (list, create, download,
restore, delete) still accept `X-API-Key`. The key's scope is enforced: a read key
can list backups but gets `403` on creating one. An API key is not a general
login, though. Routes such as `/api/config` still require a dashboard token.

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

### 5. Storage cleanup is bounded (behaviour change, safer)

- Size is measured from what the database actually uses (live pages), not the
  file size. So cleanup stops as soon as enough is freed, instead of deleting
  every old log while the file stays the same size.
- No single pass can delete more than a bounded number of rows.
- Logs newer than `min_retention_hours` are never trimmed.
- **Low free disk** (under 256 MiB free on the data volume): SentryLog trims in bounded steps and reclaims space
  (`VACUUM`, then a WAL checkpoint) between steps, measuring free space again
  each time. If reclaiming doesn't help, it **stops and logs a warning instead
  of deleting your history**. The volume is short of space for a reason that
  deleting logs won't fix. Look at the host.
- Spool batches are claimed by renaming them to `*.jsonl.claimed` before
  replay, so a batch can't be written twice. If the process crashes
  mid-replay, the claimed files are put back automatically on the next start.

## Incident Timeline

### 6. New tab and `GET /api/timeline`

The **Incident Timeline** tab puts NetMon device state changes and alerts next
to SentryLog messages from the same host, on one clock. Give it a device name
and it looks up the device's IP from NetMon, so you don't need to know it.

Setting up:

```yaml
# SentryLog sentrylog_config.yaml
netmon_integration:
  enabled: true
  netmon_url: "http://netmon-host:8080"
  read_token: "<same value as integration.read_token in NetMon>"
  timeout_seconds: 5
  verify_tls: true      # false only for an internal NetMon with a self-signed cert
```

NetMon side: set `integration.read_token` in NetMon's `config.yaml` to the
same string. Generate one with
`python -c "import secrets; print(secrets.token_urlsafe(32))"`.

How it behaves:

- **NetMon unreachable, wrong token, or too old:** the tab still shows logs
  and displays the reason (e.g. "NetMon refused the integration token (HTTP
  401)"). A timeline that looks quiet because the integration is broken would
  be worse than a visible error.
- **Searching by device name while NetMon is unreachable:** you see the error
  but no logs, because SentryLog can't look up the device's IP. Search by
  IP (`host`) instead. A device NetMon doesn't know matches no logs. It never
  falls back to showing every source.
- **`host` narrows** both sides. It is never merged with other hosts.
- **Limits are reported:** if either side hits its limit the tab says so, with
  a specific warning when it was NetMon's cap.

### 7. Times: local storage, UTC exchange

SentryLog stores log times in the server's local time. NetMon speaks UTC. The
timeline converts both to real instants and sorts on those, never on text.
Each item carries `timestamp` (UTC, with `Z`) and `local_time` (server-local,
what the tab shows; hover to see UTC). `from` / `to` without an offset mean
server-local time. With an offset, the offset is honoured. A bound that can't
be parsed returns `400`.

**Make sure the container's timezone is what you expect** (`TZ` env var;
the shipped `docker-compose.yml` sets `TZ=America/Los_Angeles`).
Log times and the timeline window are read in that zone.
