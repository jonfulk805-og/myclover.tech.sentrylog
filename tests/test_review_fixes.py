"""Regressions for the three issues raised in the review of PR #3.

1. Storage enforcement must stop once enough space is free, not delete every
   row it is permitted to delete.
2. Spool replay must not process the same batch twice.
3. Enabling dashboard auth must not lock out existing API-key clients.
"""
import datetime
import sqlite3
import threading

from conftest import make_entry


def _insert_old_logs(sentrylog, count, hours_old=48):
    old = (datetime.datetime.now() - datetime.timedelta(hours=hours_old)
           ).strftime("%Y-%m-%d %H:%M:%S")
    conn = sentrylog.get_db()
    padding = "x" * 400  # make the rows big enough to move the file size
    conn.executemany(
        "INSERT INTO logs (timestamp,received_at,source_ip,source_name,"
        "facility,facility_code,severity,severity_code,app_name,process_id,"
        "message,raw) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        [(old, old, "10.0.0.9", "host1", "user", 1, "info", 6, "app", "1",
          "msg %d %s" % (i, padding), "raw %d" % i) for i in range(count)])
    conn.commit()
    conn.close()


def _log_count(sentrylog):
    conn = sentrylog.get_db()
    try:
        return conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
    finally:
        conn.close()


# --------------------------------------------------------------------------
# 1. Storage enforcement
# --------------------------------------------------------------------------

def test_enforce_storage_limit_stops_once_under_target(sentrylog, monkeypatch):
    """A limit slightly under current size must not empty the whole table."""
    _insert_old_logs(sentrylog, 1000)
    monkeypatch.setattr(sentrylog, "_SIZE_CLEANUP_CHUNK", 100)
    before = _log_count(sentrylog)
    assert before == 1000

    limit = sentrylog.database_size_mb() * 0.95
    result = sentrylog.enforce_storage_limit(max_mb=limit)

    remaining = _log_count(sentrylog)
    assert result["enforced"] is True
    assert remaining > 0, "cleanup deleted every eligible row"
    # Only a fraction of the data was over the limit, so most of it must stay.
    assert remaining >= 500, (
        "cleanup removed %d of %d rows to free ~5%% of the file"
        % (before - remaining, before))


def test_effective_size_ignores_freed_pages(sentrylog):
    """Deleting rows must reduce the effective size before any VACUUM runs."""
    _insert_old_logs(sentrylog, 1000)
    file_before = sentrylog.database_size_mb()
    effective_before = sentrylog.effective_db_size_mb()

    conn = sentrylog.get_db()
    conn.execute("DELETE FROM logs")
    conn.commit()
    conn.close()

    # The file has not shrunk (no VACUUM yet)...
    assert sentrylog.database_size_mb() >= file_before * 0.9
    # ...but the space is known to be reusable.
    assert sentrylog.reusable_db_mb() > 0
    assert sentrylog.effective_db_size_mb() < effective_before


def test_min_retention_still_protects_recent_logs(sentrylog, monkeypatch):
    """The retention floor keeps winning: recent rows survive a tiny limit."""
    _insert_old_logs(sentrylog, 200, hours_old=48)
    conn = sentrylog.get_db()
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        "INSERT INTO logs (timestamp,received_at,source_ip,source_name,"
        "facility,facility_code,severity,severity_code,app_name,process_id,"
        "message,raw) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (now, now, "10.0.0.9", "h", "user", 1, "crit", 2, "app", "1",
         "fresh evidence", "raw"))
    conn.commit()
    conn.close()

    with sentrylog._config_lock:
        sentrylog._config.setdefault("storage", {})["min_retention_hours"] = 1
    monkeypatch.setattr(sentrylog, "_SIZE_CLEANUP_CHUNK", 50)
    sentrylog.enforce_storage_limit(max_mb=0.001)

    conn = sentrylog.get_db()
    try:
        assert conn.execute(
            "SELECT COUNT(*) FROM logs WHERE message='fresh evidence'"
        ).fetchone()[0] == 1
    finally:
        conn.close()


# --------------------------------------------------------------------------
# 2. Spool replay runs once
# --------------------------------------------------------------------------

def test_concurrent_replay_does_not_duplicate_events(sentrylog):
    """Two replay callers racing on one spool file must write it once."""
    sentrylog.spool_batch([make_entry("spooled event")], reason="test")
    assert list(sentrylog.SPOOL_DIR.glob("batch_*.jsonl"))

    start = threading.Barrier(2)
    results = []

    def replay():
        start.wait()
        results.append(sentrylog.replay_spool())

    threads = [threading.Thread(target=replay) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    conn = sentrylog.get_db()
    try:
        count = conn.execute(
            "SELECT COUNT(*) FROM logs WHERE message='spooled event'"
        ).fetchone()[0]
    finally:
        conn.close()
    assert count == 1, "spooled event was written %d times" % count
    assert sum(results) == 1


def test_replay_consumes_spool_file(sentrylog):
    sentrylog.spool_batch([make_entry("one"), make_entry("two")], reason="test")
    assert sentrylog.replay_spool() == 2
    assert list(sentrylog.SPOOL_DIR.glob("batch_*.jsonl")) == []
    assert list(sentrylog.SPOOL_DIR.glob("batch_*.claimed")) == []
    # A second replay finds nothing left to do.
    assert sentrylog.replay_spool() == 0


def test_failed_replay_returns_the_batch_to_the_spool(sentrylog, monkeypatch):
    """A still-broken database must not consume the spooled batch."""
    sentrylog.spool_batch([make_entry("keep me")], reason="test")

    def boom(batch):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(sentrylog, "write_batch", boom)
    assert sentrylog.replay_spool() == 0
    assert list(sentrylog.SPOOL_DIR.glob("batch_*.jsonl")), \
        "the batch was lost after a failed replay"


def test_recover_claimed_spool_files(sentrylog):
    """A crash mid-replay leaves a claimed file; startup must un-claim it."""
    sentrylog.spool_batch([make_entry("interrupted")], reason="test")
    spooled = list(sentrylog.SPOOL_DIR.glob("batch_*.jsonl"))[0]
    claimed = spooled.with_suffix(".jsonl.claimed")
    spooled.rename(claimed)

    assert sentrylog.recover_claimed_spool_files() == 1
    assert list(sentrylog.SPOOL_DIR.glob("batch_*.jsonl"))
    assert sentrylog.replay_spool() == 1


# --------------------------------------------------------------------------
# 3. API keys keep working when dashboard auth is on
# --------------------------------------------------------------------------

def _make_api_key(sentrylog, permissions="admin"):
    raw, key_hash, prefix = sentrylog.generate_api_key()
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = sentrylog.get_db()
    conn.execute(
        "INSERT INTO api_keys (key_hash,key_prefix,label,permissions,enabled,"
        "rate_limit,created_at,expires_at) VALUES (?,?,?,?,1,?,?,'')",
        (key_hash, prefix, "test-key", permissions, 1000, now))
    conn.commit()
    conn.close()
    return raw


def _enable_api_auth(sentrylog):
    with sentrylog._config_lock:
        sentrylog._config.setdefault("api_auth", {})["enabled"] = True


def _enable_dashboard_auth(sentrylog):
    with sentrylog._config_lock:
        sentrylog._config["auth_enabled"] = True
        sentrylog._config["users"] = [{
            "username": "admin", "role": "admin",
            "password_hash": sentrylog.hash_password("pw"),
        }]


def test_api_key_still_reaches_backup_routes_with_dashboard_auth_on(
        sentrylog, client):
    _enable_api_auth(sentrylog)
    raw = _make_api_key(sentrylog, "admin")

    resp = client.get("/api/backup/list", headers={"X-API-Key": raw})
    assert resp.status_code == 200, resp.data

    _enable_dashboard_auth(sentrylog)
    resp = client.get("/api/backup/list", headers={"X-API-Key": raw})
    assert resp.status_code == 200, (
        "dashboard auth locked out a valid API key: %s" % resp.data)


def test_invalid_api_key_is_rejected_with_dashboard_auth_on(sentrylog, client):
    _enable_api_auth(sentrylog)
    _enable_dashboard_auth(sentrylog)
    resp = client.get("/api/backup/list", headers={"X-API-Key": "nope"})
    assert resp.status_code == 401


def test_no_credential_is_still_rejected(sentrylog, client):
    _enable_api_auth(sentrylog)
    _enable_dashboard_auth(sentrylog)
    assert client.get("/api/backup/list").status_code == 401


def test_read_only_api_key_cannot_create_a_backup(sentrylog, client):
    _enable_api_auth(sentrylog)
    _enable_dashboard_auth(sentrylog)
    raw = _make_api_key(sentrylog, "read")

    assert client.get("/api/backup/list",
                      headers={"X-API-Key": raw}).status_code == 200
    resp = client.post("/api/backup/create", headers={"X-API-Key": raw},
                       json={"note": "nope"})
    assert resp.status_code == 403, (
        "a read-only key was allowed to write: %s" % resp.data)


def test_api_key_does_not_open_non_api_key_routes(sentrylog, client):
    """The gate must not turn an API key into a universal dashboard token."""
    _enable_api_auth(sentrylog)
    _enable_dashboard_auth(sentrylog)
    raw = _make_api_key(sentrylog, "admin")
    resp = client.get("/api/config", headers={"X-API-Key": raw})
    assert resp.status_code == 401
