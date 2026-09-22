"""Ingestion durability, TCP framing and storage limits."""
import sqlite3
import time

from conftest import make_entry


def log_count(sentrylog):
    conn = sqlite3.connect(str(sentrylog.DB_PATH))
    try:
        return conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
    finally:
        conn.close()


# --- durability ------------------------------------------------------------

def test_events_are_written_on_flush(sentrylog):
    for i in range(5):
        sentrylog.ingest_log(make_entry("msg %d" % i))
    assert sentrylog._flush_logs() is True
    assert log_count(sentrylog) == 5
    assert sentrylog.get_ingest_health()["queue_depth"] == 0


def test_a_failed_write_is_spooled_not_lost(sentrylog, monkeypatch):
    monkeypatch.setattr(sentrylog, "_WRITE_RETRY_DELAY", 0)

    def boom(batch):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(sentrylog, "write_batch", boom)
    for i in range(3):
        sentrylog.ingest_log(make_entry("lost? %d" % i))
    assert sentrylog._flush_logs() is False
    assert log_count(sentrylog) == 0
    spooled = list(sentrylog.SPOOL_DIR.glob("batch_*.jsonl"))
    assert len(spooled) == 1, "batch was dropped instead of spooled"
    health = sentrylog.get_ingest_health()
    assert health["spooled_events"] == 3
    assert health["write_retries"] >= sentrylog._WRITE_RETRIES


def test_spooled_batches_are_replayed(sentrylog, monkeypatch):
    monkeypatch.setattr(sentrylog, "_WRITE_RETRY_DELAY", 0)
    real_write = sentrylog.write_batch
    monkeypatch.setattr(sentrylog, "write_batch",
                        lambda batch: (_ for _ in ()).throw(
                            sqlite3.OperationalError("disk I/O error")))
    for i in range(4):
        sentrylog.ingest_log(make_entry("retry %d" % i))
    sentrylog._flush_logs()
    assert log_count(sentrylog) == 0

    monkeypatch.setattr(sentrylog, "write_batch", real_write)
    assert sentrylog.replay_spool() == 4
    assert log_count(sentrylog) == 4
    assert list(sentrylog.SPOOL_DIR.glob("batch_*.jsonl")) == []


def test_retry_succeeds_on_the_second_attempt(sentrylog, monkeypatch):
    monkeypatch.setattr(sentrylog, "_WRITE_RETRY_DELAY", 0)
    real_write = sentrylog.write_batch
    calls = {"n": 0}

    def flaky(batch):
        calls["n"] += 1
        if calls["n"] == 1:
            raise sqlite3.OperationalError("database is locked")
        return real_write(batch)

    monkeypatch.setattr(sentrylog, "write_batch", flaky)
    sentrylog.ingest_log(make_entry("flaky"))
    assert sentrylog._flush_logs() is True
    assert log_count(sentrylog) == 1
    assert list(sentrylog.SPOOL_DIR.glob("batch_*.jsonl")) == []


def test_queue_full_is_counted_not_silent(sentrylog, monkeypatch):
    import queue as queue_mod
    monkeypatch.setattr(sentrylog, "_ingest_queue", queue_mod.Queue(maxsize=2))
    assert sentrylog.ingest_log(make_entry("a")) is True
    assert sentrylog.ingest_log(make_entry("b")) is True
    assert sentrylog.ingest_log(make_entry("c")) is False
    assert sentrylog.get_ingest_health()["dropped_queue_full"] == 1


def test_forwarding_happens_after_buffering(sentrylog, monkeypatch):
    """A broken forwarding target must not stop an event being stored."""
    def broken_forward(entry):
        raise RuntimeError("SIEM unreachable")

    monkeypatch.setattr(sentrylog, "forward_log", broken_forward)
    sentrylog.ingest_log(make_entry("still stored"))
    assert sentrylog._flush_logs() is True
    assert log_count(sentrylog) == 1


def test_alert_delivery_is_outside_the_ingest_transaction(sentrylog):
    conn = sqlite3.connect(str(sentrylog.DB_PATH))
    conn.execute(
        "INSERT INTO alert_rules (name, pattern, pattern_type, severity_filter,"
        " enabled, cooldown_minutes, fire_count, created_at, updated_at) "
        "VALUES ('boom', 'kernel panic', 'contains', '', 1, 0, 0,"
        " '2026-01-01 00:00:00', '2026-01-01 00:00:00')")
    conn.commit()
    conn.close()

    delivered = []
    sentrylog._send_alert_notifications = lambda *a, **k: delivered.append(a)
    sentrylog.ingest_log(make_entry("kernel panic detected"))
    assert sentrylog._flush_logs() is True
    # The rule fired and the alert row was committed...
    conn = sqlite3.connect(str(sentrylog.DB_PATH))
    assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1
    conn.close()
    # ...and delivery was queued for the worker, not run inline.
    assert sentrylog._alert_queue.qsize() == 1
    assert delivered == []


def test_ingest_health_endpoint(client, sentrylog):
    body = client.get("/api/ingest-health").get_json()
    for key in ("queue_depth", "dropped_queue_full", "spooled_events",
                "seconds_since_last_write", "database_mb"):
        assert key in body


# --- TCP framing -----------------------------------------------------------

def test_lf_framing(sentrylog):
    messages, rest = sentrylog.extract_frames(b"<14>one\n<14>two\n")
    assert messages == [b"<14>one", b"<14>two"]
    assert rest == b""


def test_fragmented_lf_message_waits_for_the_rest(sentrylog):
    messages, rest = sentrylog.extract_frames(b"<14>par")
    assert messages == []
    messages, rest = sentrylog.extract_frames(rest + b"tial\n")
    assert messages == [b"<14>partial"]


def test_octet_counting_is_honoured(sentrylog):
    buf = b"11 <14>hello!!12 <14>hello2!!"
    messages, rest = sentrylog.extract_frames(buf)
    assert messages == [b"<14>hello!!", b"<14>hello2!!"]
    assert rest == b""


def test_octet_counted_frames_are_not_merged(sentrylog):
    """Two length-prefixed messages in one packet stay two messages."""
    first, second = b"<14>alpha", b"<14>beta"
    buf = b"%d %s%d %s" % (len(first), first, len(second), second)
    messages, rest = sentrylog.extract_frames(buf)
    assert messages == [first, second]


def test_incomplete_octet_counted_frame_is_not_delivered_early(sentrylog):
    payload = b"<14>only-partial-here!"
    buf = b"%d %s" % (len(payload), payload)
    messages, rest = sentrylog.extract_frames(buf[:16])
    assert messages == []
    messages, rest = sentrylog.extract_frames(rest + buf[16:])
    assert messages == [payload]


def test_mixed_framing_in_one_stream(sentrylog):
    buf = b"9 <14>abcde<14>lf-message\n"
    messages, rest = sentrylog.extract_frames(buf)
    assert messages == [b"<14>abcde", b"<14>lf-message"]
    assert rest == b""


def test_oversized_unframed_data_is_flushed_not_accumulated(sentrylog):
    blob = b"x" * (sentrylog._TCP_MAX_FRAME + 10)
    messages, rest = sentrylog.extract_frames(blob)
    assert len(messages) == 1
    assert rest == b""


def test_tcp_handler_parses_split_packets(sentrylog):
    class FakeSock:
        def __init__(self, chunks):
            self.chunks = list(chunks)

        def settimeout(self, _):
            pass

        def recv(self, _n):
            return self.chunks.pop(0) if self.chunks else b""

        def close(self):
            pass

    sentrylog._handle_tcp_client(
        FakeSock([b"<14>one\n<1", b"4>two\n", b"9 <14>three"]), ("10.0.0.5", 1))
    assert sentrylog._flush_logs() is True
    conn = sqlite3.connect(str(sentrylog.DB_PATH))
    rows = [r[0] for r in conn.execute("SELECT raw FROM logs ORDER BY id")]
    conn.close()
    assert len(rows) == 3


# --- storage limits --------------------------------------------------------

def test_storage_limit_is_enforced(sentrylog):
    cfg = sentrylog._config
    cfg["storage"]["max_db_size_mb"] = 0.05
    cfg["storage"]["min_retention_hours"] = 0
    conn = sqlite3.connect(str(sentrylog.DB_PATH))
    conn.executemany(
        "INSERT INTO logs (timestamp, received_at, source_ip, source_name,"
        " facility, facility_code, severity, severity_code, app_name,"
        " process_id, message, raw) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        [("2020-01-01 00:00:00", "2020-01-01 00:00:00", "10.0.0.1", "h",
          "user", 1, "info", 6, "app", "1", "x" * 500, "x" * 500)
         for _ in range(4000)])
    conn.commit()
    conn.close()
    before = sentrylog.database_size_mb()
    assert before > 0.05
    result = sentrylog.enforce_storage_limit()
    assert result["enforced"] is True
    assert result["removed"] > 0
    assert sentrylog.database_size_mb() < before


def test_storage_limit_respects_the_recent_data_floor(sentrylog):
    cfg = sentrylog._config
    cfg["storage"]["max_db_size_mb"] = 0.01
    cfg["storage"]["min_retention_hours"] = 24
    for i in range(50):
        sentrylog.ingest_log(make_entry("recent %d" % i))
    sentrylog._flush_logs()
    before = log_count(sentrylog)
    sentrylog.enforce_storage_limit()
    assert log_count(sentrylog) == before, "recent logs must not be trimmed"


def test_no_limit_configured_is_a_no_op(sentrylog):
    sentrylog._config["storage"]["max_db_size_mb"] = 0
    assert sentrylog.enforce_storage_limit()["reason"] == "no_limit"


def test_cleanup_trims_other_growing_tables(sentrylog):
    conn = sqlite3.connect(str(sentrylog.DB_PATH))
    conn.execute(
        "INSERT INTO notification_log (channel_id, channel_name, alert_id,"
        " subject, status, error_message, sent_at)"
        " VALUES (1, 'c', 1, 'subject', 'ok', '', '2019-01-01 00:00:00')")
    conn.commit()
    conn.close()
    sentrylog._config["storage"]["notification_retention_days"] = 1
    sentrylog.cleanup_old_logs()
    conn = sqlite3.connect(str(sentrylog.DB_PATH))
    remaining = conn.execute("SELECT COUNT(*) FROM notification_log").fetchone()[0]
    conn.close()
    assert remaining == 0


def test_writer_thread_drains_the_queue(sentrylog):
    sentrylog.start_ingest_workers()
    for i in range(10):
        sentrylog.ingest_log(make_entry("threaded %d" % i))
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and log_count(sentrylog) < 10:
        time.sleep(0.2)
    assert log_count(sentrylog) == 10
