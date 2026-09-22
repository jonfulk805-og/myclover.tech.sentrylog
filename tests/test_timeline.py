"""Tests for the shared NetMon<->SentryLog incident timeline.

The value of the timeline is that device state changes and log lines appear on
one clock, so the tests care most about ordering, correlation by host, and what
happens when NetMon is unavailable -- an integration that silently shows an empty
device history would be worse than no integration at all.
"""
import datetime
import urllib.error

import pytest

from conftest import make_entry


def _insert_log(sentrylog, source_ip, message, minutes_ago,
                severity="info", source_name=""):
    ts = (datetime.datetime.now() - datetime.timedelta(minutes=minutes_ago)
          ).strftime("%Y-%m-%d %H:%M:%S")
    conn = sentrylog.get_db()
    conn.execute(
        "INSERT INTO logs (timestamp, received_at, source_ip, source_name,"
        " facility, facility_code, severity, severity_code, app_name,"
        " process_id, message, raw) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (ts, ts, source_ip, source_name or source_ip, "daemon", 3, severity, 6,
         "sshd", "1", message, message))
    conn.commit()
    conn.close()
    return ts


def _netmon_event(minutes_ago, device="router", host="10.0.0.5",
                  status="critical", previous="ok", ev_type="state_change"):
    ts = (datetime.datetime.now() - datetime.timedelta(minutes=minutes_ago)
          ).strftime("%Y-%m-%d %H:%M:%S")
    return {"type": ev_type, "timestamp": ts, "device": device, "host": host,
            "check_type": "ping", "check_label": "ping", "status": status,
            "previous_status": previous, "message": "went " + status}


def _fake_netmon(monkeypatch, sentrylog, events, error=""):
    monkeypatch.setattr(sentrylog, "fetch_netmon_events",
                        lambda **kw: (events, error))


def _enable_integration(sentrylog, **overrides):
    cfg = {"enabled": True, "netmon_url": "http://netmon.local:8080",
           "read_token": "tok", "timeout_seconds": 1, "verify_tls": True}
    cfg.update(overrides)
    with sentrylog._config_lock:
        sentrylog._config["netmon_integration"] = cfg
    return cfg


# --------------------------------------------------------------------------
# Correlation and ordering
# --------------------------------------------------------------------------

def test_device_events_and_logs_are_interleaved_chronologically(
        sentrylog, monkeypatch):
    _insert_log(sentrylog, "10.0.0.5", "link down", 30)
    _insert_log(sentrylog, "10.0.0.5", "link up", 10)
    _fake_netmon(monkeypatch, sentrylog, [
        _netmon_event(28, status="critical", previous="ok"),
        _netmon_event(12, status="ok", previous="critical"),
    ])

    result = sentrylog.build_timeline(hours=2, device="router")
    kinds = [i["kind"] for i in result["items"]]
    assert kinds == ["log", "device", "device", "log"], (
        "timeline is not in time order: %s" % kinds)
    assert result["device_events"] == 2
    assert result["log_events"] == 2
    assert result["items"] == sorted(result["items"],
                                     key=lambda i: i["timestamp"])


def test_logs_are_matched_to_the_device_by_host_learned_from_netmon(
        sentrylog, monkeypatch):
    """The caller names a device; the host comes from NetMon, not from the user."""
    _insert_log(sentrylog, "10.0.0.5", "relevant", 20)
    _insert_log(sentrylog, "10.0.0.9", "someone else's problem", 20)
    _fake_netmon(monkeypatch, sentrylog, [_netmon_event(21, host="10.0.0.5")])

    result = sentrylog.build_timeline(hours=2, device="router")
    messages = [i["message"] for i in result["items"] if i["kind"] == "log"]
    assert messages == ["relevant"]
    assert result["hosts"] == ["10.0.0.5"]


def test_unknown_device_matches_no_logs_rather_than_all_of_them(
        sentrylog, monkeypatch):
    """No known host must not degrade into an unfiltered log dump."""
    _insert_log(sentrylog, "10.0.0.5", "unrelated", 20)
    _fake_netmon(monkeypatch, sentrylog, [])

    result = sentrylog.build_timeline(hours=2, device="ghost-device")
    assert result["log_events"] == 0, "unknown device showed unrelated logs"


def test_explicit_host_filter_is_honoured_without_netmon(sentrylog,
                                                         monkeypatch):
    _insert_log(sentrylog, "10.0.0.5", "mine", 20)
    _insert_log(sentrylog, "10.0.0.9", "not mine", 20)
    _fake_netmon(monkeypatch, sentrylog, [], error="netmon down")

    result = sentrylog.build_timeline(hours=2, host="10.0.0.5")
    assert [i["message"] for i in result["items"]] == ["mine"]


def test_window_and_severity_filters_apply_to_the_log_side(sentrylog,
                                                           monkeypatch):
    _insert_log(sentrylog, "10.0.0.5", "old news", 600)
    _insert_log(sentrylog, "10.0.0.5", "noise", 20, severity="debug")
    _insert_log(sentrylog, "10.0.0.5", "the problem", 20, severity="err")
    _fake_netmon(monkeypatch, sentrylog, [])

    result = sentrylog.build_timeline(hours=2, host="10.0.0.5", severity="err")
    assert [i["message"] for i in result["items"]] == ["the problem"]


def test_timeline_keeps_the_newest_items_when_truncating(sentrylog,
                                                         monkeypatch):
    for i in range(10):
        _insert_log(sentrylog, "10.0.0.5", "msg-%d" % i, 60 - i)
    _fake_netmon(monkeypatch, sentrylog, [])

    result = sentrylog.build_timeline(hours=4, host="10.0.0.5", limit=3)
    assert result["truncated"] is True
    assert [i["message"] for i in result["items"]] == ["msg-7", "msg-8",
                                                       "msg-9"]


def test_limits_and_hours_are_bounded_against_silly_input(sentrylog,
                                                          monkeypatch):
    _fake_netmon(monkeypatch, sentrylog, [])
    assert sentrylog.build_timeline(hours="not-a-number")["from"]
    big = sentrylog.build_timeline(hours=2, limit=10 ** 9)
    assert big["count"] <= sentrylog._TIMELINE_MAX_EVENTS


# --------------------------------------------------------------------------
# NetMon being unavailable must degrade loudly, not silently
# --------------------------------------------------------------------------

def test_netmon_failure_still_returns_logs_and_reports_the_error(
        sentrylog, monkeypatch):
    _insert_log(sentrylog, "10.0.0.5", "still here", 10)
    _enable_integration(sentrylog)

    def boom(req, **kwargs):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(sentrylog.urllib.request, "urlopen", boom)

    result = sentrylog.build_timeline(hours=2, host="10.0.0.5")
    assert result["log_events"] == 1
    assert result["device_events"] == 0
    assert "unreachable" in result["netmon_error"], (
        "NetMon was down and the timeline did not say so")


@pytest.mark.parametrize("code,expected", [
    (401, "integration token"),
    (403, "integration token"),
    (500, "HTTP 500"),
])
def test_http_errors_are_reported_in_plain_language(sentrylog, monkeypatch,
                                                    code, expected):
    _enable_integration(sentrylog)

    def fail(req, **kwargs):
        raise urllib.error.HTTPError("url", code, "nope", {}, None)

    monkeypatch.setattr(sentrylog.urllib.request, "urlopen", fail)
    events, error = sentrylog.fetch_netmon_events()
    assert events == []
    assert expected in error


def test_disabled_integration_does_not_call_netmon_at_all(sentrylog,
                                                          monkeypatch):
    with sentrylog._config_lock:
        sentrylog._config["netmon_integration"] = {"enabled": False,
                                                   "netmon_url": "http://x"}

    def should_not_run(req, **kwargs):
        raise AssertionError("called NetMon while the integration was disabled")

    monkeypatch.setattr(sentrylog.urllib.request, "urlopen", should_not_run)
    events, error = sentrylog.fetch_netmon_events()
    assert events == []
    assert "disabled" in error


def test_garbage_payload_is_rejected_rather_than_trusted(sentrylog,
                                                         monkeypatch):
    _enable_integration(sentrylog)

    class _Resp:
        def __init__(self, body):
            self._body = body

        def read(self):
            return self._body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    for body in (b"[1,2,3]", b"{\"events\": \"nope\"}", b"not json at all"):
        monkeypatch.setattr(sentrylog.urllib.request, "urlopen",
                            lambda req, **kw: _Resp(body))
        events, error = sentrylog.fetch_netmon_events()
        assert events == []
        assert error


def test_request_carries_the_token_and_the_window(sentrylog, monkeypatch):
    _enable_integration(sentrylog, read_token="secret-token")
    seen = {}

    class _Resp:
        def read(self):
            return b'{"events": []}'

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def capture(req, **kwargs):
        seen["url"] = req.full_url
        seen["token"] = req.get_header("X-netmon-integration-token")
        seen["timeout"] = kwargs.get("timeout")
        return _Resp()

    monkeypatch.setattr(sentrylog.urllib.request, "urlopen", capture)
    sentrylog.fetch_netmon_events(start="2026-01-01 00:00:00",
                                  end="2026-01-01 06:00:00", device="router")

    assert seen["token"] == "secret-token"
    assert "from=2026-01-01" in seen["url"] and "device=router" in seen["url"]
    assert seen["timeout"] == 1


# --------------------------------------------------------------------------
# Route
# --------------------------------------------------------------------------

def test_timeline_endpoint_returns_the_merged_view(sentrylog, client,
                                                   monkeypatch):
    _insert_log(sentrylog, "10.0.0.5", "sshd: failed login", 15)
    _fake_netmon(monkeypatch, sentrylog, [_netmon_event(16)])

    resp = client.get("/api/timeline?hours=2&device=router")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["count"] == 2
    assert data["netmon_error"] == ""
    assert [i["kind"] for i in data["items"]] == ["device", "log"]


def test_timeline_endpoint_requires_auth_when_auth_is_enabled(sentrylog,
                                                             client):
    with sentrylog._config_lock:
        sentrylog._config["auth_enabled"] = True
        sentrylog._config["users"] = [{
            "username": "admin", "role": "admin",
            "password_hash": sentrylog.hash_password("pw")}]
    assert client.get("/api/timeline").status_code in (401, 403)
