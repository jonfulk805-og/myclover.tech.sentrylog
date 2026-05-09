#!/usr/bin/env python3
"""
MyClover.Tech.SentryLog v1.0 - Log Aggregation & Security Alert Platform

A standalone log aggregation and SIEM-lite product from the MyClover.Tech suite.
Collects syslog from any device, parses and stores logs, fires alerts on pattern
matches, and provides a searchable dashboard.

Can run standalone or as an add-on to MyClover.Tech.netmon.

Features:
  - Syslog receiver (UDP + TCP, RFC 3164 / RFC 5424)
  - Auto-discovery of log sources
  - SQLite storage with configurable retention
  - Pattern-based alert rules with severity filtering
  - Real-time log viewer with search/filter
  - Source management dashboard
  - REST API for all operations
  - Dark-themed web dashboard
  - Netmon add-on integration
"""

import os
import sys
import time
import socket
import struct
import sqlite3
import hashlib
import hmac
import logging
import threading
import datetime
import re
import json as json_mod
import select
import traceback
from pathlib import Path
from collections import defaultdict

# ---------------------------------------------------------------------------
# Optional imports
# ---------------------------------------------------------------------------
try:
    import yaml
except ImportError:
    yaml = None
    print("[WARN] PyYAML not installed. Run: pip install pyyaml")

try:
    from flask import (Flask, jsonify, request, render_template,
                       abort, Response, send_file)
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False
    print("[WARN] Flask not installed. Dashboard disabled. Run: pip install flask")

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
VERSION = "1.0.0"
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "sentrylog.db"
DEFAULT_CFG = BASE_DIR / "sentrylog_config.yaml"

_config = {}
_config_lock = threading.Lock()
_running = True

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("sentrylog")

# ---------------------------------------------------------------------------
# License / Tier System (compatible with netmon keys)
# ---------------------------------------------------------------------------
_LICENSE_SECRET = b"CHANGE-ME-BEFORE-DEPLOYMENT"

TIER_FREE = "community"
TIER_PRO = "pro"
TIER_ENT = "enterprise"

TIER_FEATURES = {
    TIER_FREE: {
        "max_sources": 3,
        "max_log_retention_days": 7,
        "alert_rules": 5,
        "api_access": "read",
        "syslog": True,
        "windows_eventlog": False,
        "api_connectors": False,
        "correlation": False,
    },
    TIER_PRO: {
        "max_sources": 50,
        "max_log_retention_days": 90,
        "alert_rules": 100,
        "api_access": "full",
        "syslog": True,
        "windows_eventlog": False,
        "api_connectors": False,
        "correlation": False,
    },
    TIER_ENT: {
        "max_sources": 9999,
        "max_log_retention_days": 365,
        "alert_rules": 9999,
        "api_access": "full",
        "syslog": True,
        "windows_eventlog": True,
        "api_connectors": True,
        "correlation": True,
    },
}

_current_tier = TIER_FREE


def validate_license_key(key):
    """Validate a license key and return the tier, or None if invalid."""
    if not key or not isinstance(key, str):
        return None
    parts = key.strip().split("-")
    if len(parts) != 3:
        return None
    tier_code, uid, sig = parts
    tier_map = {"PRO": TIER_PRO, "ENT": TIER_ENT}
    if tier_code not in tier_map:
        return None
    payload = "%s-%s" % (tier_code, uid)
    expected = hashlib.sha256(
        _LICENSE_SECRET + payload.encode("utf-8")
    ).hexdigest()[:16].upper()
    if sig.upper() == expected:
        return tier_map[tier_code]
    return None


def get_tier():
    return _current_tier


def get_tier_features():
    return dict(TIER_FEATURES.get(_current_tier, TIER_FEATURES[TIER_FREE]))


def _load_license():
    global _current_tier
    with _config_lock:
        key = _config.get("license_key", "").strip()
    tier = validate_license_key(key)
    if tier:
        _current_tier = tier
        log.info("License validated -- running as %s tier", tier)
    else:
        _current_tier = TIER_FREE
        if key:
            log.warning("Invalid license key -- running as Community (free) tier")
        else:
            log.info("No license key -- running as Community (free) tier")


def require_tier(min_tier):
    """Decorator: reject request if current tier is below min_tier."""
    tier_order = [TIER_FREE, TIER_PRO, TIER_ENT]

    def decorator(f):
        def wrapper(*args, **kwargs):
            cur = tier_order.index(get_tier())
            req = tier_order.index(min_tier)
            if cur < req:
                tier_name = min_tier.capitalize()
                return jsonify({
                    "error": "upgrade_required",
                    "message": "This feature requires a %s license or higher." % tier_name,
                    "current_tier": get_tier(),
                    "required_tier": min_tier,
                    "upgrade_url": "https://myclover.tech/pricing",
                }), 403
            return f(*args, **kwargs)
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Syslog Constants
# ---------------------------------------------------------------------------
SYSLOG_FACILITIES = {
    0: "kern", 1: "user", 2: "mail", 3: "daemon",
    4: "auth", 5: "syslog", 6: "lpr", 7: "news",
    8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp",
    12: "ntp", 13: "audit", 14: "alert", 15: "clock",
    16: "local0", 17: "local1", 18: "local2", 19: "local3",
    20: "local4", 21: "local5", 22: "local6", 23: "local7",
}

SYSLOG_SEVERITIES = {
    0: "emergency", 1: "alert", 2: "critical", 3: "error",
    4: "warning", 5: "notice", 6: "info", 7: "debug",
}

SEVERITY_COLORS = {
    "emergency": "#dc2626",
    "alert": "#ea580c",
    "critical": "#ef4444",
    "error": "#f97316",
    "warning": "#eab308",
    "notice": "#22d3ee",
    "info": "#22c55e",
    "debug": "#6b7280",
}


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
def load_config(path=None):
    global _config
    cfg_path = path or DEFAULT_CFG
    if yaml is None:
        log.error("PyYAML required. pip install pyyaml")
        sys.exit(1)
    if not Path(cfg_path).exists():
        log.warning("Config not found at %s -- using defaults", cfg_path)
        _config = _default_config()
        return _config
    with open(cfg_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    with _config_lock:
        _config = data
    return _config


def save_config(cfg, path=None):
    cfg_path = path or DEFAULT_CFG
    if yaml is None:
        return
    with open(cfg_path, "w", encoding="utf-8") as f:
        yaml.dump(cfg, f, default_flow_style=False, sort_keys=False)


def _default_config():
    return {
        "license_key": "",
        "syslog": {
            "udp_port": 514,
            "tcp_port": 514,
            "udp_enabled": True,
            "tcp_enabled": True,
            "buffer_size": 8192,
        },
        "storage": {
            "retention_days": 30,
            "cleanup_interval_hours": 6,
            "max_db_size_mb": 500,
        },
        "dashboard": {
            "host": "0.0.0.0",
            "port": 8514,
        },
        "alerting": {
            "email": {
                "enabled": False,
                "smtp_host": "",
                "smtp_port": 587,
                "use_tls": True,
                "username": "",
                "password": "",
                "from_addr": "sentrylog@yourdomain.com",
                "recipients": [],
            },
        },
        "netmon_integration": {
            "enabled": False,
            "netmon_url": "http://localhost:8080",
        },
    }


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
def get_db():
    """Get a thread-local database connection."""
    conn = sqlite3.connect(str(DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA cache_size=-8000")  # 8MB cache
    return conn


def init_db():
    """Initialize database tables."""
    conn = get_db()
    c = conn.cursor()

    # Main log storage
    c.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            received_at TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            source_name TEXT DEFAULT '',
            facility TEXT DEFAULT '',
            facility_code INTEGER DEFAULT -1,
            severity TEXT DEFAULT 'info',
            severity_code INTEGER DEFAULT 6,
            app_name TEXT DEFAULT '',
            process_id TEXT DEFAULT '',
            message TEXT NOT NULL,
            raw TEXT DEFAULT ''
        )
    """)

    # Indexes for common queries
    c.execute("""
        CREATE INDEX IF NOT EXISTS idx_logs_timestamp
        ON logs(timestamp DESC)
    """)
    c.execute("""
        CREATE INDEX IF NOT EXISTS idx_logs_source
        ON logs(source_ip, timestamp DESC)
    """)
    c.execute("""
        CREATE INDEX IF NOT EXISTS idx_logs_severity
        ON logs(severity_code, timestamp DESC)
    """)
    c.execute("""
        CREATE INDEX IF NOT EXISTS idx_logs_received
        ON logs(received_at DESC)
    """)

    # Source tracking
    c.execute("""
        CREATE TABLE IF NOT EXISTS sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE NOT NULL,
            name TEXT DEFAULT '',
            device_type TEXT DEFAULT '',
            os_type TEXT DEFAULT '',
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            log_count INTEGER DEFAULT 0,
            enabled INTEGER DEFAULT 1,
            notes TEXT DEFAULT ''
        )
    """)

    # Alert rules
    c.execute("""
        CREATE TABLE IF NOT EXISTS alert_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT DEFAULT '',
            pattern TEXT NOT NULL,
            pattern_type TEXT DEFAULT 'contains',
            severity_filter TEXT DEFAULT '',
            source_filter TEXT DEFAULT '',
            facility_filter TEXT DEFAULT '',
            enabled INTEGER DEFAULT 1,
            action TEXT DEFAULT 'log',
            cooldown_minutes INTEGER DEFAULT 15,
            last_fired TEXT DEFAULT '',
            fire_count INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    # Triggered alerts
    c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id INTEGER,
            rule_name TEXT DEFAULT '',
            log_id INTEGER,
            timestamp TEXT NOT NULL,
            source_ip TEXT DEFAULT '',
            severity TEXT DEFAULT '',
            message TEXT DEFAULT '',
            acknowledged INTEGER DEFAULT 0,
            ack_by TEXT DEFAULT '',
            ack_at TEXT DEFAULT '',
            FOREIGN KEY (rule_id) REFERENCES alert_rules(id),
            FOREIGN KEY (log_id) REFERENCES logs(id)
        )
    """)

    c.execute("""
        CREATE INDEX IF NOT EXISTS idx_alerts_timestamp
        ON alerts(timestamp DESC)
    """)

    conn.commit()
    conn.close()
    log.info("Database initialized at %s", DB_PATH)


# ---------------------------------------------------------------------------
# Syslog Parser
# ---------------------------------------------------------------------------
def parse_syslog_message(data, source_ip):
    """
    Parse a syslog message (RFC 3164 or RFC 5424).
    Returns a dict with parsed fields.
    """
    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    result = {
        "timestamp": now,
        "received_at": now,
        "source_ip": source_ip,
        "source_name": "",
        "facility": "",
        "facility_code": -1,
        "severity": "info",
        "severity_code": 6,
        "app_name": "",
        "process_id": "",
        "message": "",
        "raw": "",
    }

    if isinstance(data, bytes):
        # Try UTF-8 first, fall back to latin-1
        try:
            msg = data.decode("utf-8").strip()
        except UnicodeDecodeError:
            msg = data.decode("latin-1", errors="replace").strip()
    else:
        msg = str(data).strip()

    result["raw"] = msg

    if not msg:
        return result

    # Parse PRI (priority) field: <PRI>
    pri_match = re.match(r"^<(\d{1,3})>(.*)", msg)
    if pri_match:
        try:
            pri = int(pri_match.group(1))
            facility_code = pri >> 3
            severity_code = pri & 7
            result["facility_code"] = facility_code
            result["severity_code"] = severity_code
            result["facility"] = SYSLOG_FACILITIES.get(facility_code, "unknown")
            result["severity"] = SYSLOG_SEVERITIES.get(severity_code, "info")
            msg = pri_match.group(2)
        except (ValueError, IndexError):
            pass

    # Try RFC 5424: VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID
    rfc5424_re = re.compile(
        r"^(\d)\s+"                          # version
        r"(\d{4}-\d{2}-\d{2}T[\d:.+Z-]+)\s+"  # timestamp
        r"(\S+)\s+"                           # hostname
        r"(\S+)\s+"                           # app-name
        r"(\S+)\s+"                           # procid
        r"(\S+)\s*"                           # msgid
        r"(.*)",                              # rest (structured data + msg)
        re.DOTALL
    )
    m5424 = rfc5424_re.match(msg)
    if m5424:
        ts_str = m5424.group(2)
        result["source_name"] = m5424.group(3) if m5424.group(3) != "-" else ""
        result["app_name"] = m5424.group(4) if m5424.group(4) != "-" else ""
        result["process_id"] = m5424.group(5) if m5424.group(5) != "-" else ""
        rest = m5424.group(7).strip()

        # Parse timestamp
        try:
            if "T" in ts_str:
                ts_str_clean = re.sub(r"[Z]$", "+00:00", ts_str)
                ts_str_clean = re.sub(r"(\+\d{2}):(\d{2})$", r"\1\2", ts_str_clean)
                dt = datetime.datetime.fromisoformat(
                    ts_str.replace("Z", "+00:00")
                )
                result["timestamp"] = dt.strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, TypeError):
            pass

        # Skip structured data [...]
        if rest.startswith("["):
            sd_end = rest.rfind("]")
            if sd_end >= 0:
                rest = rest[sd_end + 1:].strip()
            # If starts with BOM after SD
            if rest.startswith("\xef\xbb\xbf"):
                rest = rest[3:]

        result["message"] = rest.strip()
        return result

    # Try RFC 3164: TIMESTAMP HOSTNAME APP[PID]: MSG
    # Timestamp format: "Mon DD HH:MM:SS" or "Mon  D HH:MM:SS"
    rfc3164_re = re.compile(
        r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"  # timestamp
        r"(\S+)\s+"                                               # hostname
        r"(.*)",                                                  # rest
        re.DOTALL
    )
    m3164 = rfc3164_re.match(msg)
    if m3164:
        ts_str = m3164.group(1)
        result["source_name"] = m3164.group(2)
        rest = m3164.group(3).strip()

        # Parse timestamp (add current year)
        try:
            year = datetime.datetime.utcnow().year
            dt = datetime.datetime.strptime(
                "%d %s" % (year, ts_str), "%Y %b %d %H:%M:%S"
            )
            result["timestamp"] = dt.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass

        # Extract app name and PID
        app_match = re.match(r"^(\S+?)(?:\[(\d+)\])?:\s*(.*)", rest, re.DOTALL)
        if app_match:
            result["app_name"] = app_match.group(1)
            result["process_id"] = app_match.group(2) or ""
            result["message"] = app_match.group(3).strip()
        else:
            result["message"] = rest
        return result

    # Fallback -- just store the raw message
    result["message"] = msg
    return result


# ---------------------------------------------------------------------------
# Log Ingestion Engine
# ---------------------------------------------------------------------------
_log_buffer = []
_log_buffer_lock = threading.Lock()
_BUFFER_FLUSH_SIZE = 100
_BUFFER_FLUSH_INTERVAL = 2  # seconds


def ingest_log(parsed):
    """Add a parsed log entry to the buffer for batch insertion."""
    with _log_buffer_lock:
        _log_buffer.append(parsed)
        if len(_log_buffer) >= _BUFFER_FLUSH_SIZE:
            _flush_logs()


def _flush_logs():
    """Flush buffered logs to the database. Must hold _log_buffer_lock."""
    global _log_buffer
    if not _log_buffer:
        return
    batch = _log_buffer[:]
    _log_buffer = []

    try:
        conn = get_db()
        c = conn.cursor()
        for entry in batch:
            c.execute("""
                INSERT INTO logs (timestamp, received_at, source_ip, source_name,
                    facility, facility_code, severity, severity_code,
                    app_name, process_id, message, raw)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                entry["timestamp"], entry["received_at"], entry["source_ip"],
                entry["source_name"], entry["facility"], entry["facility_code"],
                entry["severity"], entry["severity_code"],
                entry["app_name"], entry["process_id"],
                entry["message"], entry["raw"],
            ))

            log_id = c.lastrowid

            # Update source tracking
            c.execute("""
                INSERT INTO sources (ip, name, first_seen, last_seen, log_count)
                VALUES (?, ?, ?, ?, 1)
                ON CONFLICT(ip) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    log_count = log_count + 1,
                    name = CASE WHEN sources.name = '' THEN excluded.name
                           ELSE sources.name END
            """, (
                entry["source_ip"],
                entry["source_name"],
                entry["received_at"],
                entry["received_at"],
            ))

            # Check alert rules
            _check_alert_rules(c, entry, log_id)

        conn.commit()
        conn.close()
    except Exception as e:
        log.error("Failed to flush logs: %s", e)


def _check_alert_rules(cursor, entry, log_id):
    """Check a log entry against all enabled alert rules."""
    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    try:
        rules = cursor.execute(
            "SELECT * FROM alert_rules WHERE enabled = 1"
        ).fetchall()
    except Exception:
        return

    for rule in rules:
        # Check cooldown
        if rule["last_fired"]:
            try:
                last = datetime.datetime.strptime(
                    rule["last_fired"], "%Y-%m-%d %H:%M:%S"
                )
                cooldown = datetime.timedelta(minutes=rule["cooldown_minutes"])
                if datetime.datetime.utcnow() - last < cooldown:
                    continue
            except ValueError:
                pass

        # Check severity filter
        if rule["severity_filter"]:
            allowed = [s.strip().lower() for s in rule["severity_filter"].split(",")]
            if entry["severity"].lower() not in allowed:
                continue

        # Check source filter
        if rule["source_filter"]:
            allowed = [s.strip() for s in rule["source_filter"].split(",")]
            if entry["source_ip"] not in allowed and entry["source_name"] not in allowed:
                continue

        # Check facility filter
        if rule["facility_filter"]:
            allowed = [s.strip().lower() for s in rule["facility_filter"].split(",")]
            if entry["facility"].lower() not in allowed:
                continue

        # Check pattern match
        matched = False
        pattern = rule["pattern"]
        ptype = rule["pattern_type"]
        msg = entry["message"]

        if ptype == "contains":
            matched = pattern.lower() in msg.lower()
        elif ptype == "exact":
            matched = pattern.lower() == msg.lower()
        elif ptype == "regex":
            try:
                matched = bool(re.search(pattern, msg, re.IGNORECASE))
            except re.error:
                pass
        elif ptype == "starts_with":
            matched = msg.lower().startswith(pattern.lower())

        if matched:
            # Fire alert
            cursor.execute("""
                INSERT INTO alerts (rule_id, rule_name, log_id, timestamp,
                    source_ip, severity, message)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                rule["id"], rule["name"], log_id, now,
                entry["source_ip"], entry["severity"],
                entry["message"][:500],
            ))

            cursor.execute("""
                UPDATE alert_rules SET last_fired = ?, fire_count = fire_count + 1
                WHERE id = ?
            """, (now, rule["id"]))

            log.info("[ALERT] Rule '%s' fired on log from %s: %s",
                     rule["name"], entry["source_ip"], entry["message"][:100])


def _buffer_flush_loop():
    """Periodically flush the log buffer."""
    while _running:
        time.sleep(_BUFFER_FLUSH_INTERVAL)
        with _log_buffer_lock:
            if _log_buffer:
                _flush_logs()


# ---------------------------------------------------------------------------
# Syslog Receivers
# ---------------------------------------------------------------------------
def syslog_udp_listener(port=514, buf_size=8192):
    """Listen for syslog messages over UDP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", port))
        sock.settimeout(2.0)
        log.info("Syslog UDP listener started on port %d", port)
    except PermissionError:
        log.error("Permission denied for port %d. Try a port > 1024 or run as admin.", port)
        return
    except OSError as e:
        log.error("Failed to bind UDP port %d: %s", port, e)
        return

    while _running:
        try:
            data, addr = sock.recvfrom(buf_size)
            if data:
                source_ip = addr[0]
                parsed = parse_syslog_message(data, source_ip)
                ingest_log(parsed)
        except socket.timeout:
            continue
        except Exception as e:
            if _running:
                log.error("UDP listener error: %s", e)
            time.sleep(0.1)

    sock.close()
    log.info("Syslog UDP listener stopped")


def _handle_tcp_client(client_sock, addr):
    """Handle a single TCP syslog client connection."""
    source_ip = addr[0]
    buf = b""
    try:
        client_sock.settimeout(30.0)
        while _running:
            try:
                data = client_sock.recv(4096)
                if not data:
                    break
                buf += data
                # Split on newlines (syslog over TCP uses LF as delimiter)
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    line = line.strip()
                    if line:
                        parsed = parse_syslog_message(line, source_ip)
                        ingest_log(parsed)
                # Also handle messages without trailing newline (octet counting)
                if len(buf) > 8192:
                    parsed = parse_syslog_message(buf, source_ip)
                    ingest_log(parsed)
                    buf = b""
            except socket.timeout:
                continue
            except Exception as e:
                if _running:
                    log.debug("TCP client %s error: %s", addr, e)
                break
    finally:
        # Flush remaining buffer
        if buf.strip():
            parsed = parse_syslog_message(buf.strip(), source_ip)
            ingest_log(parsed)
        client_sock.close()


def syslog_tcp_listener(port=514):
    """Listen for syslog messages over TCP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", port))
        sock.listen(50)
        sock.settimeout(2.0)
        log.info("Syslog TCP listener started on port %d", port)
    except PermissionError:
        log.error("Permission denied for port %d. Try a port > 1024 or run as admin.", port)
        return
    except OSError as e:
        log.error("Failed to bind TCP port %d: %s", port, e)
        return

    while _running:
        try:
            client, addr = sock.accept()
            t = threading.Thread(
                target=_handle_tcp_client, args=(client, addr),
                daemon=True
            )
            t.start()
        except socket.timeout:
            continue
        except Exception as e:
            if _running:
                log.error("TCP listener error: %s", e)
            time.sleep(0.1)

    sock.close()
    log.info("Syslog TCP listener stopped")


# ---------------------------------------------------------------------------
# Log Retention / Cleanup
# ---------------------------------------------------------------------------
def cleanup_old_logs():
    """Remove logs older than retention period."""
    features = get_tier_features()
    max_days = features.get("max_log_retention_days", 30)
    with _config_lock:
        cfg_days = _config.get("storage", {}).get("retention_days", 30)
    retention_days = min(cfg_days, max_days)

    cutoff = (
        datetime.datetime.utcnow() - datetime.timedelta(days=retention_days)
    ).strftime("%Y-%m-%d %H:%M:%S")

    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("DELETE FROM logs WHERE received_at < ?", (cutoff,))
        deleted = c.rowcount
        c.execute("DELETE FROM alerts WHERE timestamp < ?", (cutoff,))
        conn.commit()
        conn.close()
        if deleted > 0:
            log.info("Cleanup: removed %d logs older than %d days", deleted, retention_days)
    except Exception as e:
        log.error("Cleanup error: %s", e)


def cleanup_loop():
    """Periodic cleanup loop."""
    while _running:
        with _config_lock:
            interval = _config.get("storage", {}).get("cleanup_interval_hours", 6)
        cleanup_old_logs()
        for _ in range(int(interval * 3600)):
            if not _running:
                break
            time.sleep(1)


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------
def get_stats(hours=24):
    """Get dashboard statistics."""
    cutoff = (
        datetime.datetime.utcnow() - datetime.timedelta(hours=hours)
    ).strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db()
    c = conn.cursor()

    stats = {}

    # Total logs in period
    row = c.execute(
        "SELECT COUNT(*) FROM logs WHERE received_at >= ?", (cutoff,)
    ).fetchone()
    stats["total_logs"] = row[0] if row else 0

    # Total logs all time
    row = c.execute("SELECT COUNT(*) FROM logs").fetchone()
    stats["total_logs_all"] = row[0] if row else 0

    # Active sources
    row = c.execute(
        "SELECT COUNT(*) FROM sources WHERE last_seen >= ?", (cutoff,)
    ).fetchone()
    stats["active_sources"] = row[0] if row else 0

    # Total sources
    row = c.execute("SELECT COUNT(*) FROM sources").fetchone()
    stats["total_sources"] = row[0] if row else 0

    # Unacknowledged alerts
    row = c.execute(
        "SELECT COUNT(*) FROM alerts WHERE acknowledged = 0"
    ).fetchone()
    stats["unacked_alerts"] = row[0] if row else 0

    # Severity breakdown in period
    severity_rows = c.execute("""
        SELECT severity, COUNT(*) as cnt
        FROM logs WHERE received_at >= ?
        GROUP BY severity ORDER BY cnt DESC
    """, (cutoff,)).fetchall()
    stats["severity_breakdown"] = {r["severity"]: r["cnt"] for r in severity_rows}

    # Top sources in period
    source_rows = c.execute("""
        SELECT source_ip, source_name, COUNT(*) as cnt
        FROM logs WHERE received_at >= ?
        GROUP BY source_ip ORDER BY cnt DESC LIMIT 10
    """, (cutoff,)).fetchall()
    stats["top_sources"] = [
        {"ip": r["source_ip"], "name": r["source_name"], "count": r["cnt"]}
        for r in source_rows
    ]

    # Top facilities in period
    fac_rows = c.execute("""
        SELECT facility, COUNT(*) as cnt
        FROM logs WHERE received_at >= ?
        GROUP BY facility ORDER BY cnt DESC LIMIT 10
    """, (cutoff,)).fetchall()
    stats["top_facilities"] = {r["facility"]: r["cnt"] for r in fac_rows}

    # Logs per hour (for chart)
    hourly = c.execute("""
        SELECT strftime('%%Y-%%m-%%d %%H:00:00', received_at) as hour,
               COUNT(*) as cnt
        FROM logs WHERE received_at >= ?
        GROUP BY hour ORDER BY hour
    """, (cutoff,)).fetchall()
    stats["hourly_volume"] = [
        {"hour": r["hour"], "count": r["cnt"]} for r in hourly
    ]

    # Recent alerts
    recent_alerts = c.execute("""
        SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 10
    """).fetchall()
    stats["recent_alerts"] = [dict(r) for r in recent_alerts]

    # Alert rules count
    row = c.execute("SELECT COUNT(*) FROM alert_rules WHERE enabled = 1").fetchone()
    stats["active_rules"] = row[0] if row else 0

    conn.close()
    return stats


# ---------------------------------------------------------------------------
# Flask Dashboard & API
# ---------------------------------------------------------------------------
if HAS_FLASK:
    app = Flask(__name__, template_folder=str(BASE_DIR / "templates"))

    @app.route("/")
    def dashboard():
        return render_template("sentrylog.html")

    # ---- Stats ----
    @app.route("/api/stats")
    def api_stats():
        hours = request.args.get("hours", 24, type=int)
        return jsonify(get_stats(hours))

    # ---- Logs ----
    @app.route("/api/logs")
    def api_logs():
        limit = request.args.get("limit", 200, type=int)
        offset = request.args.get("offset", 0, type=int)
        severity = request.args.get("severity", "")
        source = request.args.get("source", "")
        facility = request.args.get("facility", "")
        search = request.args.get("search", "")
        hours = request.args.get("hours", 24, type=int)
        sort = request.args.get("sort", "desc")

        cutoff = (
            datetime.datetime.utcnow() - datetime.timedelta(hours=hours)
        ).strftime("%Y-%m-%d %H:%M:%S")

        conn = get_db()
        c = conn.cursor()

        where = ["received_at >= ?"]
        params = [cutoff]

        if severity:
            sevs = [s.strip().lower() for s in severity.split(",")]
            placeholders = ",".join(["?"] * len(sevs))
            where.append("severity IN (%s)" % placeholders)
            params.extend(sevs)

        if source:
            where.append("(source_ip = ? OR source_name = ?)")
            params.extend([source, source])

        if facility:
            where.append("facility = ?")
            params.append(facility)

        if search:
            where.append("(message LIKE ? OR app_name LIKE ? OR source_name LIKE ?)")
            like = "%" + search + "%"
            params.extend([like, like, like])

        where_clause = " AND ".join(where)
        order = "DESC" if sort == "desc" else "ASC"

        # Get total count
        count_row = c.execute(
            "SELECT COUNT(*) FROM logs WHERE %s" % where_clause, params
        ).fetchone()
        total = count_row[0] if count_row else 0

        # Get page
        rows = c.execute(
            "SELECT * FROM logs WHERE %s ORDER BY timestamp %s LIMIT ? OFFSET ?"
            % (where_clause, order),
            params + [min(limit, 1000), offset]
        ).fetchall()

        conn.close()

        return jsonify({
            "total": total,
            "limit": limit,
            "offset": offset,
            "logs": [dict(r) for r in rows],
        })

    @app.route("/api/logs/latest")
    def api_logs_latest():
        """Get latest logs since a given ID (for live view polling)."""
        since_id = request.args.get("since_id", 0, type=int)
        limit = request.args.get("limit", 50, type=int)

        conn = get_db()
        rows = conn.execute(
            "SELECT * FROM logs WHERE id > ? ORDER BY id DESC LIMIT ?",
            (since_id, min(limit, 500))
        ).fetchall()
        conn.close()

        return jsonify({
            "logs": [dict(r) for r in rows],
        })

    # ---- Sources ----
    @app.route("/api/sources")
    def api_sources():
        conn = get_db()
        rows = conn.execute(
            "SELECT * FROM sources ORDER BY last_seen DESC"
        ).fetchall()
        conn.close()
        return jsonify({"sources": [dict(r) for r in rows]})

    @app.route("/api/sources/<int:source_id>", methods=["PUT"])
    def api_update_source(source_id):
        data = request.get_json(force=True)
        conn = get_db()
        conn.execute("""
            UPDATE sources SET name = ?, device_type = ?, os_type = ?,
                notes = ?, enabled = ?
            WHERE id = ?
        """, (
            data.get("name", ""),
            data.get("device_type", ""),
            data.get("os_type", ""),
            data.get("notes", ""),
            1 if data.get("enabled", True) else 0,
            source_id,
        ))
        conn.commit()
        conn.close()
        return jsonify({"status": "ok"})

    @app.route("/api/sources/<int:source_id>", methods=["DELETE"])
    def api_delete_source(source_id):
        conn = get_db()
        conn.execute("DELETE FROM sources WHERE id = ?", (source_id,))
        conn.commit()
        conn.close()
        return jsonify({"status": "ok"})

    # ---- Alert Rules ----
    @app.route("/api/rules")
    def api_rules():
        conn = get_db()
        rows = conn.execute(
            "SELECT * FROM alert_rules ORDER BY created_at DESC"
        ).fetchall()
        conn.close()
        return jsonify({"rules": [dict(r) for r in rows]})

    @app.route("/api/rules", methods=["POST"])
    def api_create_rule():
        data = request.get_json(force=True)
        now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

        # Check rule limit
        features = get_tier_features()
        conn = get_db()
        count = conn.execute(
            "SELECT COUNT(*) FROM alert_rules"
        ).fetchone()[0]
        if count >= features.get("alert_rules", 5):
            conn.close()
            return jsonify({
                "error": "limit_reached",
                "message": "Alert rule limit reached for your tier (%d). Upgrade for more." % features["alert_rules"],
            }), 403

        conn.execute("""
            INSERT INTO alert_rules (name, description, pattern, pattern_type,
                severity_filter, source_filter, facility_filter,
                enabled, action, cooldown_minutes, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data.get("name", "Unnamed Rule"),
            data.get("description", ""),
            data.get("pattern", ""),
            data.get("pattern_type", "contains"),
            data.get("severity_filter", ""),
            data.get("source_filter", ""),
            data.get("facility_filter", ""),
            1 if data.get("enabled", True) else 0,
            data.get("action", "log"),
            data.get("cooldown_minutes", 15),
            now, now,
        ))
        conn.commit()
        rule_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.close()
        return jsonify({"status": "ok", "id": rule_id})

    @app.route("/api/rules/<int:rule_id>", methods=["PUT"])
    def api_update_rule(rule_id):
        data = request.get_json(force=True)
        now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        conn = get_db()
        conn.execute("""
            UPDATE alert_rules SET name = ?, description = ?, pattern = ?,
                pattern_type = ?, severity_filter = ?, source_filter = ?,
                facility_filter = ?, enabled = ?, action = ?,
                cooldown_minutes = ?, updated_at = ?
            WHERE id = ?
        """, (
            data.get("name", ""),
            data.get("description", ""),
            data.get("pattern", ""),
            data.get("pattern_type", "contains"),
            data.get("severity_filter", ""),
            data.get("source_filter", ""),
            data.get("facility_filter", ""),
            1 if data.get("enabled", True) else 0,
            data.get("action", "log"),
            data.get("cooldown_minutes", 15),
            now, rule_id,
        ))
        conn.commit()
        conn.close()
        return jsonify({"status": "ok"})

    @app.route("/api/rules/<int:rule_id>", methods=["DELETE"])
    def api_delete_rule(rule_id):
        conn = get_db()
        conn.execute("DELETE FROM alert_rules WHERE id = ?", (rule_id,))
        conn.commit()
        conn.close()
        return jsonify({"status": "ok"})

    # ---- Alerts ----
    @app.route("/api/alerts")
    def api_alerts():
        limit = request.args.get("limit", 100, type=int)
        unacked_only = request.args.get("unacked", "false").lower() == "true"
        conn = get_db()
        if unacked_only:
            rows = conn.execute(
                "SELECT * FROM alerts WHERE acknowledged = 0 ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            ).fetchall()
        conn.close()
        return jsonify({"alerts": [dict(r) for r in rows]})

    @app.route("/api/alerts/<int:alert_id>/ack", methods=["POST"])
    def api_ack_alert(alert_id):
        now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        conn = get_db()
        conn.execute("""
            UPDATE alerts SET acknowledged = 1, ack_at = ?, ack_by = 'dashboard'
            WHERE id = ?
        """, (now, alert_id))
        conn.commit()
        conn.close()
        return jsonify({"status": "ok"})

    @app.route("/api/alerts/ack-all", methods=["POST"])
    def api_ack_all_alerts():
        now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        conn = get_db()
        conn.execute("""
            UPDATE alerts SET acknowledged = 1, ack_at = ?, ack_by = 'dashboard'
            WHERE acknowledged = 0
        """, (now,))
        conn.commit()
        conn.close()
        return jsonify({"status": "ok"})

    # ---- License ----
    @app.route("/api/license")
    def api_license():
        features = get_tier_features()
        conn = get_db()
        source_count = conn.execute("SELECT COUNT(*) FROM sources").fetchone()[0]
        rule_count = conn.execute("SELECT COUNT(*) FROM alert_rules").fetchone()[0]
        conn.close()
        return jsonify({
            "tier": get_tier(),
            "features": features,
            "usage": {
                "sources": source_count,
                "max_sources": features["max_sources"],
                "alert_rules": rule_count,
                "max_alert_rules": features["alert_rules"],
            },
        })

    @app.route("/api/license", methods=["POST"])
    def api_activate_license():
        global _current_tier
        data = request.get_json(force=True)
        key = data.get("key", "").strip()
        tier = validate_license_key(key)
        if tier:
            _current_tier = tier
            with _config_lock:
                _config["license_key"] = key
            save_config(_config)
            return jsonify({
                "status": "ok",
                "tier": tier,
                "features": get_tier_features(),
            })
        return jsonify({"error": "invalid_key", "message": "Invalid license key."}), 400

    # ---- Config ----
    @app.route("/api/config")
    def api_get_config():
        safe = {}
        with _config_lock:
            safe["syslog"] = _config.get("syslog", {})
            safe["storage"] = _config.get("storage", {})
            safe["dashboard"] = _config.get("dashboard", {})
            safe["netmon_integration"] = _config.get("netmon_integration", {})
        return jsonify(safe)

    @app.route("/api/config", methods=["PUT"])
    def api_update_config():
        data = request.get_json(force=True)
        with _config_lock:
            for key in ["syslog", "storage", "dashboard", "netmon_integration"]:
                if key in data:
                    if key not in _config:
                        _config[key] = {}
                    _config[key].update(data[key])
        save_config(_config)
        return jsonify({"status": "ok"})

    # ---- Test / Utility ----
    @app.route("/api/test-log", methods=["POST"])
    def api_test_log():
        """Inject a test log entry (useful for testing without real syslog sources)."""
        data = request.get_json(force=True)
        now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        entry = {
            "timestamp": now,
            "received_at": now,
            "source_ip": data.get("source_ip", "127.0.0.1"),
            "source_name": data.get("source_name", "test-host"),
            "facility": data.get("facility", "local0"),
            "facility_code": data.get("facility_code", 16),
            "severity": data.get("severity", "info"),
            "severity_code": data.get("severity_code", 6),
            "app_name": data.get("app_name", "test"),
            "process_id": data.get("process_id", ""),
            "message": data.get("message", "Test log entry from SentryLog dashboard"),
            "raw": data.get("raw", ""),
        }
        ingest_log(entry)
        # Force flush so it shows up immediately
        with _log_buffer_lock:
            _flush_logs()
        return jsonify({"status": "ok", "entry": entry})

    @app.route("/api/version")
    def api_version():
        return jsonify({
            "product": "MyClover.Tech.SentryLog",
            "version": VERSION,
            "tier": get_tier(),
        })


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    global _running

    print("=" * 60)
    print("  MyClover.Tech.SentryLog v%s" % VERSION)
    print("  Log Aggregation & Security Alert Platform")
    print("=" * 60)
    print()

    # Load config
    cfg = load_config()
    if not cfg or cfg == _default_config():
        log.info("No config found -- creating default sentrylog_config.yaml")
        cfg = _default_config()
        with _config_lock:
            globals()["_config"] = cfg
        save_config(cfg)

    # Load license
    _load_license()

    # Init database
    init_db()

    # Start syslog listeners
    syslog_cfg = cfg.get("syslog", {})
    threads = []

    if syslog_cfg.get("udp_enabled", True):
        udp_port = syslog_cfg.get("udp_port", 514)
        t = threading.Thread(
            target=syslog_udp_listener,
            args=(udp_port, syslog_cfg.get("buffer_size", 8192)),
            daemon=True
        )
        t.start()
        threads.append(t)

    if syslog_cfg.get("tcp_enabled", True):
        tcp_port = syslog_cfg.get("tcp_port", 514)
        t = threading.Thread(
            target=syslog_tcp_listener, args=(tcp_port,), daemon=True
        )
        t.start()
        threads.append(t)

    # Start buffer flush loop
    t = threading.Thread(target=_buffer_flush_loop, daemon=True)
    t.start()
    threads.append(t)

    # Start cleanup loop
    t = threading.Thread(target=cleanup_loop, daemon=True)
    t.start()
    threads.append(t)

    # Start dashboard
    if HAS_FLASK:
        dash_cfg = cfg.get("dashboard", {})
        host = dash_cfg.get("host", "0.0.0.0")
        port = dash_cfg.get("port", 8514)
        print()
        log.info("Dashboard: http://localhost:%d", port)
        print()

        try:
            app.run(host=host, port=port, debug=False, threaded=True)
        except KeyboardInterrupt:
            pass
    else:
        log.warning("Flask not installed -- running in headless mode (syslog only)")
        try:
            while _running:
                time.sleep(1)
        except KeyboardInterrupt:
            pass

    _running = False
    log.info("SentryLog shutting down...")


if __name__ == "__main__":
    main()
