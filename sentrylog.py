#!/usr/bin/env python3
"""
MyClover.Tech.SentryLog v6.0 - Log Aggregation & Security Alert Platform

A standalone log aggregation and SIEM-lite product from the MyClover.Tech suite.
Collects syslog from any device, reads Windows/Linux/Mac log files locally or
remotely, parses and stores logs, fires alerts on pattern matches, and provides
a searchable dashboard with compliance reporting.

Can run standalone or as an add-on to MyClover.Tech.netmon.

Features:
  Phase 1: Core syslog receiver, SQLite storage, alert rules, dashboard, API
  Phase 2: Windows Event Log (local pywin32 + remote WinRM)
  Phase 3: Security vendor connectors (CrowdStrike, SentinelOne, Defender,
           Sophos, Cortex XDR, generic REST)
  Phase 4: Cross-source correlation engine, compliance report generator
  Phase 5: Email/webhook notifications, scheduled reports, log search &
           export (CSV/JSON), dashboard chart enhancements
  Phase 6: Linux/Mac log file tailing, log forwarding to external SIEM,
           API key authentication, rate limiting
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
import csv
import io
import smtplib
import secrets
import functools
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
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

# Phase 2: Windows Event Log support
HAS_WIN32 = False
HAS_WINRM = False

try:
    import win32evtlog
    import win32evtlogutil
    import win32con
    import win32security
    HAS_WIN32 = True
except ImportError:
    pass  # pywin32 not installed -- local Windows Event Log disabled

try:
    import winrm
    HAS_WINRM = True
except ImportError:
    pass  # pywinrm not installed -- remote Windows Event Log disabled

# Phase 3: Security API connectors
HAS_REQUESTS = False

try:
    import requests as requests_lib
    HAS_REQUESTS = True
except ImportError:
    pass  # requests not installed -- security API connectors disabled

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
VERSION = "6.0.0"
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "sentrylog.db"
DEFAULT_CFG = BASE_DIR / "sentrylog_config.yaml"

_config = {}
_config_lock = threading.Lock()
_running = True
_stop_event = threading.Event()

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
        "email_notifications": False,
        "scheduled_reports": False,
        "log_export": False,
        "file_tailing": False,
        "log_forwarding": False,
        "api_keys": False,
        "max_file_targets": 0,
        "max_forwarding_targets": 0,
    },
    TIER_PRO: {
        "max_sources": 50,
        "max_log_retention_days": 90,
        "alert_rules": 100,
        "api_access": "full",
        "syslog": True,
        "windows_eventlog": False,
        "api_connectors": False,
        "correlation": True,
        "email_notifications": True,
        "scheduled_reports": False,
        "log_export": True,
        "file_tailing": True,
        "log_forwarding": True,
        "api_keys": True,
        "max_file_targets": 10,
        "max_forwarding_targets": 3,
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
        "email_notifications": True,
        "scheduled_reports": True,
        "log_export": True,
        "file_tailing": True,
        "log_forwarding": True,
        "api_keys": True,
        "max_file_targets": 9999,
        "max_forwarding_targets": 9999,
    },
}

_current_tier = TIER_FREE


def validate_license_key(key):
    """Validate a license key and return the tier, or None if invalid."""
    if not key or not isinstance(key, str):
        return None
    parts = key.strip().upper().split("-")
    if len(parts) != 3:
        return None
    tier_code, unique_id, provided_sig = parts
    tier_map = {"PRO": TIER_PRO, "ENT": TIER_ENT}
    if tier_code not in tier_map:
        return None
    payload = "%s-%s" % (tier_code, unique_id)
    expected_sig = hashlib.sha256(
        _LICENSE_SECRET + payload.encode("utf-8")
    ).hexdigest()[:16].upper()
    if provided_sig != expected_sig:
        return None
    return tier_map[tier_code]


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
        "notifications": {
            "email_enabled": False,
            "webhook_enabled": False,
            "webhook_url": "",
            "cooldown_minutes": 5,
        },
        "file_targets": [],
        "forwarding": {
            "targets": [],
        },
        "api_auth": {
            "enabled": False,
            "rate_limit_per_minute": 120,
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

    # Phase 2: Windows Event Log targets
    c.execute("""
        CREATE TABLE IF NOT EXISTS winlog_targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            target_type TEXT NOT NULL DEFAULT 'local',
            hostname TEXT DEFAULT 'localhost',
            username TEXT DEFAULT '',
            password TEXT DEFAULT '',
            use_ssl INTEGER DEFAULT 0,
            port INTEGER DEFAULT 5985,
            channels TEXT DEFAULT 'Security,System,Application',
            poll_interval_seconds INTEGER DEFAULT 60,
            enabled INTEGER DEFAULT 1,
            last_poll TEXT DEFAULT '',
            last_bookmark TEXT DEFAULT '',
            log_count INTEGER DEFAULT 0,
            error_message TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    # Phase 3: Security API connectors
    c.execute("""
        CREATE TABLE IF NOT EXISTS security_connectors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            connector_type TEXT NOT NULL,
            api_url TEXT DEFAULT '',
            api_key TEXT DEFAULT '',
            api_secret TEXT DEFAULT '',
            extra_config TEXT DEFAULT '{}',
            poll_interval_seconds INTEGER DEFAULT 300,
            enabled INTEGER DEFAULT 1,
            last_poll TEXT DEFAULT '',
            last_cursor TEXT DEFAULT '',
            log_count INTEGER DEFAULT 0,
            error_message TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    # Phase 3: Inbound webhook tokens
    c.execute("""
        CREATE TABLE IF NOT EXISTS webhook_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT NOT NULL UNIQUE,
            label TEXT DEFAULT '',
            source_name TEXT DEFAULT 'webhook',
            enabled INTEGER DEFAULT 1,
            log_count INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        )
    """)

    # Phase 4: Correlation rules
    c.execute("""
        CREATE TABLE IF NOT EXISTS correlation_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT DEFAULT '',
            conditions TEXT NOT NULL DEFAULT '[]',
            time_window_seconds INTEGER DEFAULT 300,
            min_matches INTEGER DEFAULT 2,
            severity TEXT DEFAULT 'critical',
            enabled INTEGER DEFAULT 1,
            cooldown_minutes INTEGER DEFAULT 30,
            last_fired TEXT DEFAULT '',
            fire_count INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    # Phase 4: Correlation incidents
    c.execute("""
        CREATE TABLE IF NOT EXISTS correlation_incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id INTEGER,
            rule_name TEXT DEFAULT '',
            severity TEXT DEFAULT 'critical',
            matched_events TEXT DEFAULT '[]',
            matched_count INTEGER DEFAULT 0,
            summary TEXT DEFAULT '',
            status TEXT DEFAULT 'open',
            acknowledged INTEGER DEFAULT 0,
            ack_by TEXT DEFAULT '',
            ack_at TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            FOREIGN KEY (rule_id) REFERENCES correlation_rules(id)
        )
    """)

    c.execute("""
        CREATE INDEX IF NOT EXISTS idx_corr_incidents_created
        ON correlation_incidents(created_at DESC)
    """)

    # Phase 4: Compliance reports
    c.execute("""
        CREATE TABLE IF NOT EXISTS compliance_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            template TEXT NOT NULL,
            title TEXT DEFAULT '',
            date_from TEXT NOT NULL,
            date_to TEXT NOT NULL,
            parameters TEXT DEFAULT '{}',
            status TEXT DEFAULT 'pending',
            html_content TEXT DEFAULT '',
            summary TEXT DEFAULT '',
            generated_at TEXT DEFAULT '',
            created_at TEXT NOT NULL
        )
    """)

    # Phase 5: Notification channels
    c.execute("""
        CREATE TABLE IF NOT EXISTS notification_channels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            channel_type TEXT NOT NULL DEFAULT 'email',
            config TEXT DEFAULT '{}',
            enabled INTEGER DEFAULT 1,
            last_sent TEXT DEFAULT '',
            send_count INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        )
    """)

    # Phase 5: Notification log
    c.execute("""
        CREATE TABLE IF NOT EXISTS notification_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            channel_id INTEGER,
            channel_name TEXT DEFAULT '',
            alert_id INTEGER,
            subject TEXT DEFAULT '',
            status TEXT DEFAULT 'sent',
            error_message TEXT DEFAULT '',
            sent_at TEXT NOT NULL
        )
    """)

    # Phase 5: Scheduled reports
    c.execute("""
        CREATE TABLE IF NOT EXISTS scheduled_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            template TEXT NOT NULL DEFAULT 'custom',
            schedule TEXT NOT NULL DEFAULT 'weekly',
            recipients TEXT DEFAULT '[]',
            parameters TEXT DEFAULT '{}',
            enabled INTEGER DEFAULT 1,
            last_run TEXT DEFAULT '',
            next_run TEXT DEFAULT '',
            run_count INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    # Phase 6: Log file targets (Linux/Mac file tailing)
    c.execute("""
        CREATE TABLE IF NOT EXISTS file_targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            file_path TEXT NOT NULL,
            parse_format TEXT DEFAULT 'auto',
            source_name TEXT DEFAULT '',
            default_facility TEXT DEFAULT 'local0',
            default_severity TEXT DEFAULT 'info',
            enabled INTEGER DEFAULT 1,
            last_position INTEGER DEFAULT 0,
            last_inode INTEGER DEFAULT 0,
            last_read TEXT DEFAULT '',
            log_count INTEGER DEFAULT 0,
            error_message TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    # Phase 6: Log forwarding targets
    c.execute("""
        CREATE TABLE IF NOT EXISTS forwarding_targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            target_type TEXT NOT NULL DEFAULT 'syslog',
            host TEXT DEFAULT '',
            port INTEGER DEFAULT 514,
            protocol TEXT DEFAULT 'udp',
            webhook_url TEXT DEFAULT '',
            filter_severity TEXT DEFAULT '',
            filter_source TEXT DEFAULT '',
            filter_facility TEXT DEFAULT '',
            format TEXT DEFAULT 'rfc3164',
            enabled INTEGER DEFAULT 1,
            last_forwarded TEXT DEFAULT '',
            forward_count INTEGER DEFAULT 0,
            error_message TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    # Phase 6: API keys
    c.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_hash TEXT NOT NULL UNIQUE,
            key_prefix TEXT NOT NULL,
            label TEXT NOT NULL,
            permissions TEXT DEFAULT 'read',
            enabled INTEGER DEFAULT 1,
            last_used TEXT DEFAULT '',
            use_count INTEGER DEFAULT 0,
            rate_limit INTEGER DEFAULT 120,
            created_at TEXT NOT NULL,
            expires_at TEXT DEFAULT ''
        )
    """)

    # Phase 6: Rate limiting tracker (in-memory, but log to DB for audit)
    c.execute("""
        CREATE INDEX IF NOT EXISTS idx_api_keys_hash
        ON api_keys(key_hash)
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
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

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
                # Convert to local time if timezone-aware
                if dt.tzinfo is not None:
                    dt = dt.astimezone().replace(tzinfo=None)
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
            year = datetime.datetime.now().year
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
    # Phase 4: Feed correlation engine
    _corr_add_event(parsed)

    # Phase 6: Forward log to external targets
    try:
        forward_log(parsed)
    except Exception:
        pass

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
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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
                if datetime.datetime.now() - last < cooldown:
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

            # Phase 5: Send notifications for this alert
            _send_alert_notifications(
                cursor, rule["name"], entry["severity"],
                entry["source_ip"], entry["message"][:500]
            )


# ---------------------------------------------------------------------------
# Phase 5: Email & Webhook Notification Engine
# ---------------------------------------------------------------------------
_notification_cooldown = {}  # channel_id -> last_sent_timestamp
_notification_lock = threading.Lock()


def _send_email(smtp_host, smtp_port, use_tls, username, password,
                from_addr, to_addrs, subject, body_html):
    """Send an email via SMTP. Returns (success, error_msg)."""
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = from_addr
        msg["To"] = ", ".join(to_addrs) if isinstance(to_addrs, list) else to_addrs
        msg.attach(MIMEText(body_html, "html", "utf-8"))

        if use_tls:
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=15)
            server.starttls()
        else:
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=15)
        if username and password:
            server.login(username, password)
        recipients = to_addrs if isinstance(to_addrs, list) else [to_addrs]
        server.sendmail(from_addr, recipients, msg.as_string())
        server.quit()
        return True, ""
    except Exception as exc:
        return False, str(exc)


def _send_webhook(url, payload):
    """Send a JSON payload to a webhook URL. Returns (success, error_msg)."""
    if not HAS_REQUESTS:
        return False, "requests library not installed"
    try:
        resp = requests_lib.post(url, json=payload, timeout=10)
        if resp.status_code < 300:
            return True, ""
        return False, "HTTP %d: %s" % (resp.status_code, resp.text[:200])
    except Exception as exc:
        return False, str(exc)


def _send_alert_notifications(cursor, rule_name, severity, source_ip, message):
    """Send alert notifications to all enabled channels."""
    features = get_tier_features()
    if not features.get("email_notifications"):
        return

    now = datetime.datetime.now()
    now_str = now.strftime("%Y-%m-%d %H:%M:%S")

    # Global notification cooldown
    with _config_lock:
        cooldown_min = _config.get("notifications", {}).get("cooldown_minutes", 5)

    try:
        channels = cursor.execute(
            "SELECT * FROM notification_channels WHERE enabled = 1"
        ).fetchall()
    except Exception:
        return

    for ch in channels:
        ch_id = ch["id"]
        ch_type = ch["channel_type"]

        # Per-channel cooldown
        with _notification_lock:
            last = _notification_cooldown.get(ch_id)
            if last:
                if (now - last).total_seconds() < cooldown_min * 60:
                    continue
            _notification_cooldown[ch_id] = now

        try:
            ch_config = json_mod.loads(ch["config"]) if ch["config"] else {}
        except (json_mod.JSONDecodeError, TypeError):
            ch_config = {}

        success = False
        error = ""

        if ch_type == "email":
            smtp_cfg = ch_config
            subject = "[SentryLog Alert] %s - %s from %s" % (
                severity.upper(), rule_name, source_ip)
            body = (
                "<html><body style='font-family:sans-serif;background:#1a1a2e;"
                "color:#e0e0e0;padding:24px'>"
                "<h2 style='color:#ef4444'>SentryLog Alert</h2>"
                "<table style='border-collapse:collapse'>"
                "<tr><td style='padding:6px 12px;color:#888'>Rule:</td>"
                "<td style='padding:6px 12px;font-weight:bold'>%s</td></tr>"
                "<tr><td style='padding:6px 12px;color:#888'>Severity:</td>"
                "<td style='padding:6px 12px;color:#ef4444;font-weight:bold'>%s</td></tr>"
                "<tr><td style='padding:6px 12px;color:#888'>Source:</td>"
                "<td style='padding:6px 12px'>%s</td></tr>"
                "<tr><td style='padding:6px 12px;color:#888'>Time:</td>"
                "<td style='padding:6px 12px'>%s UTC</td></tr>"
                "</table>"
                "<pre style='background:#111;padding:16px;border-radius:8px;"
                "margin-top:16px;white-space:pre-wrap'>%s</pre>"
                "<hr style='border-color:#333;margin-top:24px'>"
                "<p style='color:#666;font-size:12px'>MyClover.Tech.SentryLog v%s</p>"
                "</body></html>"
            ) % (_html_esc(rule_name), _html_esc(severity.upper()),
                 _html_esc(source_ip), _html_esc(now_str),
                 _html_esc(message), VERSION)
            recipients = smtp_cfg.get("recipients", [])
            if not recipients:
                with _config_lock:
                    recipients = _config.get("alerting", {}).get(
                        "email", {}).get("recipients", [])
            if recipients:
                with _config_lock:
                    ecfg = _config.get("alerting", {}).get("email", {})
                success, error = _send_email(
                    smtp_cfg.get("smtp_host", ecfg.get("smtp_host", "")),
                    smtp_cfg.get("smtp_port", ecfg.get("smtp_port", 587)),
                    smtp_cfg.get("use_tls", ecfg.get("use_tls", True)),
                    smtp_cfg.get("username", ecfg.get("username", "")),
                    smtp_cfg.get("password", ecfg.get("password", "")),
                    smtp_cfg.get("from_addr", ecfg.get("from_addr", "")),
                    recipients, subject, body,
                )
        elif ch_type == "webhook":
            wh_url = ch_config.get("url", "")
            if wh_url:
                payload = {
                    "product": "SentryLog",
                    "version": VERSION,
                    "event": "alert",
                    "rule_name": rule_name,
                    "severity": severity,
                    "source_ip": source_ip,
                    "message": message,
                    "timestamp": now_str,
                }
                success, error = _send_webhook(wh_url, payload)

        # Log the notification
        status = "sent" if success else "failed"
        try:
            cursor.execute(
                "INSERT INTO notification_log "
                "(channel_id, channel_name, alert_id, subject, status, "
                " error_message, sent_at) "
                "VALUES (?, ?, 0, ?, ?, ?, ?)",
                (ch_id, ch["name"], rule_name, status, error, now_str)
            )
            cursor.execute(
                "UPDATE notification_channels SET last_sent = ?, "
                "send_count = send_count + 1 WHERE id = ?",
                (now_str, ch_id)
            )
        except Exception:
            pass

        if success:
            log.info("[Notification] Sent to '%s' (%s)", ch["name"], ch_type)
        elif error:
            log.warning("[Notification] Failed '%s': %s", ch["name"], error)


# ---------------------------------------------------------------------------
# Phase 5: Scheduled Report Engine
# ---------------------------------------------------------------------------
def _compute_next_run(schedule, last_run_str=""):
    """Compute the next run time for a schedule (daily, weekly, monthly)."""
    now = datetime.datetime.now()
    if schedule == "daily":
        # Run at 06:00 UTC each day
        nxt = now.replace(hour=6, minute=0, second=0, microsecond=0)
        if nxt <= now:
            nxt += datetime.timedelta(days=1)
    elif schedule == "weekly":
        # Run Monday at 06:00 UTC
        nxt = now.replace(hour=6, minute=0, second=0, microsecond=0)
        days_ahead = 0 - nxt.weekday()  # Monday=0
        if days_ahead <= 0:
            days_ahead += 7
        nxt += datetime.timedelta(days=days_ahead)
    elif schedule == "monthly":
        # Run 1st of month at 06:00 UTC
        if now.day == 1 and now.hour < 6:
            nxt = now.replace(day=1, hour=6, minute=0, second=0, microsecond=0)
        else:
            month = now.month + 1
            year = now.year
            if month > 12:
                month = 1
                year += 1
            nxt = datetime.datetime(year, month, 1, 6, 0, 0)
    else:
        nxt = now + datetime.timedelta(hours=24)
    return nxt.strftime("%Y-%m-%d %H:%M:%S")


def _scheduled_report_loop():
    """Background thread that checks and generates scheduled reports."""
    while not _stop_event.is_set():
        try:
            _check_scheduled_reports()
        except Exception as exc:
            log.error("[ScheduledReports] Error: %s", exc)
        _stop_event.wait(60)  # check every minute


def _check_scheduled_reports():
    """Check if any scheduled reports need to run."""
    features = get_tier_features()
    if not features.get("scheduled_reports"):
        return

    now = datetime.datetime.now()
    now_str = now.strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db()
    reports = conn.execute(
        "SELECT * FROM scheduled_reports WHERE enabled = 1"
    ).fetchall()

    for report in reports:
        next_run = report["next_run"]
        if not next_run or next_run <= now_str:
            # Time to generate
            template = report["template"]
            schedule = report["schedule"]

            # Compute date range based on schedule
            if schedule == "daily":
                date_from = (now - datetime.timedelta(days=1)).strftime("%Y-%m-%d")
                date_to = now.strftime("%Y-%m-%d")
            elif schedule == "weekly":
                date_from = (now - datetime.timedelta(days=7)).strftime("%Y-%m-%d")
                date_to = now.strftime("%Y-%m-%d")
            else:  # monthly
                date_from = (now - datetime.timedelta(days=30)).strftime("%Y-%m-%d")
                date_to = now.strftime("%Y-%m-%d")

            try:
                params = json_mod.loads(report["parameters"]) if report["parameters"] else {}
            except (json_mod.JSONDecodeError, TypeError):
                params = {}

            # Create a compliance report entry
            conn.execute(
                "INSERT INTO compliance_reports "
                "(template, title, date_from, date_to, parameters, "
                " status, created_at) "
                "VALUES (?, ?, ?, ?, ?, 'pending', ?)",
                (template,
                 "Scheduled: %s (%s)" % (report["name"], schedule),
                 date_from, date_to,
                 json_mod.dumps(params), now_str)
            )
            report_id = conn.execute(
                "SELECT last_insert_rowid()"
            ).fetchone()[0]

            # Generate it
            threading.Thread(
                target=_generate_compliance_report,
                args=(report_id, template, date_from, date_to, params),
                daemon=True,
            ).start()

            # Update schedule
            new_next = _compute_next_run(schedule)
            conn.execute(
                "UPDATE scheduled_reports SET last_run = ?, next_run = ?, "
                "run_count = run_count + 1, updated_at = ? WHERE id = ?",
                (now_str, new_next, now_str, report["id"])
            )
            conn.commit()
            log.info("[ScheduledReport] Generated '%s' (%s), next: %s",
                     report["name"], template, new_next)

    conn.close()


# ---------------------------------------------------------------------------
# Phase 6: Log File Tailing (Linux/Mac)
# ---------------------------------------------------------------------------
_file_tail_threads = {}   # target_id -> threading.Thread
_file_tail_stops = {}     # target_id -> threading.Event


def _parse_syslog_file_line(line, source_name, default_facility, default_severity):
    """Parse a line from a syslog-style log file."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = {
        "timestamp": now,
        "received_at": now,
        "source_ip": "127.0.0.1",
        "source_name": source_name,
        "facility": default_facility,
        "facility_code": -3,  # -3 = file tailing marker
        "severity": default_severity,
        "severity_code": {"emergency":0,"alert":1,"critical":2,"error":3,
                          "warning":4,"notice":5,"info":6,"debug":7}.get(
                             default_severity, 6),
        "app_name": "",
        "process_id": "",
        "message": line,
        "raw": line,
    }

    # Try to detect severity from line content
    lower = line.lower()
    if any(w in lower for w in ["emerg", "panic"]):
        entry["severity"] = "emergency"
        entry["severity_code"] = 0
    elif "alert" in lower and "alert:" in lower:
        entry["severity"] = "alert"
        entry["severity_code"] = 1
    elif any(w in lower for w in ["crit", "critical"]):
        entry["severity"] = "critical"
        entry["severity_code"] = 2
    elif any(w in lower for w in ["error", "err ", "failed"]):
        entry["severity"] = "error"
        entry["severity_code"] = 3
    elif any(w in lower for w in ["warn", "warning"]):
        entry["severity"] = "warning"
        entry["severity_code"] = 4

    # Try RFC 3164 timestamp: "Mon DD HH:MM:SS"
    m = re.match(
        r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)",
        line, re.DOTALL
    )
    if m:
        ts_str = m.group(1)
        entry["source_name"] = m.group(2) if not source_name else source_name
        rest = m.group(3)
        try:
            year = datetime.datetime.now().year
            dt = datetime.datetime.strptime(
                "%d %s" % (year, ts_str), "%Y %b %d %H:%M:%S"
            )
            entry["timestamp"] = dt.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass
        # Extract app[pid]:
        am = re.match(r"^(\S+?)(?:\[(\d+)\])?:\s*(.*)", rest, re.DOTALL)
        if am:
            entry["app_name"] = am.group(1)
            entry["process_id"] = am.group(2) or ""
            entry["message"] = am.group(3).strip()
        else:
            entry["message"] = rest
        return entry

    # Try ISO timestamp: "2024-01-15 12:30:45"
    m2 = re.match(r"^(\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2})\s+(.*)", line, re.DOTALL)
    if m2:
        entry["timestamp"] = m2.group(1).replace("T", " ")[:19]
        entry["message"] = m2.group(2).strip()
        return entry

    return entry


def _tail_file(target_id, file_path, source_name, default_facility,
               default_severity, stop_event):
    """Tail a log file and ingest new lines."""
    log.info("[FileTail] Starting tail on %s (target %d)", file_path, target_id)
    position = 0
    inode = 0

    # Get last known position from DB
    try:
        conn = get_db()
        row = conn.execute(
            "SELECT last_position, last_inode FROM file_targets WHERE id = ?",
            (target_id,)
        ).fetchone()
        if row:
            position = row["last_position"] or 0
            inode = row["last_inode"] or 0
        conn.close()
    except Exception:
        pass

    while not stop_event.is_set():
        try:
            if not os.path.exists(file_path):
                time.sleep(5)
                continue

            stat = os.stat(file_path)
            current_inode = stat.st_ino if hasattr(stat, "st_ino") else 0
            file_size = stat.st_size

            # Detect log rotation (inode changed or file shrunk)
            if current_inode != inode and inode != 0:
                log.info("[FileTail] Rotation detected on %s, resetting", file_path)
                position = 0
                inode = current_inode
            elif file_size < position:
                log.info("[FileTail] File truncated %s, resetting", file_path)
                position = 0

            inode = current_inode

            if file_size == position:
                stop_event.wait(2)
                continue

            with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
                fh.seek(position)
                lines_read = 0
                for line in fh:
                    line = line.rstrip("\n\r")
                    if line:
                        entry = _parse_syslog_file_line(
                            line, source_name, default_facility, default_severity
                        )
                        ingest_log(entry)
                        lines_read += 1
                position = fh.tell()

            # Update DB with new position
            if lines_read > 0:
                now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                try:
                    conn = get_db()
                    conn.execute(
                        "UPDATE file_targets SET last_position = ?, "
                        "last_inode = ?, last_read = ?, "
                        "log_count = log_count + ?, error_message = '' "
                        "WHERE id = ?",
                        (position, inode, now, lines_read, target_id)
                    )
                    conn.commit()
                    conn.close()
                except Exception:
                    pass

            stop_event.wait(2)

        except Exception as exc:
            log.error("[FileTail] Error tailing %s: %s", file_path, exc)
            try:
                conn = get_db()
                conn.execute(
                    "UPDATE file_targets SET error_message = ? WHERE id = ?",
                    (str(exc)[:500], target_id)
                )
                conn.commit()
                conn.close()
            except Exception:
                pass
            stop_event.wait(10)

    log.info("[FileTail] Stopped tailing %s (target %d)", file_path, target_id)


def start_file_tail(target):
    """Start a file tailing thread for a target."""
    target_id = target["id"] if isinstance(target, dict) else target[0]
    fp = target["file_path"] if isinstance(target, dict) else target[2]
    src = target.get("source_name", "") if isinstance(target, dict) else (target[4] or "")
    fac = target.get("default_facility", "local0") if isinstance(target, dict) else "local0"
    sev = target.get("default_severity", "info") if isinstance(target, dict) else "info"

    if not src:
        src = os.path.basename(fp)

    stop_event = threading.Event()
    _file_tail_stops[target_id] = stop_event

    t = threading.Thread(
        target=_tail_file,
        args=(target_id, fp, src, fac, sev, stop_event),
        daemon=True,
    )
    t.start()
    _file_tail_threads[target_id] = t
    log.info("[FileTail] Collector started for target %d: %s", target_id, fp)


def stop_file_tail(target_id):
    """Stop a file tailing thread."""
    ev = _file_tail_stops.pop(target_id, None)
    if ev:
        ev.set()
    _file_tail_threads.pop(target_id, None)


def _start_all_file_tails():
    """Start all enabled file targets from the database."""
    features = get_tier_features()
    if not features.get("file_tailing"):
        return
    try:
        conn = get_db()
        targets = conn.execute(
            "SELECT * FROM file_targets WHERE enabled = 1"
        ).fetchall()
        conn.close()
        for t in targets:
            start_file_tail(dict(t))
        if targets:
            log.info("[FileTail] Started %d file target(s)", len(targets))
    except Exception as exc:
        log.error("[FileTail] Failed to start collectors: %s", exc)


# ---------------------------------------------------------------------------
# Phase 6: Log Forwarding Engine
# ---------------------------------------------------------------------------
_forwarding_lock = threading.Lock()
_forwarding_sockets = {}  # target_id -> socket


def forward_log(entry):
    """Forward a log entry to all enabled forwarding targets."""
    features = get_tier_features()
    if not features.get("log_forwarding"):
        return

    try:
        conn = get_db()
        targets = conn.execute(
            "SELECT * FROM forwarding_targets WHERE enabled = 1"
        ).fetchall()
        conn.close()
    except Exception:
        return

    for target in targets:
        # Apply filters
        if target["filter_severity"]:
            allowed = [s.strip().lower() for s in target["filter_severity"].split(",")]
            if entry.get("severity", "info").lower() not in allowed:
                continue
        if target["filter_source"]:
            allowed = [s.strip() for s in target["filter_source"].split(",")]
            if (entry.get("source_ip", "") not in allowed and
                    entry.get("source_name", "") not in allowed):
                continue
        if target["filter_facility"]:
            allowed = [s.strip().lower() for s in target["filter_facility"].split(",")]
            if entry.get("facility", "").lower() not in allowed:
                continue

        try:
            _forward_to_target(target, entry)
        except Exception as exc:
            log.debug("[Forwarding] Error forwarding to %s: %s",
                      target["name"], exc)


def _forward_to_target(target, entry):
    """Forward a single log entry to a forwarding target."""
    tid = target["id"]
    ttype = target["target_type"]
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if ttype == "syslog":
        # Build syslog message
        sev_code = entry.get("severity_code", 6)
        fac_code = entry.get("facility_code", 16)
        if fac_code < 0:
            fac_code = 16  # local0
        pri = fac_code * 8 + sev_code
        hostname = entry.get("source_name", entry.get("source_ip", "-"))
        app = entry.get("app_name", "sentrylog")
        msg = entry.get("message", "")

        if target["format"] == "rfc5424":
            ts = entry.get("timestamp", now).replace(" ", "T") + "Z"
            pid = entry.get("process_id", "-") or "-"
            syslog_msg = "<%d>1 %s %s %s %s - - %s" % (
                pri, ts, hostname, app, pid, msg)
        else:
            ts = entry.get("timestamp", now)
            syslog_msg = "<%d>%s %s %s: %s" % (pri, ts, hostname, app, msg)

        data = syslog_msg.encode("utf-8", errors="replace")

        if target["protocol"] == "tcp":
            with _forwarding_lock:
                sock = _forwarding_sockets.get(tid)
                if not sock:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    sock.connect((target["host"], target["port"]))
                    _forwarding_sockets[tid] = sock
                try:
                    sock.send(data + b"\n")
                except Exception:
                    # Reconnect on error
                    try:
                        sock.close()
                    except Exception:
                        pass
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    sock.connect((target["host"], target["port"]))
                    sock.send(data + b"\n")
                    _forwarding_sockets[tid] = sock
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(data, (target["host"], target["port"]))
            sock.close()

    elif ttype == "webhook":
        if HAS_REQUESTS and target["webhook_url"]:
            payload = {
                "product": "SentryLog",
                "event": "log_forward",
                "timestamp": entry.get("timestamp", now),
                "source_ip": entry.get("source_ip", ""),
                "source_name": entry.get("source_name", ""),
                "severity": entry.get("severity", "info"),
                "facility": entry.get("facility", ""),
                "app_name": entry.get("app_name", ""),
                "message": entry.get("message", ""),
            }
            requests_lib.post(
                target["webhook_url"], json=payload, timeout=5
            )

    # Update stats
    try:
        conn = get_db()
        conn.execute(
            "UPDATE forwarding_targets SET last_forwarded = ?, "
            "forward_count = forward_count + 1, error_message = '' "
            "WHERE id = ?", (now, tid)
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Phase 6: API Key Authentication & Rate Limiting
# ---------------------------------------------------------------------------
_rate_limit_cache = {}  # key_hash -> [timestamps]
_rate_limit_lock = threading.Lock()


def generate_api_key():
    """Generate a new API key. Returns (raw_key, key_hash, key_prefix)."""
    raw = "slk_" + secrets.token_hex(24)
    key_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    prefix = raw[:12] + "..."
    return raw, key_hash, prefix


def validate_api_key(raw_key):
    """Validate an API key. Returns the DB row or None."""
    if not raw_key or not isinstance(raw_key, str):
        return None
    key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
    try:
        conn = get_db()
        row = conn.execute(
            "SELECT * FROM api_keys WHERE key_hash = ? AND enabled = 1",
            (key_hash,)
        ).fetchone()
        if row:
            # Check expiration
            if row["expires_at"]:
                now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                if row["expires_at"] < now_str:
                    conn.close()
                    return None
            # Update usage
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            conn.execute(
                "UPDATE api_keys SET last_used = ?, use_count = use_count + 1 "
                "WHERE id = ?", (now, row["id"])
            )
            conn.commit()
        conn.close()
        return dict(row) if row else None
    except Exception:
        return None


def check_rate_limit(key_hash, limit_per_minute=120):
    """Check if a key has exceeded its rate limit. Returns True if allowed."""
    now = time.time()
    with _rate_limit_lock:
        timestamps = _rate_limit_cache.get(key_hash, [])
        # Clean old entries (older than 60s)
        timestamps = [t for t in timestamps if now - t < 60]
        if len(timestamps) >= limit_per_minute:
            _rate_limit_cache[key_hash] = timestamps
            return False
        timestamps.append(now)
        _rate_limit_cache[key_hash] = timestamps
        return True


def optional_api_auth(f):
    """Decorator: if API auth is enabled, require a valid API key.
    Key can be passed as X-API-Key header or ?api_key= query param."""
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        with _config_lock:
            auth_enabled = _config.get("api_auth", {}).get("enabled", False)
        if not auth_enabled:
            return f(*args, **kwargs)

        key = request.headers.get("X-API-Key", "") or request.args.get("api_key", "")
        if not key:
            return jsonify({
                "error": "api_key_required",
                "message": "API key required. Pass via X-API-Key header or api_key param.",
            }), 401

        row = validate_api_key(key)
        if not row:
            return jsonify({
                "error": "invalid_api_key",
                "message": "Invalid or expired API key.",
            }), 401

        # Rate limit
        limit = row.get("rate_limit", 120)
        if not check_rate_limit(row["key_hash"], limit):
            return jsonify({
                "error": "rate_limited",
                "message": "Rate limit exceeded. Max %d requests/minute." % limit,
            }), 429

        # Check permissions for write endpoints
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            if row.get("permissions", "read") == "read":
                return jsonify({
                    "error": "insufficient_permissions",
                    "message": "This API key has read-only permissions.",
                }), 403

        request.api_key_info = row
        return f(*args, **kwargs)
    return wrapper


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
        datetime.datetime.now() - datetime.timedelta(days=retention_days)
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
# Phase 2: Windows Event Log Collector
# ---------------------------------------------------------------------------
# Maps Windows event types to syslog severity
WIN_EVENT_TYPE_MAP = {
    "Error": "error",
    "Warning": "warning",
    "Information": "info",
    "Audit Success": "info",
    "Audit Failure": "warning",
    "Critical": "critical",
}

# Numeric EventType constants (win32evtlog / EVENTLOGRECORD)
WIN_EVENT_CODE_MAP = {
    1: "error",         # EVENTLOG_ERROR_TYPE
    2: "warning",       # EVENTLOG_WARNING_TYPE
    4: "info",          # EVENTLOG_INFORMATION_TYPE
    8: "info",          # EVENTLOG_AUDIT_SUCCESS
    16: "warning",      # EVENTLOG_AUDIT_FAILURE
}

SEVERITY_CODE_MAP = {
    "emergency": 0, "alert": 1, "critical": 2, "error": 3,
    "warning": 4, "notice": 5, "info": 6, "debug": 7,
}

# Active collector threads (target_id -> thread)
_winlog_threads = {}
_winlog_threads_lock = threading.Lock()


def _winlog_event_to_log(event_dict, source_ip, source_name):
    """Convert a Windows Event Log dict into the standard log format."""
    severity = event_dict.get("severity", "info")
    sev_code = SEVERITY_CODE_MAP.get(severity, 6)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ts = event_dict.get("timestamp", now)
    return {
        "timestamp": ts,
        "received_at": now,
        "source_ip": source_ip,
        "source_name": source_name,
        "facility": "winlog:" + event_dict.get("channel", "System"),
        "facility_code": -2,  # -2 = Windows Event Log marker
        "severity": severity,
        "severity_code": sev_code,
        "app_name": event_dict.get("source", ""),
        "process_id": str(event_dict.get("event_id", "")),
        "message": event_dict.get("message", ""),
        "raw": event_dict.get("raw", ""),
    }


def _update_winlog_target(target_id, **kwargs):
    """Update a winlog target in the database."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db()
    sets = []
    params = []
    for k, v in kwargs.items():
        sets.append("%s = ?" % k)
        params.append(v)
    sets.append("updated_at = ?")
    params.append(now)
    params.append(target_id)
    conn.execute(
        "UPDATE winlog_targets SET %s WHERE id = ?" % ", ".join(sets),
        params
    )
    conn.commit()
    conn.close()


# ---- Local Windows Event Log (pywin32) ----
def _collect_local_winlog(target_id, channels, poll_interval):
    """Collect Windows Event Logs from the local machine using pywin32."""
    if not HAS_WIN32:
        _update_winlog_target(
            target_id, enabled=0,
            error_message="pywin32 not installed. Run: pip install pywin32"
        )
        log.error("[WinLog] pywin32 not installed -- disabling target %d", target_id)
        return

    log.info("[WinLog] Local collector started for target %d, channels: %s",
             target_id, channels)

    # Load bookmarks (record number per channel)
    conn = get_db()
    row = conn.execute(
        "SELECT last_bookmark FROM winlog_targets WHERE id = ?", (target_id,)
    ).fetchone()
    conn.close()

    bookmarks = {}
    if row and row["last_bookmark"]:
        try:
            bookmarks = json_mod.loads(row["last_bookmark"])
        except Exception:
            bookmarks = {}

    while _running:
        # Check if target is still enabled
        conn = get_db()
        row = conn.execute(
            "SELECT enabled FROM winlog_targets WHERE id = ?", (target_id,)
        ).fetchone()
        conn.close()
        if not row or not row["enabled"]:
            log.info("[WinLog] Target %d disabled -- stopping collector", target_id)
            break

        total_new = 0

        for channel in channels:
            channel = channel.strip()
            if not channel:
                continue

            try:
                hand = win32evtlog.OpenEventLog(None, channel)
                flags = (win32evtlog.EVENTLOG_FORWARDS_READ |
                         win32evtlog.EVENTLOG_SEQUENTIAL_READ)

                # Get total records to know where we are
                total = win32evtlog.GetNumberOfEventLogRecords(hand)
                oldest = win32evtlog.GetOldestEventLogRecord(hand)

                last_record = bookmarks.get(channel, 0)

                while True:
                    events = win32evtlog.ReadEventLog(hand, flags, 0)
                    if not events:
                        break

                    for event in events:
                        rec_num = event.RecordNumber
                        if rec_num <= last_record:
                            continue

                        # Extract event data
                        evt_type_code = event.EventType or 4
                        severity = WIN_EVENT_CODE_MAP.get(evt_type_code, "info")
                        source_name_ev = event.SourceName or ""
                        event_id = event.EventID & 0xFFFF  # Mask to 16-bit
                        ts = event.TimeGenerated
                        if hasattr(ts, "strftime"):
                            ts_str = ts.strftime("%Y-%m-%d %H:%M:%S")
                        else:
                            ts_str = str(ts)

                        # Build message from strings data
                        msg_parts = []
                        if event.StringInserts:
                            msg_parts = list(event.StringInserts)

                        # Try to format the message with FormatMessage
                        try:
                            full_msg = win32evtlogutil.SafeFormatMessage(
                                event, channel
                            )
                        except Exception:
                            full_msg = " | ".join(msg_parts) if msg_parts else (
                                "EventID %d from %s" % (event_id, source_name_ev)
                            )

                        raw_info = "Channel=%s EventID=%d RecordNumber=%d Type=%d Source=%s" % (
                            channel, event_id, rec_num, evt_type_code, source_name_ev
                        )

                        event_dict = {
                            "timestamp": ts_str,
                            "channel": channel,
                            "source": source_name_ev,
                            "event_id": event_id,
                            "severity": severity,
                            "message": full_msg,
                            "raw": raw_info,
                        }

                        entry = _winlog_event_to_log(
                            event_dict, "127.0.0.1", "localhost"
                        )
                        ingest_log(entry)
                        total_new += 1
                        bookmarks[channel] = rec_num

                win32evtlog.CloseEventLog(hand)

            except Exception as e:
                err_msg = "Error reading %s: %s" % (channel, str(e))
                log.error("[WinLog] %s", err_msg)
                _update_winlog_target(target_id, error_message=err_msg)

        # Save bookmarks and update count
        if total_new > 0:
            with _log_buffer_lock:
                _flush_logs()

        bm_json = json_mod.dumps(bookmarks)
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        _update_winlog_target(
            target_id,
            last_poll=now,
            last_bookmark=bm_json,
            error_message=""
        )
        if total_new > 0:
            conn = get_db()
            conn.execute(
                "UPDATE winlog_targets SET log_count = log_count + ? WHERE id = ?",
                (total_new, target_id)
            )
            conn.commit()
            conn.close()
            log.info("[WinLog] Local: collected %d new events", total_new)

        # Sleep for poll interval
        for _ in range(poll_interval):
            if not _running:
                return
            time.sleep(1)

    log.info("[WinLog] Local collector stopped for target %d", target_id)


# ---- Remote Windows Event Log (WinRM / pywinrm) ----
# PowerShell script to read events from a remote Windows machine
_WINRM_PS_TEMPLATE = r"""
$channels = @(%s)
$since = '%s'
$maxPerChannel = 500
$results = @()
foreach ($ch in $channels) {
    try {
        $filter = @{LogName=$ch}
        if ($since -ne '') {
            $filter['StartTime'] = [DateTime]::Parse($since)
        }
        $evts = Get-WinEvent -FilterHashtable $filter -MaxEvents $maxPerChannel -ErrorAction SilentlyContinue
        foreach ($e in $evts) {
            $obj = [PSCustomObject]@{
                Channel   = $ch
                TimeCreated = $e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                Id        = $e.Id
                Level     = $e.LevelDisplayName
                LevelVal  = $e.Level
                Source    = $e.ProviderName
                Message   = if ($e.Message) { $e.Message.Substring(0, [Math]::Min($e.Message.Length, 1000)) } else { '' }
                RecordId  = $e.RecordId
            }
            $results += $obj
        }
    } catch { }
}
$results | ConvertTo-Json -Depth 3 -Compress
"""

# WinRM event level to severity
_WINRM_LEVEL_MAP = {
    1: "critical",     # Critical
    2: "error",        # Error
    3: "warning",      # Warning
    4: "info",         # Information
    5: "debug",        # Verbose
    0: "info",         # LogAlways
}


def _collect_remote_winlog(target_id, hostname, username, password,
                           use_ssl, port, channels, poll_interval):
    """Collect Windows Event Logs from a remote machine via WinRM."""
    if not HAS_WINRM:
        _update_winlog_target(
            target_id, enabled=0,
            error_message="pywinrm not installed. Run: pip install pywinrm"
        )
        log.error("[WinRM] pywinrm not installed -- disabling target %d", target_id)
        return

    transport = "ssl" if use_ssl else "ntlm"
    scheme = "https" if use_ssl else "http"
    endpoint = "%s://%s:%d/wsman" % (scheme, hostname, port)

    log.info("[WinRM] Remote collector started for %s (target %d), channels: %s",
             hostname, target_id, channels)

    # Load bookmark (last poll timestamp per channel)
    conn = get_db()
    row = conn.execute(
        "SELECT last_bookmark FROM winlog_targets WHERE id = ?", (target_id,)
    ).fetchone()
    conn.close()

    bookmarks = {}
    if row and row["last_bookmark"]:
        try:
            bookmarks = json_mod.loads(row["last_bookmark"])
        except Exception:
            bookmarks = {}

    while _running:
        # Check if target is still enabled
        conn = get_db()
        row = conn.execute(
            "SELECT enabled FROM winlog_targets WHERE id = ?", (target_id,)
        ).fetchone()
        conn.close()
        if not row or not row["enabled"]:
            log.info("[WinRM] Target %d disabled -- stopping", target_id)
            break

        total_new = 0
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        try:
            session = winrm.Session(
                endpoint,
                auth=(username, password),
                transport=transport,
                server_cert_validation="ignore",
            )

            # Build PowerShell channel list
            ch_list = ",".join(["'%s'" % c.strip() for c in channels if c.strip()])
            # Use the latest bookmark as the since parameter
            since_times = [bookmarks.get(c.strip(), "") for c in channels if c.strip()]
            since_val = ""
            if any(since_times):
                # Use the oldest non-empty bookmark
                valid = [t for t in since_times if t]
                if valid:
                    since_val = min(valid)

            ps_script = _WINRM_PS_TEMPLATE % (ch_list, since_val)

            result = session.run_ps(ps_script)

            if result.status_code != 0:
                err = result.std_err
                if isinstance(err, bytes):
                    err = err.decode("utf-8", errors="replace")
                _update_winlog_target(
                    target_id,
                    error_message="WinRM error: %s" % str(err)[:200],
                    last_poll=now_str,
                )
                log.error("[WinRM] Error from %s: %s", hostname, str(err)[:200])
            else:
                output = result.std_out
                if isinstance(output, bytes):
                    output = output.decode("utf-8", errors="replace")
                output = output.strip()

                events = []
                if output:
                    try:
                        parsed = json_mod.loads(output)
                        if isinstance(parsed, dict):
                            events = [parsed]
                        elif isinstance(parsed, list):
                            events = parsed
                    except json_mod.JSONDecodeError:
                        log.warning("[WinRM] Could not parse JSON from %s", hostname)

                for evt in events:
                    channel_name = evt.get("Channel", "Unknown")
                    record_id = evt.get("RecordId", 0)

                    # Skip if we already have this record
                    bm_key = channel_name
                    last_ts = bookmarks.get(bm_key, "")
                    evt_ts = evt.get("TimeCreated", "")
                    if last_ts and evt_ts <= last_ts:
                        continue

                    level_val = evt.get("LevelVal", 4)
                    severity = _WINRM_LEVEL_MAP.get(level_val, "info")
                    level_name = evt.get("Level", "Information")
                    if not severity and level_name:
                        severity = WIN_EVENT_TYPE_MAP.get(level_name, "info")

                    event_dict = {
                        "timestamp": evt_ts,
                        "channel": channel_name,
                        "source": evt.get("Source", ""),
                        "event_id": evt.get("Id", 0),
                        "severity": severity,
                        "message": evt.get("Message", ""),
                        "raw": "Channel=%s EventID=%s RecordId=%s Level=%s Source=%s" % (
                            channel_name, evt.get("Id", ""),
                            record_id, level_name, evt.get("Source", "")
                        ),
                    }

                    entry = _winlog_event_to_log(
                        event_dict, hostname, hostname
                    )
                    ingest_log(entry)
                    total_new += 1

                    # Update bookmark to latest timestamp per channel
                    if evt_ts > bookmarks.get(bm_key, ""):
                        bookmarks[bm_key] = evt_ts

                _update_winlog_target(
                    target_id,
                    last_poll=now_str,
                    last_bookmark=json_mod.dumps(bookmarks),
                    error_message=""
                )

                if total_new > 0:
                    with _log_buffer_lock:
                        _flush_logs()
                    conn = get_db()
                    conn.execute(
                        "UPDATE winlog_targets SET log_count = log_count + ? WHERE id = ?",
                        (total_new, target_id)
                    )
                    conn.commit()
                    conn.close()
                    log.info("[WinRM] %s: collected %d new events", hostname, total_new)

        except Exception as e:
            err_msg = "Connection error: %s" % str(e)[:200]
            log.error("[WinRM] %s: %s", hostname, err_msg)
            _update_winlog_target(
                target_id, error_message=err_msg, last_poll=now_str
            )

        # Sleep for poll interval
        for _ in range(poll_interval):
            if not _running:
                return
            time.sleep(1)

    log.info("[WinRM] Remote collector stopped for %s (target %d)", hostname, target_id)


def start_winlog_collector(target):
    """Start a collector thread for a Windows Event Log target."""
    target_id = target["id"]

    with _winlog_threads_lock:
        if target_id in _winlog_threads:
            old_t = _winlog_threads[target_id]
            if old_t.is_alive():
                return  # Already running

    channels_str = target.get("channels", "Security,System,Application")
    channels = [c.strip() for c in channels_str.split(",") if c.strip()]
    poll_interval = target.get("poll_interval_seconds", 60)

    if target["target_type"] == "local":
        t = threading.Thread(
            target=_collect_local_winlog,
            args=(target_id, channels, poll_interval),
            daemon=True,
        )
    elif target["target_type"] == "remote":
        t = threading.Thread(
            target=_collect_remote_winlog,
            args=(
                target_id,
                target.get("hostname", ""),
                target.get("username", ""),
                target.get("password", ""),
                bool(target.get("use_ssl", 0)),
                target.get("port", 5985),
                channels,
                poll_interval,
            ),
            daemon=True,
        )
    else:
        log.error("[WinLog] Unknown target type: %s", target["target_type"])
        return

    t.start()
    with _winlog_threads_lock:
        _winlog_threads[target_id] = t
    log.info("[WinLog] Started collector for target %d (%s)",
             target_id, target["target_type"])


def stop_winlog_collector(target_id):
    """Stop a collector by disabling the target (thread checks on next poll)."""
    _update_winlog_target(target_id, enabled=0)
    log.info("[WinLog] Requested stop for target %d", target_id)


def _start_all_winlog_collectors():
    """Start collectors for all enabled winlog targets."""
    features = get_tier_features()
    if not features.get("windows_eventlog", False):
        log.info("[WinLog] Windows Event Log feature not enabled for current tier")
        return

    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM winlog_targets WHERE enabled = 1"
    ).fetchall()
    conn.close()

    for row in rows:
        target = dict(row)
        start_winlog_collector(target)

    if rows:
        log.info("[WinLog] Started %d collector(s)", len(rows))


# ---------------------------------------------------------------------------
# Phase 3: Security API Connectors
# ---------------------------------------------------------------------------
# Supported connector types
CONNECTOR_TYPES = {
    "crowdstrike": "CrowdStrike Falcon",
    "sentinelone": "SentinelOne",
    "defender": "Microsoft Defender for Endpoint",
    "sophos": "Sophos Central",
    "cortex_xdr": "Palo Alto Cortex XDR",
    "generic_api": "Generic REST API",
}

_connector_threads = {}   # connector_id -> threading.Thread
_connector_stop = {}      # connector_id -> threading.Event


def _update_security_connector(connector_id, **kwargs):
    """Update fields on a security_connectors row."""
    if not kwargs:
        return
    sets = []
    vals = []
    for k, v in kwargs.items():
        sets.append("%s = ?" % k)
        vals.append(v)
    vals.append(connector_id)
    conn = get_db()
    conn.execute(
        "UPDATE security_connectors SET %s WHERE id = ?" % ", ".join(sets),
        vals
    )
    conn.commit()
    conn.close()


def _normalize_security_event(event, connector_type, source_name):
    """Convert a security product event dict into a log dict for ingest_log().

    Each vendor normalizer returns a dict with at minimum:
      source_ip, source_name, facility, severity, message, program, pid, raw
    """
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    base = {
        "timestamp": event.get("timestamp", now_str),
        "source_ip": event.get("source_ip", "0.0.0.0"),
        "source_name": source_name,
        "facility": "security",
        "severity": event.get("severity", "warning"),
        "hostname": event.get("hostname", source_name),
        "program": event.get("program", connector_type),
        "pid": event.get("pid", ""),
        "message": event.get("message", str(event)),
        "raw": event.get("raw", str(event)),
    }
    return base


# ---------------------------------------------------------------------------
# CrowdStrike Falcon connector
# ---------------------------------------------------------------------------
def _poll_crowdstrike(connector_id, api_url, api_key, api_secret,
                      extra_config, last_cursor, stop_event):
    """Poll CrowdStrike Falcon detections via OAuth2 API."""
    if not HAS_REQUESTS:
        _update_security_connector(connector_id,
                                   error_message="requests library not installed")
        return last_cursor

    base_url = api_url.rstrip("/") if api_url else "https://api.crowdstrike.com"
    try:
        # Authenticate -- OAuth2 client credentials
        token_resp = requests_lib.post(
            "%s/oauth2/token" % base_url,
            data={"client_id": api_key, "client_secret": api_secret},
            timeout=30
        )
        token_resp.raise_for_status()
        token = token_resp.json().get("access_token", "")
        headers = {"Authorization": "Bearer %s" % token}

        # Fetch detection IDs since last cursor
        params = {"sort": "first_behavior|asc", "limit": 100}
        if last_cursor:
            params["filter"] = "first_behavior:>'%s'" % last_cursor
        det_resp = requests_lib.get(
            "%s/detects/queries/detects/v1" % base_url,
            headers=headers, params=params, timeout=30
        )
        det_resp.raise_for_status()
        det_ids = det_resp.json().get("resources", [])

        if not det_ids:
            _update_security_connector(connector_id, error_message="",
                                       last_poll=datetime.datetime.now().strftime(
                                           "%Y-%m-%d %H:%M:%S"))
            return last_cursor

        # Fetch detection details
        detail_resp = requests_lib.post(
            "%s/detects/entities/summaries/GET/v1" % base_url,
            headers=headers, json={"ids": det_ids}, timeout=30
        )
        detail_resp.raise_for_status()
        detections = detail_resp.json().get("resources", [])

        sev_map = {"1": "info", "2": "notice", "3": "warning",
                    "4": "error", "5": "critical"}
        newest_time = last_cursor or ""
        count = 0

        for det in detections:
            if stop_event.is_set():
                break
            ts = det.get("first_behavior", "")
            severity_num = str(det.get("max_severity", 3))
            sev = sev_map.get(severity_num, "warning")
            desc = det.get("max_severity_displayname", "Detection")
            device = det.get("device", {})
            hostname = device.get("hostname", "unknown")

            event = {
                "timestamp": ts[:19].replace("T", " ") if ts else "",
                "source_ip": device.get("local_ip", "0.0.0.0"),
                "hostname": hostname,
                "severity": sev,
                "program": "CrowdStrike",
                "message": "[%s] %s on %s -- %s" % (
                    desc, det.get("tactic", ""),
                    hostname, det.get("technique", "")),
                "raw": json_mod.dumps(det, default=str),
            }
            normalized = _normalize_security_event(event, "crowdstrike",
                                                   "CrowdStrike Falcon")
            ingest_log(normalized)
            count += 1
            if ts and ts > newest_time:
                newest_time = ts

        _update_security_connector(
            connector_id, error_message="",
            log_count=count,
            last_poll=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            last_cursor=newest_time or last_cursor
        )
        # Increment count in DB
        conn = get_db()
        conn.execute(
            "UPDATE security_connectors SET log_count = log_count + ? WHERE id = ?",
            (count, connector_id))
        conn.commit()
        conn.close()
        return newest_time or last_cursor

    except Exception as exc:
        _update_security_connector(connector_id,
                                   error_message=str(exc)[:500],
                                   last_poll=datetime.datetime.now().strftime(
                                       "%Y-%m-%d %H:%M:%S"))
        log.error("[Connector] CrowdStrike error: %s", exc)
        return last_cursor


# ---------------------------------------------------------------------------
# SentinelOne connector
# ---------------------------------------------------------------------------
def _poll_sentinelone(connector_id, api_url, api_key, api_secret,
                      extra_config, last_cursor, stop_event):
    """Poll SentinelOne threats/alerts via REST API."""
    if not HAS_REQUESTS:
        _update_security_connector(connector_id,
                                   error_message="requests library not installed")
        return last_cursor

    base_url = api_url.rstrip("/") if api_url else ""
    if not base_url:
        _update_security_connector(connector_id,
                                   error_message="API URL required (e.g. https://usea1.sentinelone.net)")
        return last_cursor

    try:
        headers = {"Authorization": "ApiToken %s" % api_key}
        params = {"sortBy": "createdAt", "sortOrder": "asc", "limit": 100}
        if last_cursor:
            params["cursor"] = last_cursor

        resp = requests_lib.get(
            "%s/web/api/v2.1/threats" % base_url,
            headers=headers, params=params, timeout=30
        )
        resp.raise_for_status()
        body = resp.json()
        threats = body.get("data", [])
        next_cursor = body.get("pagination", {}).get("nextCursor", "")

        sev_map = {"Low": "notice", "Medium": "warning",
                    "High": "error", "Critical": "critical"}
        count = 0

        for threat in threats:
            if stop_event.is_set():
                break
            ti = threat.get("threatInfo", threat)
            agent = threat.get("agentRealtimeInfo", threat.get("agentDetectionInfo", {}))
            sev = sev_map.get(ti.get("confidenceLevel", "Medium"), "warning")
            hostname = agent.get("agentComputerName", "unknown")

            event = {
                "timestamp": ti.get("createdAt", "")[:19].replace("T", " "),
                "source_ip": agent.get("agentIpV4", "0.0.0.0"),
                "hostname": hostname,
                "severity": sev,
                "program": "SentinelOne",
                "message": "[%s] %s on %s -- Classification: %s" % (
                    ti.get("confidenceLevel", ""),
                    ti.get("threatName", "Threat"),
                    hostname,
                    ti.get("classification", "")),
                "raw": json_mod.dumps(threat, default=str),
            }
            normalized = _normalize_security_event(event, "sentinelone",
                                                   "SentinelOne")
            ingest_log(normalized)
            count += 1

        _update_security_connector(
            connector_id, error_message="",
            last_poll=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            last_cursor=next_cursor or last_cursor
        )
        conn = get_db()
        conn.execute(
            "UPDATE security_connectors SET log_count = log_count + ? WHERE id = ?",
            (count, connector_id))
        conn.commit()
        conn.close()
        return next_cursor or last_cursor

    except Exception as exc:
        _update_security_connector(connector_id,
                                   error_message=str(exc)[:500],
                                   last_poll=datetime.datetime.now().strftime(
                                       "%Y-%m-%d %H:%M:%S"))
        log.error("[Connector] SentinelOne error: %s", exc)
        return last_cursor


# ---------------------------------------------------------------------------
# Microsoft Defender for Endpoint connector
# ---------------------------------------------------------------------------
def _poll_defender(connector_id, api_url, api_key, api_secret,
                   extra_config, last_cursor, stop_event):
    """Poll Microsoft Defender for Endpoint alerts via Graph/MDE API.

    api_key   = client_id (Azure AD app)
    api_secret = client_secret
    extra_config should contain {"tenant_id": "..."}
    """
    if not HAS_REQUESTS:
        _update_security_connector(connector_id,
                                   error_message="requests library not installed")
        return last_cursor

    try:
        cfg = json_mod.loads(extra_config) if isinstance(extra_config, str) else extra_config
    except Exception:
        cfg = {}

    tenant_id = cfg.get("tenant_id", "")
    if not tenant_id:
        _update_security_connector(connector_id,
                                   error_message="tenant_id required in extra config")
        return last_cursor

    try:
        # Get OAuth2 token
        token_resp = requests_lib.post(
            "https://login.microsoftonline.com/%s/oauth2/v2.0/token" % tenant_id,
            data={
                "client_id": api_key,
                "client_secret": api_secret,
                "scope": "https://api.securitycenter.microsoft.com/.default",
                "grant_type": "client_credentials",
            },
            timeout=30
        )
        token_resp.raise_for_status()
        token = token_resp.json().get("access_token", "")
        headers = {"Authorization": "Bearer %s" % token}

        # Fetch alerts
        url = "https://api.securitycenter.microsoft.com/api/alerts"
        params = {"$top": 100, "$orderby": "alertCreationTime asc"}
        if last_cursor:
            params["$filter"] = "alertCreationTime gt %s" % last_cursor

        resp = requests_lib.get(url, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        alerts = resp.json().get("value", [])

        sev_map = {"Informational": "info", "Low": "notice",
                    "Medium": "warning", "High": "error"}
        newest_time = last_cursor or ""
        count = 0

        for alert in alerts:
            if stop_event.is_set():
                break
            ts = alert.get("alertCreationTime", "")
            sev = sev_map.get(alert.get("severity", "Medium"), "warning")
            hostname = ""
            machines = alert.get("machines", [])
            if machines:
                hostname = machines[0].get("computerDnsName", "unknown")

            event = {
                "timestamp": ts[:19].replace("T", " ") if ts else "",
                "source_ip": "0.0.0.0",
                "hostname": hostname or "Defender",
                "severity": sev,
                "program": "Defender",
                "message": "[%s] %s -- %s" % (
                    alert.get("severity", ""),
                    alert.get("title", "Alert"),
                    alert.get("description", "")[:200]),
                "raw": json_mod.dumps(alert, default=str),
            }
            normalized = _normalize_security_event(event, "defender",
                                                   "MS Defender")
            ingest_log(normalized)
            count += 1
            if ts and ts > newest_time:
                newest_time = ts

        _update_security_connector(
            connector_id, error_message="",
            last_poll=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            last_cursor=newest_time or last_cursor
        )
        conn = get_db()
        conn.execute(
            "UPDATE security_connectors SET log_count = log_count + ? WHERE id = ?",
            (count, connector_id))
        conn.commit()
        conn.close()
        return newest_time or last_cursor

    except Exception as exc:
        _update_security_connector(connector_id,
                                   error_message=str(exc)[:500],
                                   last_poll=datetime.datetime.now().strftime(
                                       "%Y-%m-%d %H:%M:%S"))
        log.error("[Connector] Defender error: %s", exc)
        return last_cursor


# ---------------------------------------------------------------------------
# Sophos Central connector
# ---------------------------------------------------------------------------
def _poll_sophos(connector_id, api_url, api_key, api_secret,
                 extra_config, last_cursor, stop_event):
    """Poll Sophos Central alerts via Partner/Organization API.

    api_key   = client_id
    api_secret = client_secret
    extra_config may contain {"tenant_id": "..."} for partner API
    """
    if not HAS_REQUESTS:
        _update_security_connector(connector_id,
                                   error_message="requests library not installed")
        return last_cursor

    try:
        # Authenticate
        token_resp = requests_lib.post(
            "https://id.sophos.com/api/v2/oauth2/token",
            data={
                "client_id": api_key,
                "client_secret": api_secret,
                "grant_type": "client_credentials",
                "scope": "token",
            },
            timeout=30
        )
        token_resp.raise_for_status()
        token = token_resp.json().get("access_token", "")
        headers = {"Authorization": "Bearer %s" % token}

        # Get whoami to find data region
        whoami = requests_lib.get(
            "https://api.central.sophos.com/whoami/v1",
            headers=headers, timeout=30
        )
        whoami.raise_for_status()
        whoami_data = whoami.json()
        data_url = whoami_data.get("apiHosts", {}).get("dataRegion", "")
        tenant_id = whoami_data.get("id", "")

        if not data_url:
            _update_security_connector(connector_id,
                                       error_message="Could not determine Sophos data region")
            return last_cursor

        headers["X-Tenant-ID"] = tenant_id

        # Fetch alerts
        params = {"pageSize": 100, "sort": "raisedAt:asc"}
        if last_cursor:
            params["pageFromKey"] = last_cursor

        resp = requests_lib.get(
            "%s/common/v1/alerts" % data_url,
            headers=headers, params=params, timeout=30
        )
        resp.raise_for_status()
        body = resp.json()
        alerts = body.get("items", [])
        next_key = body.get("pages", {}).get("nextKey", "")

        sev_map = {"low": "notice", "medium": "warning",
                    "high": "error", "critical": "critical"}
        count = 0

        for alert in alerts:
            if stop_event.is_set():
                break
            ts = alert.get("raisedAt", "")
            sev = sev_map.get(alert.get("severity", "medium"), "warning")

            event = {
                "timestamp": ts[:19].replace("T", " ") if ts else "",
                "source_ip": "0.0.0.0",
                "hostname": alert.get("managedAgent", {}).get(
                    "name", "Sophos"),
                "severity": sev,
                "program": "Sophos",
                "message": "[%s] %s -- %s" % (
                    alert.get("severity", ""),
                    alert.get("type", "Alert"),
                    alert.get("description", "")),
                "raw": json_mod.dumps(alert, default=str),
            }
            normalized = _normalize_security_event(event, "sophos",
                                                   "Sophos Central")
            ingest_log(normalized)
            count += 1

        _update_security_connector(
            connector_id, error_message="",
            last_poll=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            last_cursor=next_key or last_cursor
        )
        conn = get_db()
        conn.execute(
            "UPDATE security_connectors SET log_count = log_count + ? WHERE id = ?",
            (count, connector_id))
        conn.commit()
        conn.close()
        return next_key or last_cursor

    except Exception as exc:
        _update_security_connector(connector_id,
                                   error_message=str(exc)[:500],
                                   last_poll=datetime.datetime.now().strftime(
                                       "%Y-%m-%d %H:%M:%S"))
        log.error("[Connector] Sophos error: %s", exc)
        return last_cursor


# ---------------------------------------------------------------------------
# Palo Alto Cortex XDR connector
# ---------------------------------------------------------------------------
def _poll_cortex_xdr(connector_id, api_url, api_key, api_secret,
                     extra_config, last_cursor, stop_event):
    """Poll Palo Alto Cortex XDR incidents via REST API.

    api_url    = FQDN (e.g. https://api-{fqdn}.xdr.us.paloaltonetworks.com)
    api_key    = API key
    api_secret = API key ID
    """
    if not HAS_REQUESTS:
        _update_security_connector(connector_id,
                                   error_message="requests library not installed")
        return last_cursor

    base_url = api_url.rstrip("/") if api_url else ""
    if not base_url:
        _update_security_connector(connector_id,
                                   error_message="API URL required")
        return last_cursor

    try:
        # Cortex XDR uses API key + API key ID in headers
        import secrets as secrets_mod
        nonce = secrets_mod.token_hex(32)
        ts_ms = str(int(time.time() * 1000))

        # Generate auth headers per Cortex XDR docs
        auth_string = "%s%s%s" % (api_key, nonce, ts_ms)
        auth_hash = hashlib.sha256(auth_string.encode("utf-8")).hexdigest()

        headers = {
            "x-xdr-auth-id": str(api_secret),
            "x-xdr-nonce": nonce,
            "x-xdr-timestamp": ts_ms,
            "Authorization": auth_hash,
            "Content-Type": "application/json",
        }

        # Fetch incidents
        body = {
            "request_data": {
                "sort": {"field": "creation_time", "keyword": "asc"},
                "search_from": 0,
                "search_to": 100,
            }
        }
        if last_cursor:
            body["request_data"]["filters"] = [{
                "field": "creation_time",
                "operator": "gte",
                "value": int(last_cursor)
            }]

        resp = requests_lib.post(
            "%s/public_api/v1/incidents/get_incidents/" % base_url,
            headers=headers, json=body, timeout=30
        )
        resp.raise_for_status()
        incidents = resp.json().get("reply", {}).get("incidents", [])

        sev_map = {"informational": "info", "low": "notice",
                    "medium": "warning", "high": "error",
                    "critical": "critical"}
        newest_ts = int(last_cursor) if last_cursor else 0
        count = 0

        for inc in incidents:
            if stop_event.is_set():
                break
            creation_time = inc.get("creation_time", 0)
            sev = sev_map.get(
                inc.get("severity", "medium").lower(), "warning")
            hosts = inc.get("hosts", ["unknown"])
            hostname = hosts[0] if hosts else "unknown"

            ts_str = datetime.datetime.fromtimestamp(
                creation_time / 1000.0
            ).strftime("%Y-%m-%d %H:%M:%S") if creation_time else ""

            event = {
                "timestamp": ts_str,
                "source_ip": "0.0.0.0",
                "hostname": hostname,
                "severity": sev,
                "program": "Cortex XDR",
                "message": "[%s] Incident #%s: %s" % (
                    inc.get("severity", ""),
                    inc.get("incident_id", ""),
                    inc.get("description", "")[:200]),
                "raw": json_mod.dumps(inc, default=str),
            }
            normalized = _normalize_security_event(event, "cortex_xdr",
                                                   "Cortex XDR")
            ingest_log(normalized)
            count += 1
            if creation_time and creation_time > newest_ts:
                newest_ts = creation_time

        new_cursor = str(newest_ts) if newest_ts else last_cursor
        _update_security_connector(
            connector_id, error_message="",
            last_poll=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            last_cursor=new_cursor
        )
        conn = get_db()
        conn.execute(
            "UPDATE security_connectors SET log_count = log_count + ? WHERE id = ?",
            (count, connector_id))
        conn.commit()
        conn.close()
        return new_cursor

    except Exception as exc:
        _update_security_connector(connector_id,
                                   error_message=str(exc)[:500],
                                   last_poll=datetime.datetime.now().strftime(
                                       "%Y-%m-%d %H:%M:%S"))
        log.error("[Connector] Cortex XDR error: %s", exc)
        return last_cursor


# ---------------------------------------------------------------------------
# Generic REST API connector
# ---------------------------------------------------------------------------
def _poll_generic_api(connector_id, api_url, api_key, api_secret,
                      extra_config, last_cursor, stop_event):
    """Poll a generic REST API endpoint for alerts/events.

    api_url    = full URL to GET
    api_key    = Authorization header value (Bearer token, API key, etc.)
    extra_config = {"auth_header": "Authorization", "auth_prefix": "Bearer ",
                    "events_path": "data.alerts", "message_field": "message",
                    "severity_field": "severity", "timestamp_field": "timestamp",
                    "cursor_field": "next_cursor"}
    """
    if not HAS_REQUESTS:
        _update_security_connector(connector_id,
                                   error_message="requests library not installed")
        return last_cursor

    if not api_url:
        _update_security_connector(connector_id,
                                   error_message="API URL required")
        return last_cursor

    try:
        cfg = json_mod.loads(extra_config) if isinstance(extra_config, str) else extra_config
    except Exception:
        cfg = {}

    auth_header = cfg.get("auth_header", "Authorization")
    auth_prefix = cfg.get("auth_prefix", "Bearer ")
    events_path = cfg.get("events_path", "")      # dot-separated, e.g. "data.alerts"
    msg_field = cfg.get("message_field", "message")
    sev_field = cfg.get("severity_field", "severity")
    ts_field = cfg.get("timestamp_field", "timestamp")
    cursor_field = cfg.get("cursor_field", "")

    try:
        headers = {}
        if api_key:
            headers[auth_header] = "%s%s" % (auth_prefix, api_key)

        params = {}
        if last_cursor and cursor_field:
            params["cursor"] = last_cursor

        resp = requests_lib.get(api_url, headers=headers, params=params,
                                timeout=30)
        resp.raise_for_status()
        body = resp.json()

        # Navigate to events list via dot path
        events = body
        if events_path:
            for part in events_path.split("."):
                if isinstance(events, dict):
                    events = events.get(part, [])
                else:
                    events = []
                    break
        if not isinstance(events, list):
            events = [events] if events else []

        # Extract next cursor
        next_cursor = ""
        if cursor_field:
            cursor_val = body
            for part in cursor_field.split("."):
                if isinstance(cursor_val, dict):
                    cursor_val = cursor_val.get(part, "")
                else:
                    cursor_val = ""
                    break
            next_cursor = str(cursor_val) if cursor_val else ""

        count = 0
        for evt in events:
            if stop_event.is_set():
                break
            if not isinstance(evt, dict):
                continue

            event = {
                "timestamp": str(evt.get(ts_field, ""))[:19].replace("T", " "),
                "source_ip": evt.get("source_ip", evt.get("ip", "0.0.0.0")),
                "hostname": evt.get("hostname", evt.get("host", "generic")),
                "severity": evt.get(sev_field, "warning"),
                "program": "GenericAPI",
                "message": str(evt.get(msg_field, str(evt)))[:2000],
                "raw": json_mod.dumps(evt, default=str),
            }
            normalized = _normalize_security_event(event, "generic_api",
                                                   "Generic API")
            ingest_log(normalized)
            count += 1

        _update_security_connector(
            connector_id, error_message="",
            last_poll=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            last_cursor=next_cursor or last_cursor
        )
        conn = get_db()
        conn.execute(
            "UPDATE security_connectors SET log_count = log_count + ? WHERE id = ?",
            (count, connector_id))
        conn.commit()
        conn.close()
        return next_cursor or last_cursor

    except Exception as exc:
        _update_security_connector(connector_id,
                                   error_message=str(exc)[:500],
                                   last_poll=datetime.datetime.now().strftime(
                                       "%Y-%m-%d %H:%M:%S"))
        log.error("[Connector] Generic API error: %s", exc)
        return last_cursor


# Dispatcher map: connector_type -> poll function
_CONNECTOR_POLLERS = {
    "crowdstrike": _poll_crowdstrike,
    "sentinelone": _poll_sentinelone,
    "defender": _poll_defender,
    "sophos": _poll_sophos,
    "cortex_xdr": _poll_cortex_xdr,
    "generic_api": _poll_generic_api,
}


def _connector_poll_loop(connector_id, connector_type, api_url, api_key,
                         api_secret, extra_config, poll_interval,
                         stop_event):
    """Main loop for a security connector thread."""
    cursor = ""
    # Load last cursor from DB
    try:
        conn = get_db()
        row = conn.execute(
            "SELECT last_cursor FROM security_connectors WHERE id = ?",
            (connector_id,)
        ).fetchone()
        if row:
            cursor = row[0] or ""
        conn.close()
    except Exception:
        pass

    poller = _CONNECTOR_POLLERS.get(connector_type)
    if not poller:
        _update_security_connector(connector_id,
                                   error_message="Unknown connector type: %s" % connector_type)
        return

    log.info("[Connector] Starting %s connector (id=%d, interval=%ds)",
             connector_type, connector_id, poll_interval)

    _db_fail_count = 0
    while not stop_event.is_set():
        # Check if still enabled
        try:
            conn = get_db()
            row = conn.execute(
                "SELECT enabled FROM security_connectors WHERE id = ?",
                (connector_id,)
            ).fetchone()
            conn.close()
            _db_fail_count = 0  # Reset on success
            if not row or not row[0]:
                log.info("[Connector] Connector %d disabled, stopping",
                         connector_id)
                break
        except Exception as exc:
            _db_fail_count += 1
            log.warning("[Connector] DB check failed for connector %d "
                        "(attempt %d): %s", connector_id, _db_fail_count, exc)
            if _db_fail_count >= 5:
                log.error("[Connector] Too many DB failures for connector %d, "
                          "stopping", connector_id)
                _update_security_connector(
                    connector_id,
                    error_message="Polling stopped: repeated DB errors")
                break
            # Transient DB error -- wait and retry instead of dying
            stop_event.wait(poll_interval)
            continue

        try:
            cursor = poller(connector_id, api_url, api_key, api_secret,
                            extra_config, cursor, stop_event)
        except Exception as exc:
            log.error("[Connector] %s poll error: %s", connector_type, exc)
            _update_security_connector(connector_id,
                                       error_message=str(exc)[:500])

        stop_event.wait(poll_interval)

    log.info("[Connector] Stopped %s connector (id=%d)",
             connector_type, connector_id)


def start_security_connector(connector):
    """Start a security connector polling thread."""
    cid = connector["id"]
    if cid in _connector_threads and _connector_threads[cid].is_alive():
        return  # Already running

    stop_event = threading.Event()
    _connector_stop[cid] = stop_event

    t = threading.Thread(
        target=_connector_poll_loop,
        args=(cid, connector["connector_type"], connector["api_url"],
              connector["api_key"], connector["api_secret"],
              connector["extra_config"], connector["poll_interval_seconds"],
              stop_event),
        daemon=True,
        name="connector-%d-%s" % (cid, connector["connector_type"])
    )
    t.start()
    _connector_threads[cid] = t
    log.info("[Connector] Started thread for connector %d (%s)",
             cid, connector["connector_type"])


def stop_security_connector(connector_id):
    """Stop a running security connector."""
    if connector_id in _connector_stop:
        _connector_stop[connector_id].set()
    if connector_id in _connector_threads:
        _connector_threads[connector_id].join(timeout=5)
        del _connector_threads[connector_id]
    if connector_id in _connector_stop:
        del _connector_stop[connector_id]


def _start_all_security_connectors():
    """Start all enabled security connectors on application boot."""
    try:
        conn = get_db()
        rows = conn.execute(
            "SELECT id, name, connector_type, api_url, api_key, api_secret, "
            "extra_config, poll_interval_seconds, enabled "
            "FROM security_connectors WHERE enabled = 1"
        ).fetchall()
        conn.close()
    except Exception:
        return

    for row in rows:
        connector = {
            "id": row[0], "name": row[1], "connector_type": row[2],
            "api_url": row[3], "api_key": row[4], "api_secret": row[5],
            "extra_config": row[6], "poll_interval_seconds": row[7],
            "enabled": row[8],
        }
        start_security_connector(connector)

    if rows:
        log.info("[Connector] Started %d security connector(s)", len(rows))


# ---------------------------------------------------------------------------
# Phase 4: Cross-Source Correlation Engine
# ---------------------------------------------------------------------------
# Condition format in JSON:
#   [
#     {"field": "message", "operator": "contains", "value": "failed",
#      "source_filter": "", "severity_filter": ""},
#     {"field": "message", "operator": "regex", "value": "brute.?force",
#      "source_filter": "10.0.0.1", "severity_filter": "critical"}
#   ]
# A correlation fires when >= min_matches distinct conditions match
# within time_window_seconds of each other.

_correlation_lock = threading.Lock()
_correlation_buffer = []    # recent logs for correlation window
_CORR_BUFFER_MAX = 5000    # rolling buffer size

def _corr_add_event(log_entry):
    """Add a log entry to the correlation rolling buffer."""
    with _correlation_lock:
        _correlation_buffer.append(log_entry)
        if len(_correlation_buffer) > _CORR_BUFFER_MAX:
            del _correlation_buffer[:len(_correlation_buffer) - _CORR_BUFFER_MAX]


def _corr_match_condition(entry, condition):
    """Check if a single log entry matches a correlation condition."""
    field = condition.get("field", "message")
    operator = condition.get("operator", "contains")
    value = condition.get("value", "")
    src_filter = condition.get("source_filter", "").strip()
    sev_filter = condition.get("severity_filter", "").strip()

    # Source filter
    if src_filter:
        entry_src = "%s %s" % (entry.get("source_ip", ""),
                               entry.get("source_name", ""))
        if src_filter.lower() not in entry_src.lower():
            return False

    # Severity filter
    if sev_filter:
        if entry.get("severity", "").lower() != sev_filter.lower():
            return False

    # Field match
    field_val = str(entry.get(field, entry.get("message", "")))
    if operator == "contains":
        return value.lower() in field_val.lower()
    elif operator == "equals":
        return field_val.lower() == value.lower()
    elif operator == "regex":
        try:
            return bool(re.search(value, field_val, re.IGNORECASE))
        except re.error:
            return False
    elif operator == "not_contains":
        return value.lower() not in field_val.lower()
    elif operator == "severity_gte":
        sev_map = {"emergency": 0, "alert": 1, "critical": 2, "error": 3,
                   "warning": 4, "notice": 5, "info": 6, "debug": 7}
        entry_sev = sev_map.get(entry.get("severity", "info").lower(), 6)
        target_sev = sev_map.get(value.lower(), 4)
        return entry_sev <= target_sev
    return False


def _run_correlation_check():
    """Evaluate all correlation rules against the rolling buffer.
    Called periodically from the correlation thread.
    """
    tier = get_tier()
    tier_order = [TIER_FREE, TIER_PRO, TIER_ENT]
    if tier_order.index(tier) < tier_order.index(TIER_PRO):
        return

    conn = get_db()
    rules = conn.execute(
        "SELECT id, name, conditions, time_window_seconds, min_matches, "
        "severity, cooldown_minutes, last_fired, fire_count "
        "FROM correlation_rules WHERE enabled = 1"
    ).fetchall()

    now = datetime.datetime.now()
    now_str = now.strftime("%Y-%m-%d %H:%M:%S")

    with _correlation_lock:
        buffer_copy = list(_correlation_buffer)

    for rule in rules:
        rule_id, rule_name = rule[0], rule[1]
        try:
            conditions = json_mod.loads(rule[2])
        except (json_mod.JSONDecodeError, TypeError):
            continue
        time_window = rule[3] or 300
        min_matches = rule[4] or 2
        severity = rule[5] or "critical"
        cooldown = rule[6] or 30
        last_fired = rule[7] or ""
        fire_count = rule[8] or 0

        # Cooldown check
        if last_fired:
            try:
                lf = datetime.datetime.strptime(last_fired, "%Y-%m-%d %H:%M:%S")
                if (now - lf).total_seconds() < cooldown * 60:
                    continue
            except ValueError:
                pass

        # Evaluate conditions against buffer
        cutoff = now - datetime.timedelta(seconds=time_window)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        # Only check recent events in window
        recent = [e for e in buffer_copy
                  if e.get("received_at", e.get("timestamp", "")) >= cutoff_str]
        if not recent:
            continue

        # For each condition, find matching events
        matched_conditions = {}
        matched_events = []
        for ci, cond in enumerate(conditions):
            for entry in recent:
                if _corr_match_condition(entry, cond):
                    matched_conditions[ci] = True
                    matched_events.append({
                        "condition_index": ci,
                        "source_ip": entry.get("source_ip", ""),
                        "source_name": entry.get("source_name", ""),
                        "severity": entry.get("severity", ""),
                        "message": str(entry.get("message", ""))[:200],
                        "timestamp": entry.get("timestamp",
                                    entry.get("received_at", "")),
                    })
                    break  # one match per condition is enough

        # Fire if enough distinct conditions matched
        if len(matched_conditions) >= min_matches:
            summary = ("Correlation rule '%s' fired: %d/%d conditions matched "
                       "within %ds window" % (
                           rule_name, len(matched_conditions),
                           len(conditions), time_window))

            events_json = json_mod.dumps(matched_events[:50], default=str)

            conn.execute(
                "INSERT INTO correlation_incidents "
                "(rule_id, rule_name, severity, matched_events, matched_count, "
                " summary, status, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, 'open', ?)",
                (rule_id, rule_name, severity, events_json,
                 len(matched_conditions), summary, now_str)
            )
            conn.execute(
                "UPDATE correlation_rules SET last_fired = ?, "
                "fire_count = fire_count + 1 WHERE id = ?",
                (now_str, rule_id)
            )
            conn.commit()
            log.info("[Correlation] %s", summary)

    conn.close()


def _correlation_loop():
    """Background thread that runs correlation checks every 30 seconds."""
    while not _stop_event.is_set():
        try:
            _run_correlation_check()
        except Exception as exc:
            log.error("[Correlation] Error: %s", exc)
        _stop_event.wait(30)


# ---------------------------------------------------------------------------
# Phase 4: Compliance Report Generator
# ---------------------------------------------------------------------------
COMPLIANCE_TEMPLATES = {
    "pci_dss": {
        "name": "PCI-DSS Log Review",
        "description": "Payment Card Industry Data Security Standard - "
                       "daily log review covering access, auth failures, "
                       "privilege escalation, and system changes.",
        "sections": [
            "executive_summary", "log_volume", "auth_failures",
            "privilege_events", "critical_alerts", "source_summary",
            "security_connectors", "recommendations"
        ],
    },
    "hipaa": {
        "name": "HIPAA Security Audit",
        "description": "Health Insurance Portability and Accountability Act - "
                       "access monitoring, audit trail integrity, "
                       "and incident response review.",
        "sections": [
            "executive_summary", "log_volume", "access_events",
            "auth_failures", "critical_alerts", "source_summary",
            "data_integrity", "recommendations"
        ],
    },
    "soc2": {
        "name": "SOC 2 Type II Evidence",
        "description": "Service Organization Control 2 - "
                       "security monitoring, availability, "
                       "and incident response evidence.",
        "sections": [
            "executive_summary", "log_volume", "security_events",
            "availability_metrics", "incident_response",
            "source_summary", "recommendations"
        ],
    },
    "nist_csf": {
        "name": "NIST Cybersecurity Framework",
        "description": "National Institute of Standards and Technology CSF - "
                       "identify, protect, detect, respond, recover assessment.",
        "sections": [
            "executive_summary", "log_volume", "identify_assets",
            "protect_access", "detect_anomalies", "respond_alerts",
            "recover_summary", "recommendations"
        ],
    },
    "cis_controls": {
        "name": "CIS Controls Audit",
        "description": "Center for Internet Security Controls - "
                       "log management and monitoring compliance check.",
        "sections": [
            "executive_summary", "log_volume", "asset_inventory",
            "audit_logging", "continuous_monitoring",
            "incident_response", "recommendations"
        ],
    },
    "custom": {
        "name": "Custom Report",
        "description": "Generate a custom compliance report with "
                       "selected sections.",
        "sections": [
            "executive_summary", "log_volume", "auth_failures",
            "critical_alerts", "source_summary", "recommendations"
        ],
    },
}


def _generate_compliance_report(report_id, template, date_from, date_to,
                                parameters):
    """Generate a compliance report (runs in background thread)."""
    conn = get_db()
    conn.execute(
        "UPDATE compliance_reports SET status = 'generating' WHERE id = ?",
        (report_id,))
    conn.commit()

    try:
        tpl = COMPLIANCE_TEMPLATES.get(template, COMPLIANCE_TEMPLATES["custom"])
        params = json_mod.loads(parameters) if parameters else {}
        title = params.get("title", tpl["name"])

        # ---- Gather data ----
        total_logs = conn.execute(
            "SELECT COUNT(*) FROM logs WHERE timestamp >= ? AND timestamp <= ?",
            (date_from, date_to)
        ).fetchone()[0]

        sev_dist = conn.execute(
            "SELECT severity, COUNT(*) FROM logs "
            "WHERE timestamp >= ? AND timestamp <= ? "
            "GROUP BY severity ORDER BY COUNT(*) DESC",
            (date_from, date_to)
        ).fetchall()

        top_sources = conn.execute(
            "SELECT source_ip, source_name, COUNT(*) as cnt FROM logs "
            "WHERE timestamp >= ? AND timestamp <= ? "
            "GROUP BY source_ip ORDER BY cnt DESC LIMIT 20",
            (date_from, date_to)
        ).fetchall()

        alerts_total = conn.execute(
            "SELECT COUNT(*) FROM alerts "
            "WHERE timestamp >= ? AND timestamp <= ?",
            (date_from, date_to)
        ).fetchone()[0]

        alerts_by_sev = conn.execute(
            "SELECT severity, COUNT(*) FROM alerts "
            "WHERE timestamp >= ? AND timestamp <= ? "
            "GROUP BY severity ORDER BY COUNT(*) DESC",
            (date_from, date_to)
        ).fetchall()

        auth_fail_count = conn.execute(
            "SELECT COUNT(*) FROM logs "
            "WHERE timestamp >= ? AND timestamp <= ? "
            "AND (LOWER(message) LIKE '%failed%auth%' "
            "  OR LOWER(message) LIKE '%authentication fail%' "
            "  OR LOWER(message) LIKE '%login fail%' "
            "  OR LOWER(message) LIKE '%invalid password%' "
            "  OR LOWER(message) LIKE '%access denied%')",
            (date_from, date_to)
        ).fetchone()[0]

        priv_events = conn.execute(
            "SELECT COUNT(*) FROM logs "
            "WHERE timestamp >= ? AND timestamp <= ? "
            "AND (LOWER(message) LIKE '%privilege%' "
            "  OR LOWER(message) LIKE '%sudo%' "
            "  OR LOWER(message) LIKE '%root%' "
            "  OR LOWER(message) LIKE '%admin%' "
            "  OR LOWER(message) LIKE '%escalat%')",
            (date_from, date_to)
        ).fetchone()[0]

        critical_count = conn.execute(
            "SELECT COUNT(*) FROM logs "
            "WHERE timestamp >= ? AND timestamp <= ? "
            "AND severity_code <= 2",
            (date_from, date_to)
        ).fetchone()[0]

        corr_incidents = conn.execute(
            "SELECT COUNT(*) FROM correlation_incidents "
            "WHERE created_at >= ? AND created_at <= ?",
            (date_from, date_to)
        ).fetchone()[0]

        source_count = conn.execute(
            "SELECT COUNT(DISTINCT source_ip) FROM logs "
            "WHERE timestamp >= ? AND timestamp <= ?",
            (date_from, date_to)
        ).fetchone()[0]

        connector_count = conn.execute(
            "SELECT COUNT(*) FROM security_connectors WHERE enabled = 1"
        ).fetchone()[0]

        daily_counts = conn.execute(
            "SELECT DATE(timestamp) as d, COUNT(*) FROM logs "
            "WHERE timestamp >= ? AND timestamp <= ? "
            "GROUP BY d ORDER BY d",
            (date_from, date_to)
        ).fetchall()

        # ---- Build HTML report ----
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        html = []
        html.append("<!DOCTYPE html>")
        html.append("<html><head>")
        html.append("<meta charset='utf-8'>")
        html.append("<title>%s - SentryLog Compliance Report</title>" %
                    _html_esc(title))
        html.append("<style>")
        html.append("body{font-family:Arial,Helvetica,sans-serif;margin:40px;"
                     "color:#1a1a2e;background:#fff;line-height:1.6}")
        html.append("h1{color:#0f3460;border-bottom:3px solid #0f3460;"
                     "padding-bottom:8px}")
        html.append("h2{color:#16213e;margin-top:32px;border-bottom:1px solid #ddd;"
                     "padding-bottom:6px}")
        html.append("h3{color:#1a1a2e;margin-top:20px}")
        html.append("table{border-collapse:collapse;width:100%;margin:12px 0}")
        html.append("th,td{border:1px solid #ddd;padding:8px 12px;text-align:left}")
        html.append("th{background:#0f3460;color:#fff;font-weight:600}")
        html.append("tr:nth-child(even){background:#f8f9fa}")
        html.append(".stat-grid{display:flex;flex-wrap:wrap;gap:16px;margin:16px 0}")
        html.append(".stat-card{background:#f0f4ff;border:1px solid #d0d8f0;"
                     "border-radius:8px;padding:16px 24px;min-width:160px}")
        html.append(".stat-num{font-size:28px;font-weight:700;color:#0f3460}")
        html.append(".stat-label{font-size:13px;color:#666;margin-top:4px}")
        html.append(".finding{background:#fff3cd;border-left:4px solid #ffc107;"
                     "padding:12px 16px;margin:8px 0;border-radius:0 4px 4px 0}")
        html.append(".finding-critical{background:#f8d7da;border-left-color:#dc3545}")
        html.append(".footer{margin-top:40px;padding-top:16px;"
                     "border-top:2px solid #0f3460;font-size:12px;color:#888}")
        html.append("@media print{body{margin:20px}}")
        html.append("</style></head><body>")

        # Header
        html.append("<h1>%s</h1>" % _html_esc(title))
        html.append("<p><strong>Report Period:</strong> %s to %s</p>" % (
            _html_esc(date_from[:10]), _html_esc(date_to[:10])))
        html.append("<p><strong>Generated:</strong> %s UTC by "
                     "MyClover.Tech.SentryLog v%s</p>" % (now_str, VERSION))
        html.append("<p><strong>Template:</strong> %s</p>" %
                    _html_esc(tpl["name"]))

        # Executive Summary
        html.append("<h2>1. Executive Summary</h2>")
        html.append("<div class='stat-grid'>")
        html.append("<div class='stat-card'><div class='stat-num'>%s</div>"
                     "<div class='stat-label'>Total Log Events</div></div>" %
                    _fmt_num(total_logs))
        html.append("<div class='stat-card'><div class='stat-num'>%s</div>"
                     "<div class='stat-label'>Unique Sources</div></div>" %
                    _fmt_num(source_count))
        html.append("<div class='stat-card'><div class='stat-num'>%s</div>"
                     "<div class='stat-label'>Alerts Triggered</div></div>" %
                    _fmt_num(alerts_total))
        html.append("<div class='stat-card'><div class='stat-num'>%s</div>"
                     "<div class='stat-label'>Critical Events</div></div>" %
                    _fmt_num(critical_count))
        html.append("<div class='stat-card'><div class='stat-num'>%s</div>"
                     "<div class='stat-label'>Auth Failures</div></div>" %
                    _fmt_num(auth_fail_count))
        html.append("<div class='stat-card'><div class='stat-num'>%s</div>"
                     "<div class='stat-label'>Correlation Incidents</div></div>" %
                    _fmt_num(corr_incidents))
        html.append("</div>")

        if critical_count > 0:
            html.append("<div class='finding finding-critical'>"
                         "<strong>Critical Finding:</strong> %d critical/emergency "
                         "events detected during the reporting period. "
                         "Immediate review recommended.</div>" % critical_count)
        if auth_fail_count > 50:
            html.append("<div class='finding'>"
                         "<strong>Warning:</strong> %d authentication failures "
                         "detected. Possible brute-force activity.</div>" %
                        auth_fail_count)

        # Log Volume
        html.append("<h2>2. Log Volume Analysis</h2>")
        html.append("<h3>Daily Log Volume</h3>")
        html.append("<table><tr><th>Date</th><th>Events</th></tr>")
        for row in daily_counts:
            html.append("<tr><td>%s</td><td>%s</td></tr>" % (
                _html_esc(str(row[0])), _fmt_num(row[1])))
        if not daily_counts:
            html.append("<tr><td colspan='2'>No logs in this period</td></tr>")
        html.append("</table>")

        html.append("<h3>Severity Distribution</h3>")
        html.append("<table><tr><th>Severity</th><th>Count</th>"
                     "<th>Percentage</th></tr>")
        for row in sev_dist:
            pct = (row[1] / total_logs * 100) if total_logs > 0 else 0
            html.append("<tr><td>%s</td><td>%s</td><td>%.1f%%</td></tr>" % (
                _html_esc(str(row[0])), _fmt_num(row[1]), pct))
        html.append("</table>")

        # Authentication Failures
        html.append("<h2>3. Authentication & Access Events</h2>")
        html.append("<p>Authentication failures detected: "
                     "<strong>%s</strong></p>" % _fmt_num(auth_fail_count))
        html.append("<p>Privilege escalation events: "
                     "<strong>%s</strong></p>" % _fmt_num(priv_events))

        top_auth_sources = conn.execute(
            "SELECT source_ip, COUNT(*) as cnt FROM logs "
            "WHERE timestamp >= ? AND timestamp <= ? "
            "AND (LOWER(message) LIKE '%failed%auth%' "
            "  OR LOWER(message) LIKE '%authentication fail%' "
            "  OR LOWER(message) LIKE '%login fail%') "
            "GROUP BY source_ip ORDER BY cnt DESC LIMIT 10",
            (date_from, date_to)
        ).fetchall()

        if top_auth_sources:
            html.append("<h3>Top Sources of Auth Failures</h3>")
            html.append("<table><tr><th>Source IP</th>"
                         "<th>Failures</th></tr>")
            for row in top_auth_sources:
                html.append("<tr><td>%s</td><td>%s</td></tr>" % (
                    _html_esc(str(row[0])), _fmt_num(row[1])))
            html.append("</table>")

        # Alerts & Incidents
        html.append("<h2>4. Alerts & Correlation Incidents</h2>")
        html.append("<p>Total alerts: <strong>%s</strong></p>" %
                    _fmt_num(alerts_total))
        if alerts_by_sev:
            html.append("<table><tr><th>Severity</th><th>Count</th></tr>")
            for row in alerts_by_sev:
                html.append("<tr><td>%s</td><td>%s</td></tr>" % (
                    _html_esc(str(row[0])), _fmt_num(row[1])))
            html.append("</table>")
        html.append("<p>Correlation incidents: "
                     "<strong>%s</strong></p>" % _fmt_num(corr_incidents))

        # Source Summary
        html.append("<h2>5. Source Inventory</h2>")
        html.append("<p>Active sources: <strong>%d</strong> | "
                     "Security connectors: <strong>%d</strong></p>" % (
                         source_count, connector_count))
        html.append("<table><tr><th>Source IP</th><th>Name</th>"
                     "<th>Events</th></tr>")
        for row in top_sources:
            html.append("<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (
                _html_esc(str(row[0])),
                _html_esc(str(row[1]) if row[1] else ""),
                _fmt_num(row[2])))
        html.append("</table>")

        # Recommendations
        html.append("<h2>6. Recommendations</h2>")
        html.append("<ol>")
        if critical_count > 0:
            html.append("<li>Review and remediate %d critical events "
                         "immediately.</li>" % critical_count)
        if auth_fail_count > 20:
            html.append("<li>Investigate %d authentication failures for "
                         "potential brute-force or credential stuffing.</li>" %
                        auth_fail_count)
        if source_count < 5:
            html.append("<li>Consider adding more log sources to improve "
                         "visibility (currently %d sources).</li>" %
                        source_count)
        if connector_count == 0:
            html.append("<li>Enable security API connectors (CrowdStrike, "
                         "Defender, etc.) for deeper threat visibility.</li>")
        if corr_incidents == 0 and total_logs > 100:
            html.append("<li>Set up correlation rules to detect multi-source "
                         "attack patterns.</li>")
        html.append("<li>Ensure log retention meets compliance requirements "
                     "for your framework.</li>")
        html.append("<li>Schedule automated compliance reports for "
                     "continuous monitoring.</li>")
        html.append("</ol>")

        # Footer
        html.append("<div class='footer'>")
        html.append("<p>Generated by MyClover.Tech.SentryLog v%s | "
                     "Template: %s | Period: %s to %s</p>" % (
                         VERSION, _html_esc(tpl["name"]),
                         _html_esc(date_from[:10]),
                         _html_esc(date_to[:10])))
        html.append("<p>This report is auto-generated. Verify findings "
                     "before taking action.</p>")
        html.append("</div></body></html>")

        full_html = "\n".join(html)
        summary = ("Analyzed %s events from %d sources. "
                   "%d alerts, %d critical events, %d auth failures, "
                   "%d correlation incidents." % (
                       _fmt_num(total_logs), source_count,
                       alerts_total, critical_count,
                       auth_fail_count, corr_incidents))

        conn.execute(
            "UPDATE compliance_reports SET status = 'completed', "
            "html_content = ?, summary = ?, generated_at = ? WHERE id = ?",
            (full_html, summary, now_str, report_id)
        )
        conn.commit()
        log.info("[Compliance] Report %d generated: %s", report_id, summary)

    except Exception as exc:
        log.error("[Compliance] Report %d failed: %s", report_id, exc)
        conn.execute(
            "UPDATE compliance_reports SET status = 'failed', "
            "summary = ? WHERE id = ?",
            ("Error: %s" % str(exc)[:500], report_id)
        )
        conn.commit()
    finally:
        conn.close()


def _html_esc(text):
    """Escape HTML special characters."""
    return (str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


def _fmt_num(n):
    """Format a number with commas."""
    try:
        return "{:,}".format(int(n))
    except (ValueError, TypeError):
        return str(n)


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------
def get_stats(hours=24):
    """Get dashboard statistics."""
    cutoff = (
        datetime.datetime.now() - datetime.timedelta(hours=hours)
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
            datetime.datetime.now() - datetime.timedelta(hours=hours)
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
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

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
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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

    # ---- Windows Event Log Targets (Phase 2) ----
    @app.route("/api/winlog/targets")
    @require_tier(TIER_ENT)
    def api_winlog_targets():
        conn = get_db()
        rows = conn.execute(
            "SELECT * FROM winlog_targets ORDER BY created_at DESC"
        ).fetchall()
        conn.close()
        targets = []
        for r in rows:
            d = dict(r)
            # Mask password in response
            if d.get("password"):
                d["password"] = "********"
            # Check if collector thread is alive
            with _winlog_threads_lock:
                t = _winlog_threads.get(d["id"])
                d["collector_running"] = t is not None and t.is_alive()
            targets.append(d)
        return jsonify({"targets": targets})

    @app.route("/api/winlog/targets", methods=["POST"])
    @require_tier(TIER_ENT)
    def api_create_winlog_target():
        data = request.get_json(force=True)
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        target_type = data.get("target_type", "local")

        conn = get_db()
        c = conn.cursor()
        c.execute("""
            INSERT INTO winlog_targets (name, target_type, hostname, username,
                password, use_ssl, port, channels, poll_interval_seconds,
                enabled, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data.get("name", "Windows Logs"),
            target_type,
            data.get("hostname", "localhost"),
            data.get("username", ""),
            data.get("password", ""),
            1 if data.get("use_ssl", False) else 0,
            data.get("port", 5985 if not data.get("use_ssl") else 5986),
            data.get("channels", "Security,System,Application"),
            data.get("poll_interval_seconds", 60),
            1 if data.get("enabled", True) else 0,
            now, now,
        ))
        target_id = c.lastrowid
        conn.commit()

        # Also add as a source
        conn.execute("""
            INSERT OR IGNORE INTO sources (ip, name, first_seen, last_seen,
                log_count, device_type, os_type)
            VALUES (?, ?, ?, ?, 0, 'Windows', 'Windows')
        """, (
            data.get("hostname", "localhost"),
            data.get("name", "Windows Logs"),
            now, now,
        ))
        conn.commit()
        conn.close()

        # Start collector if enabled
        if data.get("enabled", True):
            row = get_db().execute(
                "SELECT * FROM winlog_targets WHERE id = ?", (target_id,)
            ).fetchone()
            if row:
                start_winlog_collector(dict(row))

        return jsonify({"status": "ok", "id": target_id})

    @app.route("/api/winlog/targets/<int:target_id>", methods=["PUT"])
    @require_tier(TIER_ENT)
    def api_update_winlog_target(target_id):
        data = request.get_json(force=True)
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        conn = get_db()
        # If password is masked, keep the old one
        old_row = conn.execute(
            "SELECT password FROM winlog_targets WHERE id = ?", (target_id,)
        ).fetchone()
        password = data.get("password", "")
        if password == "********" and old_row:
            password = old_row["password"]

        conn.execute("""
            UPDATE winlog_targets SET name = ?, target_type = ?, hostname = ?,
                username = ?, password = ?, use_ssl = ?, port = ?,
                channels = ?, poll_interval_seconds = ?, enabled = ?,
                updated_at = ?
            WHERE id = ?
        """, (
            data.get("name", ""),
            data.get("target_type", "local"),
            data.get("hostname", "localhost"),
            data.get("username", ""),
            password,
            1 if data.get("use_ssl", False) else 0,
            data.get("port", 5985),
            data.get("channels", "Security,System,Application"),
            data.get("poll_interval_seconds", 60),
            1 if data.get("enabled", True) else 0,
            now, target_id,
        ))
        conn.commit()
        conn.close()

        # Restart collector
        was_enabled = data.get("enabled", True)
        if was_enabled:
            row = get_db().execute(
                "SELECT * FROM winlog_targets WHERE id = ?", (target_id,)
            ).fetchone()
            if row:
                start_winlog_collector(dict(row))

        return jsonify({"status": "ok"})

    @app.route("/api/winlog/targets/<int:target_id>", methods=["DELETE"])
    @require_tier(TIER_ENT)
    def api_delete_winlog_target(target_id):
        stop_winlog_collector(target_id)
        conn = get_db()
        conn.execute("DELETE FROM winlog_targets WHERE id = ?", (target_id,))
        conn.commit()
        conn.close()
        return jsonify({"status": "ok"})

    @app.route("/api/winlog/targets/<int:target_id>/test", methods=["POST"])
    @require_tier(TIER_ENT)
    def api_test_winlog_target(target_id):
        """Test connectivity to a Windows Event Log target."""
        conn = get_db()
        row = conn.execute(
            "SELECT * FROM winlog_targets WHERE id = ?", (target_id,)
        ).fetchone()
        conn.close()
        if not row:
            return jsonify({"error": "not_found"}), 404

        target = dict(row)
        result = {"target_id": target_id, "status": "unknown"}

        if target["target_type"] == "local":
            if not HAS_WIN32:
                result["status"] = "error"
                result["message"] = "pywin32 not installed. Run: pip install pywin32"
            else:
                try:
                    channels = [c.strip() for c in target["channels"].split(",") if c.strip()]
                    test_ch = channels[0] if channels else "System"
                    hand = win32evtlog.OpenEventLog(None, test_ch)
                    total = win32evtlog.GetNumberOfEventLogRecords(hand)
                    win32evtlog.CloseEventLog(hand)
                    result["status"] = "ok"
                    result["message"] = "Connected. %s has %d records." % (test_ch, total)
                except Exception as e:
                    result["status"] = "error"
                    result["message"] = str(e)

        elif target["target_type"] == "remote":
            if not HAS_WINRM:
                result["status"] = "error"
                result["message"] = "pywinrm not installed. Run: pip install pywinrm"
            else:
                try:
                    scheme = "https" if target["use_ssl"] else "http"
                    endpoint = "%s://%s:%d/wsman" % (
                        scheme, target["hostname"], target["port"]
                    )
                    transport = "ssl" if target["use_ssl"] else "ntlm"
                    session = winrm.Session(
                        endpoint,
                        auth=(target["username"], target["password"]),
                        transport=transport,
                        server_cert_validation="ignore",
                    )
                    r = session.run_ps("Get-WinEvent -ListLog System | Select-Object RecordCount | ConvertTo-Json")
                    if r.status_code == 0:
                        output = r.std_out
                        if isinstance(output, bytes):
                            output = output.decode("utf-8", errors="replace")
                        result["status"] = "ok"
                        result["message"] = "Connected to %s. Response: %s" % (
                            target["hostname"], output.strip()[:200]
                        )
                    else:
                        err = r.std_err
                        if isinstance(err, bytes):
                            err = err.decode("utf-8", errors="replace")
                        result["status"] = "error"
                        result["message"] = str(err)[:200]
                except Exception as e:
                    result["status"] = "error"
                    result["message"] = str(e)[:200]

        return jsonify(result)

    @app.route("/api/winlog/status")
    @require_tier(TIER_ENT)
    def api_winlog_status():
        """Get overall Windows Event Log collection status."""
        conn = get_db()
        targets = conn.execute("SELECT * FROM winlog_targets").fetchall()
        total_count = conn.execute(
            "SELECT COUNT(*) FROM logs WHERE facility_code = -2"
        ).fetchone()[0]
        conn.close()

        running = 0
        with _winlog_threads_lock:
            for tid, t in _winlog_threads.items():
                if t.is_alive():
                    running += 1

        return jsonify({
            "total_targets": len(targets),
            "enabled_targets": sum(1 for t in targets if t["enabled"]),
            "running_collectors": running,
            "total_winlog_events": total_count,
            "pywin32_available": HAS_WIN32,
            "pywinrm_available": HAS_WINRM,
        })

    # ---- Phase 3: Security Connector endpoints (Enterprise) ----

    @app.route("/api/security/connectors")
    @require_tier(TIER_ENT)
    def api_list_security_connectors():
        conn = get_db()
        rows = conn.execute(
            "SELECT id, name, connector_type, api_url, api_key, api_secret, "
            "extra_config, poll_interval_seconds, enabled, last_poll, "
            "last_cursor, log_count, error_message, created_at, updated_at "
            "FROM security_connectors ORDER BY id"
        ).fetchall()
        conn.close()
        connectors = []
        for r in rows:
            cid = r[0]
            connectors.append({
                "id": cid, "name": r[1], "connector_type": r[2],
                "connector_label": CONNECTOR_TYPES.get(r[2], r[2]),
                "api_url": r[3],
                "api_key_set": bool(r[4]),
                "api_secret_set": bool(r[5]),
                "extra_config": r[6],
                "poll_interval_seconds": r[7], "enabled": bool(r[8]),
                "last_poll": r[9], "last_cursor": r[10],
                "log_count": r[11], "error_message": r[12],
                "created_at": r[13], "updated_at": r[14],
                "collector_running": (cid in _connector_threads
                                      and _connector_threads[cid].is_alive()),
            })
        return jsonify({"connectors": connectors})

    @app.route("/api/security/connectors", methods=["POST"])
    @require_tier(TIER_ENT)
    def api_create_security_connector():
        data = request.get_json(force=True)
        name = data.get("name", "").strip()
        ctype = data.get("connector_type", "").strip()
        if not name:
            return jsonify({"error": True, "message": "Name is required."}), 400
        if ctype not in CONNECTOR_TYPES:
            return jsonify({"error": True,
                            "message": "Invalid connector type."}), 400

        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        extra = data.get("extra_config", "{}")
        if isinstance(extra, dict):
            extra = json_mod.dumps(extra)

        conn = get_db()
        c = conn.execute(
            "INSERT INTO security_connectors "
            "(name, connector_type, api_url, api_key, api_secret, extra_config, "
            " poll_interval_seconds, enabled, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (name, ctype,
             data.get("api_url", "").strip(),
             data.get("api_key", "").strip(),
             data.get("api_secret", "").strip(),
             extra,
             int(data.get("poll_interval_seconds", 300)),
             1 if data.get("enabled", True) else 0,
             now, now)
        )
        new_id = c.lastrowid
        conn.commit()
        conn.close()

        # Auto-start if enabled
        if data.get("enabled", True):
            connector = {
                "id": new_id, "name": name, "connector_type": ctype,
                "api_url": data.get("api_url", ""),
                "api_key": data.get("api_key", ""),
                "api_secret": data.get("api_secret", ""),
                "extra_config": extra,
                "poll_interval_seconds": int(data.get("poll_interval_seconds", 300)),
                "enabled": 1,
            }
            start_security_connector(connector)

        return jsonify({"id": new_id, "status": "created"})

    @app.route("/api/security/connectors/<int:cid>", methods=["PUT"])
    @require_tier(TIER_ENT)
    def api_update_security_connector(cid):
        data = request.get_json(force=True)
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Stop existing collector before update
        stop_security_connector(cid)

        extra = data.get("extra_config", None)
        if isinstance(extra, dict):
            extra = json_mod.dumps(extra)

        conn = get_db()
        fields = []
        vals = []
        for key in ("name", "connector_type", "api_url", "api_key",
                     "api_secret", "poll_interval_seconds"):
            if key in data:
                fields.append("%s = ?" % key)
                vals.append(data[key])
        if extra is not None:
            fields.append("extra_config = ?")
            vals.append(extra)
        if "enabled" in data:
            fields.append("enabled = ?")
            vals.append(1 if data["enabled"] else 0)
        fields.append("updated_at = ?")
        vals.append(now)
        vals.append(cid)

        if fields:
            conn.execute(
                "UPDATE security_connectors SET %s WHERE id = ?" % ", ".join(fields),
                vals
            )
        conn.commit()

        # Restart if enabled
        row = conn.execute(
            "SELECT id, name, connector_type, api_url, api_key, api_secret, "
            "extra_config, poll_interval_seconds, enabled "
            "FROM security_connectors WHERE id = ?", (cid,)
        ).fetchone()
        conn.close()

        if row and row[8]:
            connector = {
                "id": row[0], "name": row[1], "connector_type": row[2],
                "api_url": row[3], "api_key": row[4], "api_secret": row[5],
                "extra_config": row[6], "poll_interval_seconds": row[7],
                "enabled": row[8],
            }
            start_security_connector(connector)

        return jsonify({"status": "updated"})

    @app.route("/api/security/connectors/<int:cid>", methods=["DELETE"])
    @require_tier(TIER_ENT)
    def api_delete_security_connector(cid):
        stop_security_connector(cid)
        conn = get_db()
        conn.execute("DELETE FROM security_connectors WHERE id = ?", (cid,))
        conn.commit()
        conn.close()
        return jsonify({"status": "deleted"})

    @app.route("/api/security/connectors/<int:cid>/test", methods=["POST"])
    @require_tier(TIER_ENT)
    def api_test_security_connector(cid):
        conn = get_db()
        row = conn.execute(
            "SELECT connector_type, api_url, api_key, api_secret, extra_config "
            "FROM security_connectors WHERE id = ?", (cid,)
        ).fetchone()
        conn.close()

        if not row:
            return jsonify({"status": "error",
                            "message": "Connector not found."}), 404

        ctype, api_url, api_key, api_secret, extra_config = row

        if not HAS_REQUESTS:
            return jsonify({"status": "error",
                            "message": "requests library not installed. "
                            "Run: pip install requests"})

        # Attempt a lightweight connectivity check per vendor
        try:
            if ctype == "crowdstrike":
                base = api_url.rstrip("/") if api_url else "https://api.crowdstrike.com"
                r = requests_lib.post(
                    "%s/oauth2/token" % base,
                    data={"client_id": api_key, "client_secret": api_secret},
                    timeout=15)
                if r.status_code == 201 or r.status_code == 200:
                    return jsonify({"status": "ok",
                                    "message": "CrowdStrike OAuth2 token obtained."})
                return jsonify({"status": "error",
                                "message": "Auth failed: HTTP %d" % r.status_code})

            elif ctype == "sentinelone":
                if not api_url:
                    return jsonify({"status": "error",
                                    "message": "API URL required."})
                r = requests_lib.get(
                    "%s/web/api/v2.1/system/status" % api_url.rstrip("/"),
                    headers={"Authorization": "ApiToken %s" % api_key},
                    timeout=15)
                if r.ok:
                    return jsonify({"status": "ok",
                                    "message": "SentinelOne API reachable."})
                return jsonify({"status": "error",
                                "message": "HTTP %d" % r.status_code})

            elif ctype == "defender":
                cfg = json_mod.loads(extra_config) if extra_config else {}
                tid = cfg.get("tenant_id", "")
                if not tid:
                    return jsonify({"status": "error",
                                    "message": "tenant_id required in extra config."})
                r = requests_lib.post(
                    "https://login.microsoftonline.com/%s/oauth2/v2.0/token" % tid,
                    data={"client_id": api_key, "client_secret": api_secret,
                          "scope": "https://api.securitycenter.microsoft.com/.default",
                          "grant_type": "client_credentials"},
                    timeout=15)
                if r.ok:
                    return jsonify({"status": "ok",
                                    "message": "Defender token obtained."})
                return jsonify({"status": "error",
                                "message": "Auth failed: HTTP %d" % r.status_code})

            elif ctype == "sophos":
                r = requests_lib.post(
                    "https://id.sophos.com/api/v2/oauth2/token",
                    data={"client_id": api_key, "client_secret": api_secret,
                          "grant_type": "client_credentials", "scope": "token"},
                    timeout=15)
                if r.ok:
                    return jsonify({"status": "ok",
                                    "message": "Sophos auth successful."})
                return jsonify({"status": "error",
                                "message": "Auth failed: HTTP %d" % r.status_code})

            elif ctype == "cortex_xdr":
                if not api_url:
                    return jsonify({"status": "error",
                                    "message": "API URL required."})
                # Lightweight ping -- list incident-count
                return jsonify({"status": "ok",
                                "message": "Cortex XDR URL configured. "
                                "Full test runs on first poll."})

            elif ctype == "generic_api":
                if not api_url:
                    return jsonify({"status": "error",
                                    "message": "API URL required."})
                headers = {}
                if api_key:
                    cfg = json_mod.loads(extra_config) if extra_config else {}
                    ah = cfg.get("auth_header", "Authorization")
                    ap = cfg.get("auth_prefix", "Bearer ")
                    headers[ah] = "%s%s" % (ap, api_key)
                r = requests_lib.get(api_url, headers=headers, timeout=15)
                return jsonify({"status": "ok" if r.ok else "error",
                                "message": "HTTP %d (%d bytes)" % (
                                    r.status_code, len(r.content))})

            else:
                return jsonify({"status": "error",
                                "message": "Unknown connector type."})

        except Exception as exc:
            return jsonify({"status": "error",
                            "message": str(exc)[:500]})

    @app.route("/api/security/connectors/status")
    @require_tier(TIER_ENT)
    def api_security_connectors_status():
        conn = get_db()
        total = conn.execute(
            "SELECT COUNT(*) FROM security_connectors"
        ).fetchone()[0]
        total_events = conn.execute(
            "SELECT COALESCE(SUM(log_count), 0) FROM security_connectors"
        ).fetchone()[0]
        conn.close()

        running = sum(1 for cid, t in _connector_threads.items()
                      if t.is_alive())

        return jsonify({
            "total_connectors": total,
            "running_connectors": running,
            "total_events": total_events,
            "requests_available": HAS_REQUESTS,
            "supported_types": CONNECTOR_TYPES,
        })

    # ---- Phase 3: Inbound Webhook endpoint ----

    @app.route("/api/security/webhook/<token>", methods=["POST"])
    def api_security_webhook(token):
        """Receive events from any security tool via webhook push.
        No tier restriction on the webhook itself -- gated by token existence.
        """
        conn = get_db()
        row = conn.execute(
            "SELECT id, source_name, enabled FROM webhook_tokens WHERE token = ?",
            (token,)
        ).fetchone()
        if not row or not row[2]:
            conn.close()
            return jsonify({"error": "Invalid or disabled webhook token."}), 403

        wh_id, source_name, _ = row

        data = request.get_json(silent=True) or {}
        if isinstance(data, list):
            events = data
        elif "events" in data:
            events = data["events"]
        elif "alerts" in data:
            events = data["alerts"]
        else:
            events = [data]

        count = 0
        for evt in events:
            if not isinstance(evt, dict):
                continue
            event = {
                "timestamp": str(evt.get("timestamp", ""))[:19].replace("T", " "),
                "source_ip": evt.get("source_ip", evt.get("ip",
                             request.remote_addr or "0.0.0.0")),
                "hostname": evt.get("hostname", evt.get("host", source_name)),
                "severity": evt.get("severity", evt.get("level", "warning")),
                "program": evt.get("program", evt.get("source", "webhook")),
                "message": str(evt.get("message", evt.get("description",
                           str(evt))))[:2000],
                "raw": json_mod.dumps(evt, default=str),
            }
            normalized = _normalize_security_event(event, "webhook",
                                                   source_name)
            ingest_log(normalized)
            count += 1

        conn.execute(
            "UPDATE webhook_tokens SET log_count = log_count + ? WHERE id = ?",
            (count, wh_id))
        conn.commit()
        conn.close()

        return jsonify({"status": "ok", "ingested": count})

    @app.route("/api/security/webhooks")
    @require_tier(TIER_ENT)
    def api_list_webhooks():
        conn = get_db()
        rows = conn.execute(
            "SELECT id, token, label, source_name, enabled, log_count, created_at "
            "FROM webhook_tokens ORDER BY id"
        ).fetchall()
        conn.close()
        webhooks = []
        for r in rows:
            webhooks.append({
                "id": r[0], "token": r[1], "label": r[2],
                "source_name": r[3], "enabled": bool(r[4]),
                "log_count": r[5], "created_at": r[6],
            })
        return jsonify({"webhooks": webhooks})

    @app.route("/api/security/webhooks", methods=["POST"])
    @require_tier(TIER_ENT)
    def api_create_webhook():
        data = request.get_json(force=True)
        import secrets as secrets_mod
        token = data.get("token", "").strip() or secrets_mod.token_urlsafe(32)
        label = data.get("label", "").strip() or "Webhook"
        source_name = data.get("source_name", "").strip() or "webhook"
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        conn = get_db()
        c = conn.execute(
            "INSERT INTO webhook_tokens (token, label, source_name, enabled, created_at) "
            "VALUES (?, ?, ?, 1, ?)",
            (token, label, source_name, now)
        )
        new_id = c.lastrowid
        conn.commit()
        conn.close()

        return jsonify({
            "id": new_id, "token": token,
            "webhook_url": "/api/security/webhook/%s" % token,
            "status": "created"
        })

    @app.route("/api/security/webhooks/<int:wh_id>", methods=["DELETE"])
    @require_tier(TIER_ENT)
    def api_delete_webhook(wh_id):
        conn = get_db()
        conn.execute("DELETE FROM webhook_tokens WHERE id = ?", (wh_id,))
        conn.commit()
        conn.close()
        return jsonify({"status": "deleted"})

    # ---- Phase 4: Correlation endpoints ----

    @app.route("/api/correlation/rules")
    @require_tier(TIER_PRO)
    def api_corr_rules():
        conn = get_db()
        rows = conn.execute(
            "SELECT id, name, description, conditions, time_window_seconds, "
            "min_matches, severity, enabled, cooldown_minutes, last_fired, "
            "fire_count, created_at, updated_at "
            "FROM correlation_rules ORDER BY id"
        ).fetchall()
        conn.close()
        rules = []
        for r in rows:
            rules.append({
                "id": r[0], "name": r[1], "description": r[2],
                "conditions": r[3], "time_window_seconds": r[4],
                "min_matches": r[5], "severity": r[6],
                "enabled": bool(r[7]), "cooldown_minutes": r[8],
                "last_fired": r[9], "fire_count": r[10],
                "created_at": r[11], "updated_at": r[12],
            })
        return jsonify({"rules": rules})

    @app.route("/api/correlation/rules", methods=["POST"])
    @require_tier(TIER_PRO)
    def api_create_corr_rule():
        data = request.get_json(force=True)
        name = data.get("name", "").strip()
        if not name:
            return jsonify({"error": True,
                            "message": "Name is required."}), 400

        conditions = data.get("conditions", "[]")
        if isinstance(conditions, list):
            conditions = json_mod.dumps(conditions)

        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = get_db()
        c = conn.execute(
            "INSERT INTO correlation_rules "
            "(name, description, conditions, time_window_seconds, min_matches, "
            " severity, enabled, cooldown_minutes, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (name,
             data.get("description", ""),
             conditions,
             int(data.get("time_window_seconds", 300)),
             int(data.get("min_matches", 2)),
             data.get("severity", "critical"),
             1 if data.get("enabled", True) else 0,
             int(data.get("cooldown_minutes", 30)),
             now, now)
        )
        new_id = c.lastrowid
        conn.commit()
        conn.close()
        return jsonify({"id": new_id, "status": "created"})

    @app.route("/api/correlation/rules/<int:rid>", methods=["PUT"])
    @require_tier(TIER_PRO)
    def api_update_corr_rule(rid):
        data = request.get_json(force=True)
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        conn = get_db()
        fields = []
        vals = []
        for key in ("name", "description", "time_window_seconds",
                     "min_matches", "severity", "cooldown_minutes"):
            if key in data:
                fields.append("%s = ?" % key)
                vals.append(data[key])
        if "conditions" in data:
            cond = data["conditions"]
            if isinstance(cond, list):
                cond = json_mod.dumps(cond)
            fields.append("conditions = ?")
            vals.append(cond)
        if "enabled" in data:
            fields.append("enabled = ?")
            vals.append(1 if data["enabled"] else 0)
        fields.append("updated_at = ?")
        vals.append(now)
        vals.append(rid)

        if fields:
            conn.execute(
                "UPDATE correlation_rules SET %s WHERE id = ?" %
                ", ".join(fields), vals)
        conn.commit()
        conn.close()
        return jsonify({"status": "updated"})

    @app.route("/api/correlation/rules/<int:rid>", methods=["DELETE"])
    @require_tier(TIER_PRO)
    def api_delete_corr_rule(rid):
        conn = get_db()
        conn.execute("DELETE FROM correlation_rules WHERE id = ?", (rid,))
        conn.commit()
        conn.close()
        return jsonify({"status": "deleted"})

    @app.route("/api/correlation/incidents")
    @require_tier(TIER_PRO)
    def api_corr_incidents():
        limit = int(request.args.get("limit", 100))
        status_filter = request.args.get("status", "")

        conn = get_db()
        sql = ("SELECT id, rule_id, rule_name, severity, matched_events, "
               "matched_count, summary, status, acknowledged, ack_by, "
               "ack_at, created_at FROM correlation_incidents")
        params = []
        if status_filter:
            sql += " WHERE status = ?"
            params.append(status_filter)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(sql, params).fetchall()
        conn.close()

        incidents = []
        for r in rows:
            incidents.append({
                "id": r[0], "rule_id": r[1], "rule_name": r[2],
                "severity": r[3], "matched_events": r[4],
                "matched_count": r[5], "summary": r[6],
                "status": r[7], "acknowledged": bool(r[8]),
                "ack_by": r[9], "ack_at": r[10],
                "created_at": r[11],
            })
        return jsonify({"incidents": incidents})

    @app.route("/api/correlation/incidents/<int:iid>/acknowledge",
               methods=["POST"])
    @require_tier(TIER_PRO)
    def api_ack_corr_incident(iid):
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = get_db()
        conn.execute(
            "UPDATE correlation_incidents SET acknowledged = 1, "
            "status = 'acknowledged', ack_at = ? WHERE id = ?",
            (now, iid))
        conn.commit()
        conn.close()
        return jsonify({"status": "acknowledged"})

    @app.route("/api/correlation/incidents/<int:iid>/close",
               methods=["POST"])
    @require_tier(TIER_PRO)
    def api_close_corr_incident(iid):
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = get_db()
        conn.execute(
            "UPDATE correlation_incidents SET status = 'closed', "
            "ack_at = ? WHERE id = ?",
            (now, iid))
        conn.commit()
        conn.close()
        return jsonify({"status": "closed"})

    @app.route("/api/correlation/status")
    @require_tier(TIER_PRO)
    def api_corr_status():
        conn = get_db()
        total_rules = conn.execute(
            "SELECT COUNT(*) FROM correlation_rules"
        ).fetchone()[0]
        enabled_rules = conn.execute(
            "SELECT COUNT(*) FROM correlation_rules WHERE enabled = 1"
        ).fetchone()[0]
        open_incidents = conn.execute(
            "SELECT COUNT(*) FROM correlation_incidents WHERE status = 'open'"
        ).fetchone()[0]
        total_incidents = conn.execute(
            "SELECT COUNT(*) FROM correlation_incidents"
        ).fetchone()[0]
        conn.close()

        return jsonify({
            "total_rules": total_rules,
            "enabled_rules": enabled_rules,
            "open_incidents": open_incidents,
            "total_incidents": total_incidents,
            "buffer_size": len(_correlation_buffer),
        })

    # ---- Phase 4: Compliance Report endpoints (Enterprise) ----

    @app.route("/api/compliance/templates")
    @require_tier(TIER_ENT)
    def api_compliance_templates():
        templates = {}
        for key, tpl in COMPLIANCE_TEMPLATES.items():
            templates[key] = {
                "name": tpl["name"],
                "description": tpl["description"],
                "sections": tpl["sections"],
            }
        return jsonify({"templates": templates})

    @app.route("/api/compliance/reports/generate", methods=["POST"])
    @require_tier(TIER_ENT)
    def api_generate_compliance_report():
        data = request.get_json(force=True)
        template = data.get("template", "custom")
        if template not in COMPLIANCE_TEMPLATES:
            return jsonify({"error": True,
                            "message": "Invalid template."}), 400

        date_from = data.get("date_from", "")
        date_to = data.get("date_to", "")
        if not date_from or not date_to:
            return jsonify({"error": True,
                            "message": "date_from and date_to required."}), 400

        params = data.get("parameters", "{}")
        if isinstance(params, dict):
            params = json_mod.dumps(params)

        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = get_db()
        c = conn.execute(
            "INSERT INTO compliance_reports "
            "(template, title, date_from, date_to, parameters, "
            " status, created_at) VALUES (?, ?, ?, ?, ?, 'pending', ?)",
            (template,
             data.get("title", COMPLIANCE_TEMPLATES[template]["name"]),
             date_from, date_to, params, now)
        )
        report_id = c.lastrowid
        conn.commit()
        conn.close()

        # Generate in background thread
        t = threading.Thread(
            target=_generate_compliance_report,
            args=(report_id, template, date_from, date_to, params),
            daemon=True
        )
        t.start()

        return jsonify({"id": report_id, "status": "generating"})

    @app.route("/api/compliance/reports")
    @require_tier(TIER_ENT)
    def api_list_compliance_reports():
        conn = get_db()
        rows = conn.execute(
            "SELECT id, template, title, date_from, date_to, status, "
            "summary, generated_at, created_at "
            "FROM compliance_reports ORDER BY id DESC LIMIT 50"
        ).fetchall()
        conn.close()
        reports = []
        for r in rows:
            reports.append({
                "id": r[0], "template": r[1], "title": r[2],
                "date_from": r[3], "date_to": r[4],
                "status": r[5], "summary": r[6],
                "generated_at": r[7], "created_at": r[8],
            })
        return jsonify({"reports": reports})

    @app.route("/api/compliance/reports/<int:rid>")
    @require_tier(TIER_ENT)
    def api_get_compliance_report(rid):
        conn = get_db()
        row = conn.execute(
            "SELECT id, template, title, date_from, date_to, status, "
            "html_content, summary, generated_at, created_at "
            "FROM compliance_reports WHERE id = ?", (rid,)
        ).fetchone()
        conn.close()
        if not row:
            return jsonify({"error": True, "message": "Not found."}), 404

        return jsonify({
            "id": row[0], "template": row[1], "title": row[2],
            "date_from": row[3], "date_to": row[4],
            "status": row[5], "html_content": row[6],
            "summary": row[7], "generated_at": row[8],
            "created_at": row[9],
        })

    @app.route("/api/compliance/reports/<int:rid>/html")
    @require_tier(TIER_ENT)
    def api_compliance_report_html(rid):
        conn = get_db()
        row = conn.execute(
            "SELECT html_content, status FROM compliance_reports WHERE id = ?",
            (rid,)
        ).fetchone()
        conn.close()
        if not row or not row[0]:
            return "<html><body><h1>Report not found or not generated yet."  \
                   "</h1></body></html>", 404
        from flask import Response
        return Response(row[0], mimetype="text/html")

    @app.route("/api/compliance/reports/<int:rid>", methods=["DELETE"])
    @require_tier(TIER_ENT)
    def api_delete_compliance_report(rid):
        conn = get_db()
        conn.execute("DELETE FROM compliance_reports WHERE id = ?", (rid,))
        conn.commit()
        conn.close()
        return jsonify({"status": "deleted"})

    # ---- Phase 5: Notification Channel endpoints ----
    @app.route("/api/notifications/channels")
    @require_tier(TIER_PRO)
    def api_notification_channels():
        conn = get_db()
        rows = conn.execute(
            "SELECT * FROM notification_channels ORDER BY id"
        ).fetchall()
        conn.close()
        result = []
        for r in rows:
            d = dict(r)
            try:
                cfg = json_mod.loads(d.get("config", "{}"))
                # Mask passwords
                if "password" in cfg:
                    cfg["password"] = "***" if cfg["password"] else ""
                d["config_display"] = cfg
            except Exception:
                d["config_display"] = {}
            result.append(d)
        return jsonify({"channels": result})

    @app.route("/api/notifications/channels", methods=["POST"])
    @require_tier(TIER_PRO)
    def api_create_notification_channel():
        data = request.get_json(force=True)
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        name = data.get("name", "Untitled")
        ch_type = data.get("channel_type", "email")
        config = json_mod.dumps(data.get("config", {}))
        conn = get_db()
        conn.execute(
            "INSERT INTO notification_channels "
            "(name, channel_type, config, enabled, created_at) "
            "VALUES (?, ?, ?, 1, ?)",
            (name, ch_type, config, now)
        )
        conn.commit()
        cid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.close()
        return jsonify({"status": "created", "id": cid})

    @app.route("/api/notifications/channels/<int:cid>", methods=["PUT"])
    @require_tier(TIER_PRO)
    def api_update_notification_channel(cid):
        data = request.get_json(force=True)
        conn = get_db()
        row = conn.execute(
            "SELECT * FROM notification_channels WHERE id = ?", (cid,)
        ).fetchone()
        if not row:
            conn.close()
            return jsonify({"error": "not_found"}), 404
        name = data.get("name", row["name"])
        ch_type = data.get("channel_type", row["channel_type"])
        enabled = data.get("enabled", row["enabled"])
        if "config" in data:
            config = json_mod.dumps(data["config"])
        else:
            config = row["config"]
        conn.execute(
            "UPDATE notification_channels SET name=?, channel_type=?, "
            "config=?, enabled=? WHERE id=?",
            (name, ch_type, config, int(enabled), cid)
        )
        conn.commit()
        conn.close()
        return jsonify({"status": "updated"})

    @app.route("/api/notifications/channels/<int:cid>", methods=["DELETE"])
    @require_tier(TIER_PRO)
    def api_delete_notification_channel(cid):
        conn = get_db()
        conn.execute("DELETE FROM notification_channels WHERE id = ?", (cid,))
        conn.commit()
        conn.close()
        return jsonify({"status": "deleted"})

    @app.route("/api/notifications/channels/<int:cid>/test", methods=["POST"])
    @require_tier(TIER_PRO)
    def api_test_notification_channel(cid):
        conn = get_db()
        row = conn.execute(
            "SELECT * FROM notification_channels WHERE id = ?", (cid,)
        ).fetchone()
        conn.close()
        if not row:
            return jsonify({"error": "not_found"}), 404
        try:
            cfg = json_mod.loads(row["config"]) if row["config"] else {}
        except Exception:
            cfg = {}
        if row["channel_type"] == "email":
            recipients = cfg.get("recipients", [])
            if not recipients:
                with _config_lock:
                    recipients = _config.get("alerting", {}).get(
                        "email", {}).get("recipients", [])
            if not recipients:
                return jsonify({"status": "error",
                                "message": "No recipients configured"})
            with _config_lock:
                ecfg = _config.get("alerting", {}).get("email", {})
            ok, err = _send_email(
                cfg.get("smtp_host", ecfg.get("smtp_host", "")),
                cfg.get("smtp_port", ecfg.get("smtp_port", 587)),
                cfg.get("use_tls", ecfg.get("use_tls", True)),
                cfg.get("username", ecfg.get("username", "")),
                cfg.get("password", ecfg.get("password", "")),
                cfg.get("from_addr", ecfg.get("from_addr", "")),
                recipients,
                "[SentryLog] Test Notification",
                "<h2>Test notification from SentryLog</h2>"
                "<p>If you see this, email notifications are working.</p>"
            )
            if ok:
                return jsonify({"status": "ok", "message": "Test email sent"})
            return jsonify({"status": "error", "message": err})
        elif row["channel_type"] == "webhook":
            url = cfg.get("url", "")
            if not url:
                return jsonify({"status": "error", "message": "No webhook URL"})
            ok, err = _send_webhook(url, {
                "product": "SentryLog", "event": "test",
                "message": "Test notification from SentryLog"
            })
            if ok:
                return jsonify({"status": "ok", "message": "Test webhook sent"})
            return jsonify({"status": "error", "message": err})
        return jsonify({"status": "error", "message": "Unknown channel type"})

    @app.route("/api/notifications/log")
    @require_tier(TIER_PRO)
    def api_notification_log():
        limit = request.args.get("limit", 50, type=int)
        conn = get_db()
        rows = conn.execute(
            "SELECT * FROM notification_log ORDER BY sent_at DESC LIMIT ?",
            (min(limit, 500),)
        ).fetchall()
        conn.close()
        return jsonify({"log": [dict(r) for r in rows]})

    # ---- Phase 5: Scheduled Reports endpoints ----
    @app.route("/api/scheduled-reports")
    @require_tier(TIER_ENT)
    def api_scheduled_reports():
        conn = get_db()
        rows = conn.execute(
            "SELECT * FROM scheduled_reports ORDER BY id"
        ).fetchall()
        conn.close()
        return jsonify({"reports": [dict(r) for r in rows]})

    @app.route("/api/scheduled-reports", methods=["POST"])
    @require_tier(TIER_ENT)
    def api_create_scheduled_report():
        data = request.get_json(force=True)
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        name = data.get("name", "Untitled Schedule")
        template = data.get("template", "custom")
        schedule = data.get("schedule", "weekly")
        recipients = json_mod.dumps(data.get("recipients", []))
        params = json_mod.dumps(data.get("parameters", {}))
        next_run = _compute_next_run(schedule)
        conn = get_db()
        conn.execute(
            "INSERT INTO scheduled_reports "
            "(name, template, schedule, recipients, parameters, "
            " enabled, next_run, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)",
            (name, template, schedule, recipients, params, next_run, now, now)
        )
        conn.commit()
        rid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.close()
        return jsonify({"status": "created", "id": rid, "next_run": next_run})

    @app.route("/api/scheduled-reports/<int:sid>", methods=["PUT"])
    @require_tier(TIER_ENT)
    def api_update_scheduled_report(sid):
        data = request.get_json(force=True)
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = get_db()
        row = conn.execute(
            "SELECT * FROM scheduled_reports WHERE id = ?", (sid,)
        ).fetchone()
        if not row:
            conn.close()
            return jsonify({"error": "not_found"}), 404
        name = data.get("name", row["name"])
        template = data.get("template", row["template"])
        schedule = data.get("schedule", row["schedule"])
        enabled = data.get("enabled", row["enabled"])
        if "recipients" in data:
            recipients = json_mod.dumps(data["recipients"])
        else:
            recipients = row["recipients"]
        if "parameters" in data:
            params = json_mod.dumps(data["parameters"])
        else:
            params = row["parameters"]
        next_run = _compute_next_run(schedule) if schedule != row["schedule"] else row["next_run"]
        conn.execute(
            "UPDATE scheduled_reports SET name=?, template=?, schedule=?, "
            "recipients=?, parameters=?, enabled=?, next_run=?, updated_at=? "
            "WHERE id=?",
            (name, template, schedule, recipients, params, int(enabled),
             next_run, now, sid)
        )
        conn.commit()
        conn.close()
        return jsonify({"status": "updated"})

    @app.route("/api/scheduled-reports/<int:sid>", methods=["DELETE"])
    @require_tier(TIER_ENT)
    def api_delete_scheduled_report(sid):
        conn = get_db()
        conn.execute("DELETE FROM scheduled_reports WHERE id = ?", (sid,))
        conn.commit()
        conn.close()
        return jsonify({"status": "deleted"})

    # ---- Phase 5: Log Export endpoint ----
    @app.route("/api/logs/export")
    @require_tier(TIER_PRO)
    def api_logs_export():
        """Export filtered logs as CSV or JSON."""
        fmt = request.args.get("format", "csv")
        severity = request.args.get("severity", "")
        source = request.args.get("source", "")
        search = request.args.get("search", "")
        hours = request.args.get("hours", 24, type=int)
        limit = request.args.get("limit", 10000, type=int)

        cutoff = (
            datetime.datetime.now() - datetime.timedelta(hours=hours)
        ).strftime("%Y-%m-%d %H:%M:%S")

        where = ["received_at >= ?"]
        params = [cutoff]
        if severity:
            sevs = [s.strip().lower() for s in severity.split(",")]
            ph = ",".join(["?"] * len(sevs))
            where.append("severity IN (%s)" % ph)
            params.extend(sevs)
        if source:
            where.append("(source_ip = ? OR source_name = ?)")
            params.extend([source, source])
        if search:
            where.append("(message LIKE ? OR app_name LIKE ?)")
            like = "%" + search + "%"
            params.extend([like, like])

        conn = get_db()
        rows = conn.execute(
            "SELECT timestamp, source_ip, source_name, severity, facility, "
            "app_name, process_id, message FROM logs WHERE %s "
            "ORDER BY timestamp DESC LIMIT ?"
            % " AND ".join(where),
            params + [min(limit, 50000)]
        ).fetchall()
        conn.close()

        if fmt == "json":
            data = json_mod.dumps([dict(r) for r in rows], indent=2)
            return Response(
                data, mimetype="application/json",
                headers={"Content-Disposition": "attachment; filename=sentrylog_export.json"}
            )
        else:
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["timestamp", "source_ip", "source_name",
                             "severity", "facility", "app_name",
                             "process_id", "message"])
            for r in rows:
                writer.writerow([r["timestamp"], r["source_ip"],
                                 r["source_name"], r["severity"],
                                 r["facility"], r["app_name"],
                                 r["process_id"], r["message"]])
            csv_data = output.getvalue()
            return Response(
                csv_data, mimetype="text/csv",
                headers={"Content-Disposition": "attachment; filename=sentrylog_export.csv"}
            )

    # ---- Phase 6: File Target endpoints ----
    @app.route("/api/file-targets")
    @require_tier(TIER_PRO)
    def api_file_targets():
        conn = get_db()
        rows = conn.execute(
            "SELECT * FROM file_targets ORDER BY id"
        ).fetchall()
        conn.close()
        result = []
        for r in rows:
            d = dict(r)
            d["running"] = r["id"] in _file_tail_threads
            result.append(d)
        return jsonify({"targets": result})

    @app.route("/api/file-targets", methods=["POST"])
    @require_tier(TIER_PRO)
    def api_create_file_target():
        data = request.get_json(force=True)
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        fp = data.get("file_path", "")
        if not fp:
            return jsonify({"error": "file_path required"}), 400
        name = data.get("name", os.path.basename(fp))
        src = data.get("source_name", name)
        fmt = data.get("parse_format", "auto")
        fac = data.get("default_facility", "local0")
        sev = data.get("default_severity", "info")

        # Check tier limits
        features = get_tier_features()
        conn = get_db()
        count = conn.execute("SELECT COUNT(*) FROM file_targets").fetchone()[0]
        if count >= features.get("max_file_targets", 0):
            conn.close()
            return jsonify({"error": "limit_reached",
                            "message": "File target limit reached for your tier"}), 403

        conn.execute(
            "INSERT INTO file_targets "
            "(name, file_path, parse_format, source_name, default_facility, "
            " default_severity, enabled, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)",
            (name, fp, fmt, src, fac, sev, now, now)
        )
        conn.commit()
        tid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        target = conn.execute(
            "SELECT * FROM file_targets WHERE id = ?", (tid,)
        ).fetchone()
        conn.close()

        # Start tailing
        start_file_tail(dict(target))
        return jsonify({"status": "created", "id": tid})

    @app.route("/api/file-targets/<int:tid>", methods=["PUT"])
    @require_tier(TIER_PRO)
    def api_update_file_target(tid):
        data = request.get_json(force=True)
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = get_db()
        row = conn.execute(
            "SELECT * FROM file_targets WHERE id = ?", (tid,)
        ).fetchone()
        if not row:
            conn.close()
            return jsonify({"error": "not_found"}), 404
        name = data.get("name", row["name"])
        fp = data.get("file_path", row["file_path"])
        src = data.get("source_name", row["source_name"])
        fmt = data.get("parse_format", row["parse_format"])
        fac = data.get("default_facility", row["default_facility"])
        sev = data.get("default_severity", row["default_severity"])
        enabled = data.get("enabled", row["enabled"])
        conn.execute(
            "UPDATE file_targets SET name=?, file_path=?, source_name=?, "
            "parse_format=?, default_facility=?, default_severity=?, "
            "enabled=?, updated_at=? WHERE id=?",
            (name, fp, src, fmt, fac, sev, int(enabled), now, tid)
        )
        conn.commit()
        conn.close()

        # Restart if running
        stop_file_tail(tid)
        if enabled:
            target = {"id": tid, "file_path": fp, "source_name": src,
                       "default_facility": fac, "default_severity": sev}
            start_file_tail(target)
        return jsonify({"status": "updated"})

    @app.route("/api/file-targets/<int:tid>", methods=["DELETE"])
    @require_tier(TIER_PRO)
    def api_delete_file_target(tid):
        stop_file_tail(tid)
        conn = get_db()
        conn.execute("DELETE FROM file_targets WHERE id = ?", (tid,))
        conn.commit()
        conn.close()
        return jsonify({"status": "deleted"})

    # ---- Phase 6: Forwarding Target endpoints ----
    @app.route("/api/forwarding-targets")
    @require_tier(TIER_PRO)
    def api_forwarding_targets():
        conn = get_db()
        rows = conn.execute(
            "SELECT * FROM forwarding_targets ORDER BY id"
        ).fetchall()
        conn.close()
        return jsonify({"targets": [dict(r) for r in rows]})

    @app.route("/api/forwarding-targets", methods=["POST"])
    @require_tier(TIER_PRO)
    def api_create_forwarding_target():
        data = request.get_json(force=True)
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        name = data.get("name", "Untitled")
        ttype = data.get("target_type", "syslog")
        host = data.get("host", "")
        port = data.get("port", 514)
        protocol = data.get("protocol", "udp")
        wh_url = data.get("webhook_url", "")
        fsev = data.get("filter_severity", "")
        fsrc = data.get("filter_source", "")
        ffac = data.get("filter_facility", "")
        fmt = data.get("format", "rfc3164")

        features = get_tier_features()
        conn = get_db()
        count = conn.execute("SELECT COUNT(*) FROM forwarding_targets").fetchone()[0]
        if count >= features.get("max_forwarding_targets", 0):
            conn.close()
            return jsonify({"error": "limit_reached",
                            "message": "Forwarding target limit reached"}), 403

        conn.execute(
            "INSERT INTO forwarding_targets "
            "(name, target_type, host, port, protocol, webhook_url, "
            " filter_severity, filter_source, filter_facility, format, "
            " enabled, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)",
            (name, ttype, host, port, protocol, wh_url,
             fsev, fsrc, ffac, fmt, now, now)
        )
        conn.commit()
        fid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.close()
        return jsonify({"status": "created", "id": fid})

    @app.route("/api/forwarding-targets/<int:fid>", methods=["PUT"])
    @require_tier(TIER_PRO)
    def api_update_forwarding_target(fid):
        data = request.get_json(force=True)
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = get_db()
        row = conn.execute(
            "SELECT * FROM forwarding_targets WHERE id = ?", (fid,)
        ).fetchone()
        if not row:
            conn.close()
            return jsonify({"error": "not_found"}), 404
        fields = ["name", "target_type", "host", "port", "protocol",
                   "webhook_url", "filter_severity", "filter_source",
                   "filter_facility", "format", "enabled"]
        vals = []
        sets = []
        for f in fields:
            if f in data:
                sets.append("%s = ?" % f)
                vals.append(data[f] if f != "enabled" else int(data[f]))
            else:
                sets.append("%s = ?" % f)
                vals.append(row[f])
        sets.append("updated_at = ?")
        vals.append(now)
        vals.append(fid)
        conn.execute(
            "UPDATE forwarding_targets SET %s WHERE id = ?" % ", ".join(sets),
            vals
        )
        conn.commit()
        conn.close()
        # Clear cached socket
        with _forwarding_lock:
            sock = _forwarding_sockets.pop(fid, None)
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
        return jsonify({"status": "updated"})

    @app.route("/api/forwarding-targets/<int:fid>", methods=["DELETE"])
    @require_tier(TIER_PRO)
    def api_delete_forwarding_target(fid):
        conn = get_db()
        conn.execute("DELETE FROM forwarding_targets WHERE id = ?", (fid,))
        conn.commit()
        conn.close()
        with _forwarding_lock:
            sock = _forwarding_sockets.pop(fid, None)
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
        return jsonify({"status": "deleted"})

    # ---- Phase 6: API Key endpoints ----
    @app.route("/api/api-keys")
    @require_tier(TIER_PRO)
    def api_list_api_keys():
        conn = get_db()
        rows = conn.execute(
            "SELECT id, key_prefix, label, permissions, enabled, "
            "last_used, use_count, rate_limit, created_at, expires_at "
            "FROM api_keys ORDER BY id"
        ).fetchall()
        conn.close()
        return jsonify({"keys": [dict(r) for r in rows]})

    @app.route("/api/api-keys", methods=["POST"])
    @require_tier(TIER_PRO)
    def api_create_api_key():
        data = request.get_json(force=True)
        label = data.get("label", "Untitled Key")
        permissions = data.get("permissions", "read")
        rate_limit = data.get("rate_limit", 120)
        expires_days = data.get("expires_days", 0)

        raw_key, key_hash, prefix = generate_api_key()
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        expires = ""
        if expires_days > 0:
            exp_dt = datetime.datetime.now() + datetime.timedelta(days=expires_days)
            expires = exp_dt.strftime("%Y-%m-%d %H:%M:%S")

        conn = get_db()
        conn.execute(
            "INSERT INTO api_keys "
            "(key_hash, key_prefix, label, permissions, enabled, "
            " rate_limit, created_at, expires_at) "
            "VALUES (?, ?, ?, ?, 1, ?, ?, ?)",
            (key_hash, prefix, label, permissions, rate_limit, now, expires)
        )
        conn.commit()
        kid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.close()
        # Return the raw key ONCE -- it cannot be retrieved later
        return jsonify({
            "status": "created", "id": kid,
            "api_key": raw_key,
            "warning": "Save this key now. It cannot be retrieved again.",
        })

    @app.route("/api/api-keys/<int:kid>", methods=["PUT"])
    @require_tier(TIER_PRO)
    def api_update_api_key(kid):
        data = request.get_json(force=True)
        conn = get_db()
        row = conn.execute("SELECT * FROM api_keys WHERE id = ?", (kid,)).fetchone()
        if not row:
            conn.close()
            return jsonify({"error": "not_found"}), 404
        label = data.get("label", row["label"])
        permissions = data.get("permissions", row["permissions"])
        enabled = data.get("enabled", row["enabled"])
        rate_limit = data.get("rate_limit", row["rate_limit"])
        conn.execute(
            "UPDATE api_keys SET label=?, permissions=?, enabled=?, rate_limit=? "
            "WHERE id=?",
            (label, permissions, int(enabled), rate_limit, kid)
        )
        conn.commit()
        conn.close()
        return jsonify({"status": "updated"})

    @app.route("/api/api-keys/<int:kid>", methods=["DELETE"])
    @require_tier(TIER_PRO)
    def api_delete_api_key(kid):
        conn = get_db()
        conn.execute("DELETE FROM api_keys WHERE id = ?", (kid,))
        conn.commit()
        conn.close()
        return jsonify({"status": "deleted"})

    # ---- Test / Utility ----
    @app.route("/api/test-log", methods=["POST"])
    def api_test_log():
        """Inject a test log entry (useful for testing without real syslog sources)."""
        data = request.get_json(force=True)
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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
    if HAS_WIN32:
        print("  [OK] pywin32 detected -- local Windows Event Log enabled")
    else:
        print("  [--] pywin32 not found -- local Windows Event Log disabled")
        print("       Install: pip install pywin32")
    if HAS_WINRM:
        print("  [OK] pywinrm detected -- remote Windows Event Log enabled")
    else:
        print("  [--] pywinrm not found -- remote Windows Event Log disabled")
        print("       Install: pip install pywinrm")
    if HAS_REQUESTS:
        print("  [OK] requests detected -- security API connectors enabled")
    else:
        print("  [--] requests not found -- security API connectors disabled")
        print("       Install: pip install requests")
    print("  [OK] Email notifications (SMTP) available")
    print("  [OK] Log file tailing (Linux/Mac) available")
    print("  [OK] Log forwarding to external SIEM available")
    print("  [OK] API key authentication available")
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

    # Start Windows Event Log collectors (Phase 2)
    _start_all_winlog_collectors()

    # Start Security API connectors (Phase 3)
    _start_all_security_connectors()

    # Start Correlation Engine (Phase 4)
    corr_thread = threading.Thread(target=_correlation_loop, daemon=True)
    corr_thread.start()
    log.info("Correlation engine started (30s check interval)")

    # Start Scheduled Report Engine (Phase 5)
    sched_thread = threading.Thread(target=_scheduled_report_loop, daemon=True)
    sched_thread.start()
    log.info("Scheduled report engine started (60s check interval)")

    # Start Log File Tailers (Phase 6)
    _start_all_file_tails()

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
    _stop_event.set()
    # Stop all file tailers
    for tid in list(_file_tail_stops.keys()):
        stop_file_tail(tid)
    log.info("SentryLog shutting down...")


if __name__ == "__main__":
    main()
