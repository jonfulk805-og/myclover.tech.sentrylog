"""Test fixtures for SentryLog.

sentrylog.py resolves its data paths at import time (exactly like the Docker
image does), so the SENTRYLOG_* variables are set before the import.
"""
import importlib
import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_CONFIG = """\
license_key: ''
auth_enabled: false
users: []
syslog:
  udp_port: 5514
  tcp_port: 5514
  udp_enabled: false
  tcp_enabled: false
  buffer_size: 8192
storage:
  retention_days: 30
  cleanup_interval_hours: 6
  max_db_size_mb: 0
  min_retention_hours: 0
dashboard:
  host: 127.0.0.1
  port: 8514
netmon_integration:
  enabled: false
  netmon_url: http://localhost:8080
  api_key: netmon-secret-key
"""


def load_sentrylog(data_dir):
    os.environ["SENTRYLOG_DATA_DIR"] = str(data_dir)
    os.environ["SENTRYLOG_DB_PATH"] = str(Path(data_dir) / "sentrylog.db")
    os.environ["SENTRYLOG_CONFIG"] = str(Path(data_dir) / "sentrylog_config.yaml")
    os.environ["SENTRYLOG_BACKUP_DIR"] = str(Path(data_dir) / "backups")
    os.environ["SENTRYLOG_SPOOL_DIR"] = str(Path(data_dir) / "spool")
    os.environ["SENTRYLOG_SECRET_FILE"] = str(Path(data_dir) / "auth_secret.key")
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    sys.modules.pop("sentrylog", None)
    return importlib.import_module("sentrylog")


@pytest.fixture()
def data_dir(tmp_path):
    d = tmp_path / "data"
    d.mkdir()
    (d / "sentrylog_config.yaml").write_text(DEFAULT_CONFIG, encoding="utf-8")
    return d


@pytest.fixture()
def sentrylog(data_dir):
    mod = load_sentrylog(data_dir)
    mod.load_config()
    mod.init_db()
    return mod


@pytest.fixture()
def client(sentrylog):
    sentrylog.app.config["TESTING"] = True
    return sentrylog.app.test_client()


def make_entry(message="hello", source_ip="10.0.0.9", severity="info"):
    import datetime
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return {
        "timestamp": now, "received_at": now, "source_ip": source_ip,
        "source_name": "host1", "facility": "user", "facility_code": 1,
        "severity": severity, "severity_code": 6, "app_name": "app",
        "process_id": "1", "message": message, "raw": message,
    }
