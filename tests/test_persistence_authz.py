"""Docker persistence contract, secrets, password storage and authorization."""
import sqlite3
from pathlib import Path

import pytest

from conftest import load_sentrylog, DEFAULT_CONFIG, make_entry

REPO_ROOT = Path(__file__).resolve().parent.parent


# --- persistence -----------------------------------------------------------

def test_env_vars_decide_paths(sentrylog, data_dir):
    assert sentrylog.DB_PATH == data_dir / "sentrylog.db"
    assert sentrylog.DEFAULT_CFG == data_dir / "sentrylog_config.yaml"
    assert sentrylog.BACKUP_DIR == data_dir / "backups"
    assert sentrylog.SPOOL_DIR == data_dir / "spool"
    assert not (sentrylog.BASE_DIR / "sentrylog.db").exists()


def test_state_survives_container_replacement(tmp_path):
    volume = tmp_path / "volume"
    volume.mkdir()
    (volume / "sentrylog_config.yaml").write_text(DEFAULT_CONFIG, encoding="utf-8")

    first = load_sentrylog(volume)
    first.load_config()
    first.init_db()
    first.ingest_log(make_entry("before replacement"))
    assert first._flush_logs() is True
    cfg = dict(first._config)
    cfg["storage"]["retention_days"] = 7
    first.save_config(cfg)

    second = load_sentrylog(volume)
    second.load_config()
    second.init_db()
    rows = sqlite3.connect(str(second.DB_PATH)).execute(
        "SELECT COUNT(*) FROM logs").fetchone()[0]
    assert rows == 1, "logs did not survive container replacement"
    assert second._config["storage"]["retention_days"] == 7


def test_backup_and_spool_dirs_live_in_the_volume(sentrylog, data_dir):
    assert (data_dir / "backups").is_dir()
    assert (data_dir / "spool").is_dir()


def test_dockerfile_matches_the_code_contract():
    text = REPO_ROOT.joinpath("Dockerfile").read_text(encoding="utf-8")
    assert "ENV SENTRYLOG_DATA_DIR=/app/data" in text
    assert "ENV SENTRYLOG_CONFIG=/app/data/sentrylog_config.yaml" in text
    assert "ENV SENTRYLOG_DB_PATH=/app/data/sentrylog.db" in text
    assert 'VOLUME ["/app/data"]' in text


# --- secrets & passwords ---------------------------------------------------

def test_secret_is_per_installation(sentrylog, data_dir):
    assert (data_dir / "auth_secret.key").exists()
    assert b"sentrylog-user-auth" not in sentrylog._USER_AUTH_SECRET


def test_no_hardcoded_user_secret_in_source():
    src = REPO_ROOT.joinpath("sentrylog.py").read_text(encoding="utf-8")
    assert 'b"sentrylog-user-auth-2026"' not in src


def test_hash_and_verify(sentrylog):
    stored = sentrylog.hash_password("a good password")
    assert stored.startswith("pbkdf2_sha256$")
    assert sentrylog.verify_password("a good password", stored)
    assert not sentrylog.verify_password("nope", stored)
    assert not sentrylog.verify_password("changeme", "changeme")


def test_plaintext_config_is_migrated(sentrylog, data_dir):
    cfg = dict(sentrylog._config)
    cfg["users"] = [{"username": "admin", "password": "changeme", "role": "admin"}]
    sentrylog.save_config(cfg)
    sentrylog.load_config()
    on_disk = (data_dir / "sentrylog_config.yaml").read_text(encoding="utf-8")
    assert "changeme" not in on_disk
    assert "pbkdf2_sha256" in on_disk


# --- authorization ---------------------------------------------------------

def enable_auth(sentrylog, users):
    cfg = dict(sentrylog._config)
    cfg["users"] = [{"username": u, "password_hash": sentrylog.hash_password(p),
                     "role": r} for u, p, r in users]
    cfg["auth_enabled"] = True
    sentrylog.save_config(cfg)
    sentrylog.load_config()


def login(client, username, password):
    resp = client.post("/api/auth/login",
                       json={"username": username, "password": password})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    return resp.get_json()["token"]


def auth(token):
    return {"Authorization": "Bearer %s" % token}


@pytest.mark.parametrize("path", ["/api/config", "/api/stats", "/api/users",
                                  "/api/ingest-health"])
def test_protected_routes_require_a_token(client, sentrylog, path):
    enable_auth(sentrylog, [("admin", "adminpassword", "admin")])
    assert client.get(path).status_code == 401


def test_config_routes_are_no_longer_open(client, sentrylog):
    enable_auth(sentrylog, [("v", "viewerpassword", "viewer")])
    token = login(client, "v", "viewerpassword")
    assert client.get("/api/config", headers=auth(token)).status_code == 403
    assert client.put("/api/config", json={"auth_enabled": False},
                      headers=auth(token)).status_code == 403
    sentrylog.load_config()
    assert sentrylog._config["auth_enabled"] is True


def test_every_route_has_a_permission_or_is_exempt(sentrylog):
    ungated = []
    for rule in sentrylog.app.url_map.iter_rules():
        endpoint = rule.endpoint
        if endpoint in sentrylog._AUTH_EXEMPT_ENDPOINTS:
            continue
        if endpoint in sentrylog._SELF_AUTHENTICATED_ENDPOINTS:
            continue
        if sentrylog._required_perm_for(endpoint, "GET") not in (
                "read", "write", "config", "users"):
            ungated.append(endpoint)
    assert not ungated, "routes without a permission: %s" % ungated


def test_token_is_invalidated_when_role_changes(client, sentrylog):
    enable_auth(sentrylog, [("admin", "adminpassword", "admin"),
                            ("op", "operatorpass", "operator")])
    op_token = login(client, "op", "operatorpass")
    admin_token = login(client, "admin", "adminpassword")
    assert client.get("/api/stats", headers=auth(op_token)).status_code == 200
    client.put("/api/users/op", json={"role": "viewer"}, headers=auth(admin_token))
    sentrylog.load_config()
    assert client.get("/api/stats", headers=auth(op_token)).status_code == 401


def test_forged_token_with_the_old_public_secret_is_rejected(client, sentrylog):
    import base64
    import hashlib
    import hmac
    import time
    enable_auth(sentrylog, [("admin", "adminpassword", "admin")])
    payload = "admin:admin:%d:deadbeefcafe" % (int(time.time()) + 3600)
    sig = hmac.new(b"sentrylog-user-auth-2026", payload.encode(),
                   hashlib.sha256).hexdigest()[:32]
    forged = base64.urlsafe_b64encode(("%s:%s" % (payload, sig)).encode()).decode()
    assert client.get("/api/stats", headers=auth(forged)).status_code == 401


def test_auth_on_with_no_users_fails_closed(client, sentrylog):
    cfg = dict(sentrylog._config)
    cfg["auth_enabled"] = True
    cfg["users"] = []
    sentrylog.save_config(cfg)
    sentrylog.load_config()
    assert client.get("/api/stats").status_code == 401


def test_enabling_auth_without_an_admin_is_refused(client):
    resp = client.put("/api/config", json={"auth_enabled": True})
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "no_admin_user"


def test_last_admin_cannot_be_deleted_while_auth_is_on(client, sentrylog):
    enable_auth(sentrylog, [("admin", "adminpassword", "admin")])
    token = login(client, "admin", "adminpassword")
    assert client.delete("/api/users/admin",
                         headers=auth(token)).status_code == 409


def test_config_endpoint_redacts_credentials(client):
    body = client.get("/api/config").get_json()
    assert body["netmon_integration"]["api_key"] == "__set__"
    assert "netmon-secret-key" not in str(body)


def test_redaction_placeholder_is_not_written_back(client, sentrylog):
    body = client.get("/api/config").get_json()
    client.put("/api/config", json={"netmon_integration": body["netmon_integration"]})
    sentrylog.load_config()
    assert sentrylog._config["netmon_integration"]["api_key"] == "netmon-secret-key"


def test_webhook_ingestion_stays_reachable_for_shippers(client, sentrylog):
    """The webhook endpoint authenticates with its own token, so it stays open."""
    enable_auth(sentrylog, [("admin", "adminpassword", "admin")])
    resp = client.post("/api/security/webhook/not-a-real-token", json={})
    assert resp.status_code == 403  # rejected by token check, not by 401
