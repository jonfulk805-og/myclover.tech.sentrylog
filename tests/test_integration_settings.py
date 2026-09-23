"""NetMon integration can be configured and tested from the Settings page."""


def _set_integration(client, **values):
    return client.put("/api/config", json={"netmon_integration": values})


def test_token_saved_from_settings_is_never_echoed_back(client, sentrylog):
    assert _set_integration(client, enabled=True, netmon_url="http://nas:8080",
                            read_token="s3cret-token-value",
                            verify_tls=False).status_code == 200
    cfg = sentrylog._config["netmon_integration"]
    assert cfg["read_token"] == "s3cret-token-value"
    assert cfg["verify_tls"] is False
    body = client.get("/api/config").get_json()["netmon_integration"]
    assert body["read_token"] == "__set__"
    assert "s3cret" not in str(body)


def test_saving_other_fields_keeps_the_existing_token(client, sentrylog):
    _set_integration(client, read_token="keep-me-please")
    # The UI omits read_token when the field is left blank.
    _set_integration(client, enabled=True, netmon_url="http://other:8080")
    assert sentrylog._config["netmon_integration"]["read_token"] == "keep-me-please"


def test_connection_test_reports_success(client, sentrylog, monkeypatch):
    monkeypatch.setattr(sentrylog, "fetch_netmon_feed", lambda **kw: {
        "events": [{"x": 1}, {"x": 2}], "error": "", "truncated": False,
        "device_hosts": {}})
    body = client.post("/api/config/netmon-test").get_json()
    assert body == {"ok": True, "events": 2}


def test_connection_test_surfaces_the_error(client, sentrylog):
    # Integration is disabled by default, so the real fetch reports why.
    body = client.post("/api/config/netmon-test").get_json()
    assert body["ok"] is False
    assert "disabled" in body["error"]


def test_connection_test_requires_config_permission(sentrylog):
    assert sentrylog._required_perm_for("api_config_netmon_test", "POST") == "config"
