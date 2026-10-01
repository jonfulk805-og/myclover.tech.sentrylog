"""The dashboard must show the running VERSION, not a hard-coded string."""


def test_dashboard_template_renders_running_version(sentrylog):
    # Use the fixture, never a bare `import sentrylog`: importing without the
    # SENTRYLOG_* env vars writes auth_secret.key into the repo folder (that is
    # how a signing secret got committed in 5d57551).
    app = sentrylog.Flask(__name__, template_folder="../templates")
    with app.test_request_context("/"):
        html = sentrylog.render_template("sentrylog.html", version=sentrylog.VERSION)
    assert "SentryLog v%s |" % sentrylog.VERSION in html
    assert "v4.0.0" not in html
