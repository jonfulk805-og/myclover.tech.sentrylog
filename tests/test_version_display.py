"""The dashboard must show the running VERSION, not a hard-coded string."""
import sentrylog


def test_dashboard_template_renders_running_version():
    app = sentrylog.Flask(__name__, template_folder="../templates")
    with app.test_request_context("/"):
        html = sentrylog.render_template("sentrylog.html", version=sentrylog.VERSION)
    assert "SentryLog v%s |" % sentrylog.VERSION in html
    assert "v4.0.0" not in html
