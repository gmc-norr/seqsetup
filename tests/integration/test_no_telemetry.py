"""SeqSetup sends no telemetry (group 3b). FastAPI 0.142 sets up OpenTelemetry
export by itself when OTEL_EXPORTER_OTLP_* settings are present; both FastAPI
apps turn that off, so requests take the same path as before FastAPI 0.142
and nothing about them leaves the server."""

import logging

from starlette.testclient import TestClient


class TestNoTelemetry:
    """The main app, and the JSON API mounted at /api."""

    def test_otel_settings_set_up_no_export(self, fresh_app, monkeypatch, caplog):
        app, _ctx, _db = fresh_app
        monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
        with caplog.at_level(logging.DEBUG):
            with TestClient(app, base_url="http://testserver") as client:
                assert client.get("/login").status_code == 200
        assert "OpenTelemetry" not in caplog.text

    def test_the_api_app_has_telemetry_off(self, fresh_app):
        app, _ctx, _db = fresh_app
        api = next(route.app for route in app.routes if getattr(route, "path", "") == "/api")
        config = api._telemetry  # FastAPI keeps FastAPI(telemetry=...) here
        assert not any(config[key] for key in
                       ("tracing", "metrics", "logs", "operation_spans", "auto_configure"))
