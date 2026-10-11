"""Tests for the security-headers middleware.

Focus on the pure header-setting logic — it's small enough that a unit test
against a Response object covers the behaviour without spinning up an app.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest
from starlette.responses import PlainTextResponse

from seqsetup.security_headers import apply_security_headers, https_only_from_env


class TestApplySecurityHeaders:
    """Pure unit tests for apply_security_headers()."""

    def _fresh_response(self) -> PlainTextResponse:
        return PlainTextResponse("body")

    def test_baseline_headers_present(self):
        response = self._fresh_response()
        apply_security_headers(response, is_https=False)
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert response.headers["Referrer-Policy"] == "same-origin"
        assert response.headers["Cross-Origin-Opener-Policy"] == "same-origin"
        assert response.headers["Cross-Origin-Resource-Policy"] == "same-origin"

    def test_hsts_only_on_https(self):
        """HSTS over plaintext is meaningless; only emit it on TLS responses."""
        plain = self._fresh_response()
        apply_security_headers(plain, is_https=False)
        assert "Strict-Transport-Security" not in plain.headers

        tls = self._fresh_response()
        apply_security_headers(tls, is_https=True)
        assert "Strict-Transport-Security" in tls.headers
        assert "max-age" in tls.headers["Strict-Transport-Security"]
        assert "includeSubDomains" in tls.headers["Strict-Transport-Security"]

    def test_does_not_clobber_pre_existing_header(self):
        """If a handler set a header deliberately, the middleware leaves it alone."""
        response = self._fresh_response()
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        apply_security_headers(response, is_https=False)
        assert response.headers["X-Frame-Options"] == "SAMEORIGIN"


class TestMiddlewareIntegration:
    """Smoke-test the ASGI middleware against a minimal Starlette app."""

    def test_headers_applied_to_real_response(self):
        from starlette.applications import Starlette
        from starlette.routing import Route
        from starlette.testclient import TestClient

        from seqsetup.security_headers import SecurityHeadersMiddleware

        async def homepage(request):
            return PlainTextResponse("hello")

        app = Starlette(routes=[Route("/", homepage)])
        app.add_middleware(SecurityHeadersMiddleware)

        client = TestClient(app)
        response = client.get("/")

        assert response.status_code == 200
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        # TestClient defaults to http:// so HSTS should NOT be set
        assert "Strict-Transport-Security" not in response.headers

    def test_hsts_applied_when_https_scheme(self):
        from starlette.applications import Starlette
        from starlette.routing import Route
        from starlette.testclient import TestClient

        from seqsetup.security_headers import SecurityHeadersMiddleware

        async def homepage(request):
            return PlainTextResponse("hello")

        app = Starlette(routes=[Route("/", homepage)])
        app.add_middleware(SecurityHeadersMiddleware)

        client = TestClient(app, base_url="https://test")
        response = client.get("/")

        assert response.status_code == 200
        assert "Strict-Transport-Security" in response.headers


_UNKNOWN_VALUE_MESSAGE = (
    "SEQSETUP_HTTPS_ONLY={!r} is not a known value. Set it to 1 (or true, yes) when users "
    "reach SeqSetup over HTTPS, or to 0 (or false, no) when they do not."
)


class TestHttpsOnlySetting:
    """SEQSETUP_HTTPS_ONLY is read strictly: a typo must not quietly mean off."""

    @pytest.mark.parametrize("value", ["1", "TRUE", "yes"])
    def test_an_on_value_reads_as_on(self, monkeypatch, value):
        monkeypatch.setenv("SEQSETUP_HTTPS_ONLY", value)
        assert https_only_from_env() is True

    @pytest.mark.parametrize("value", ["", "0", "false", "No"])
    def test_an_off_value_reads_as_off(self, monkeypatch, value):
        monkeypatch.setenv("SEQSETUP_HTTPS_ONLY", value)
        assert https_only_from_env() is False

    def test_unset_reads_as_off(self, monkeypatch):
        monkeypatch.delenv("SEQSETUP_HTTPS_ONLY", raising=False)
        assert https_only_from_env() is False

    @pytest.mark.parametrize("value", ["on", "enabled", " 1", "2"])
    def test_an_unknown_value_is_refused(self, monkeypatch, value):
        monkeypatch.setenv("SEQSETUP_HTTPS_ONLY", value)
        with pytest.raises(RuntimeError) as refused:
            https_only_from_env()
        assert str(refused.value) == _UNKNOWN_VALUE_MESSAGE.format(value)


class TestTheAppChecksHttpsOnlyFirst:
    """A value the app does not know stops it at start, before the database."""

    def test_an_unknown_value_stops_the_app(self, tmp_path):
        src = Path(__file__).resolve().parents[2] / "src"
        # An address nothing listens on: if the check came after the database,
        # the app must not reach a real one. A secret, so nothing writes a key file.
        env = {**os.environ, "SEQSETUP_HTTPS_ONLY": "on", "PYTHONPATH": str(src),
               "MONGODB_URI": "mongodb://127.0.0.1:1", "SEQSETUP_SESSION_SECRET": "x" * 64}
        proc = subprocess.run([sys.executable, "-c", "import seqsetup.app"], env=env, cwd=tmp_path,
                              capture_output=True, text=True, timeout=300)
        assert proc.returncode != 0
        assert _UNKNOWN_VALUE_MESSAGE.format("on") in proc.stderr
