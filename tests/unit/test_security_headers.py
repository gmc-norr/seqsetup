"""Tests for the security-headers middleware.

Focus on the pure header-setting logic — it's small enough that a unit test
against a Response object covers the behaviour without spinning up an app.
"""

from starlette.responses import PlainTextResponse

from seqsetup.security_headers import apply_security_headers


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
