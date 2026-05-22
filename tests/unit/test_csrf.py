"""Tests for the CSRF Origin/Host check middleware."""

from seqsetup.csrf import check_origin_against_host


class TestCheckOriginAgainstHost:
    """Pure unit tests for the core decision function."""

    def test_get_request_always_allowed(self):
        ok, _ = check_origin_against_host(
            method="GET",
            path="/runs",
            origin_header="",
            host_header="seqsetup.example.com",
            request_scheme="https",
            trusted_origins=set(),
        )
        assert ok is True

    def test_post_with_matching_origin_allowed(self):
        ok, _ = check_origin_against_host(
            method="POST",
            path="/runs/abc/samples",
            origin_header="https://seqsetup.example.com",
            host_header="seqsetup.example.com",
            request_scheme="https",
            trusted_origins=set(),
        )
        assert ok is True

    def test_post_with_cross_origin_rejected(self):
        ok, reason = check_origin_against_host(
            method="POST",
            path="/runs/abc/samples",
            origin_header="https://attacker.example.org",
            host_header="seqsetup.example.com",
            request_scheme="https",
            trusted_origins=set(),
        )
        assert ok is False
        assert "does not match Host" in reason

    def test_post_with_no_origin_rejected(self):
        """Browsers normally send Origin on POST. Reject if missing — a
        request that omits Origin to evade the check is itself suspect."""
        ok, reason = check_origin_against_host(
            method="POST",
            path="/runs/abc/samples",
            origin_header="",
            host_header="seqsetup.example.com",
            request_scheme="https",
            trusted_origins=set(),
        )
        assert ok is False
        assert "Missing Origin" in reason

    def test_api_routes_exempt(self):
        """Bearer-token API surface isn't cookie-driven; non-browser clients
        legitimately omit Origin."""
        ok, _ = check_origin_against_host(
            method="POST",
            path="/api/runs/abc/import",
            origin_header="",
            host_header="seqsetup.example.com",
            request_scheme="https",
            trusted_origins=set(),
        )
        assert ok is True

    def test_trusted_origin_allowed(self):
        ok, _ = check_origin_against_host(
            method="POST",
            path="/runs/abc/samples",
            origin_header="https://lb-frontend.example.com",
            host_header="seqsetup-internal.example.com",  # different from origin
            request_scheme="https",
            trusted_origins={"https://lb-frontend.example.com"},
        )
        assert ok is True

    def test_default_port_normalised(self):
        """Browsers omit :443 from Origin when scheme is https; Host headers
        often include the port. Comparison must normalise."""
        ok, _ = check_origin_against_host(
            method="POST",
            path="/runs/abc/samples",
            origin_header="https://seqsetup.example.com",  # no port
            host_header="seqsetup.example.com:443",          # explicit default port
            request_scheme="https",
            trusted_origins=set(),
        )
        assert ok is True

    def test_non_default_port_must_match(self):
        ok, _ = check_origin_against_host(
            method="POST",
            path="/runs/abc/samples",
            origin_header="https://seqsetup.example.com:8443",
            host_header="seqsetup.example.com:8443",
            request_scheme="https",
            trusted_origins=set(),
        )
        assert ok is True

        bad, _ = check_origin_against_host(
            method="POST",
            path="/runs/abc/samples",
            origin_header="https://seqsetup.example.com:9443",  # wrong port
            host_header="seqsetup.example.com:8443",
            request_scheme="https",
            trusted_origins=set(),
        )
        assert bad is False

    def test_state_changing_methods_all_covered(self):
        """POST/PUT/PATCH/DELETE must all be checked, GET/HEAD/OPTIONS exempt."""
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            ok, _ = check_origin_against_host(
                method=method,
                path="/runs/abc",
                origin_header="https://evil.com",
                host_header="seqsetup.example.com",
                request_scheme="https",
                trusted_origins=set(),
            )
            assert ok is False, f"{method} must be checked"
        for method in ("GET", "HEAD", "OPTIONS"):
            ok, _ = check_origin_against_host(
                method=method,
                path="/runs/abc",
                origin_header="",
                host_header="seqsetup.example.com",
                request_scheme="https",
                trusted_origins=set(),
            )
            assert ok is True, f"{method} must be exempt"


class TestOriginCheckMiddlewareIntegration:
    """Mini integration test against a Starlette app."""

    def test_post_with_matching_origin_passes(self):
        from starlette.applications import Starlette
        from starlette.responses import PlainTextResponse
        from starlette.routing import Route
        from starlette.testclient import TestClient

        from seqsetup.csrf import OriginCheckMiddleware

        async def submit(request):
            return PlainTextResponse("ok")

        app = Starlette(routes=[Route("/x", submit, methods=["POST"])])
        app.add_middleware(OriginCheckMiddleware, trusted_origins=set())

        client = TestClient(app, base_url="http://testserver")
        # TestClient sets Host=testserver; pass matching Origin explicitly.
        response = client.post("/x", headers={"Origin": "http://testserver"})
        assert response.status_code == 200

    def test_post_with_cross_origin_is_403(self):
        from starlette.applications import Starlette
        from starlette.responses import PlainTextResponse
        from starlette.routing import Route
        from starlette.testclient import TestClient

        from seqsetup.csrf import OriginCheckMiddleware

        async def submit(request):
            return PlainTextResponse("ok")

        app = Starlette(routes=[Route("/x", submit, methods=["POST"])])
        app.add_middleware(OriginCheckMiddleware, trusted_origins=set())

        client = TestClient(app, base_url="http://testserver")
        response = client.post("/x", headers={"Origin": "http://attacker.example"})
        assert response.status_code == 403
