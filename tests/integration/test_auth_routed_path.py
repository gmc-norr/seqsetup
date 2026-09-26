"""The login and CSRF checks decide on the path the router routes, never on
a URL rebuilt from the Host header.

Starlette's ``request.url`` is ``scheme://`` + Host header + path. A Host
header holding a "/" (e.g. ``x/api``) moved the start of
``request.url.path``, so to AuthMiddleware every page looked like
``/api/...`` and was served with no login: the dashboard, any run page, any
export (security audit 2026-09, N-01). Both middlewares now read
``scope["path"]``, the value the router matches. AuthMiddleware also refuses
"." and ".." path segments: browsers never send them, and a hop that
collapsed them after the login check would turn an exempt prefix (/api/,
/static/) into a protected page.

Requests are sent at raw-ASGI level: an HTTP client would normalise the
path or the Host header and make these tests pass for the wrong reason.
"""

import asyncio
import json
from urllib.parse import urlencode

import pytest

from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun

RUN_ID = "routed-path-run"
MARKER = "ROUTED-PATH-RUN-MARKER"
SAMPLE_MARKER = "ROUTED-PATH-SAMPLE-01"


def _run(ctx, status=RunStatus.DRAFT):
    run = SequencingRun(
        id=RUN_ID, run_name=MARKER,
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=status,
    )
    run.add_sample(Sample(id="s1", sample_id=SAMPLE_MARKER, lanes=[1]))
    ctx.run_repo.save(run)


def _call(app, method, path, headers=(), body=b""):
    """(status, headers dict, body bytes) for one raw ASGI request."""
    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
        "method": method, "scheme": "http", "path": path, "raw_path": path.encode(),
        "root_path": "", "query_string": b"",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers],
        "client": ("127.0.0.1", 5555), "server": ("testserver", 80),
    }
    sent = []
    pending = [{"type": "http.request", "body": body, "more_body": False}]

    async def receive():
        if pending:
            return pending.pop()
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    asyncio.run(app(scope, receive, send))
    start = next(m for m in sent if m["type"] == "http.response.start")
    out = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return start["status"], {k.decode(): v.decode() for k, v in start["headers"]}, out


def _session_cookie(client):
    """The Cookie header value of a logged-in TestClient."""
    return "; ".join(f"{name}={value}" for name, value in client.cookies.items())


class TestHostHeaderCannotSkipLogin:
    """A Host header with a "/" in it no longer skips the session check."""

    @pytest.mark.parametrize("host", ["x/api", "x/static", "x/js", "x/css", "x/img"])
    def test_run_page_needs_login_whatever_the_host(self, fresh_app, host):
        app, ctx, _db = fresh_app
        _run(ctx)

        status, headers, body = _call(app, "GET", f"/runs/{RUN_ID}", [("host", host)])

        assert status == 303
        assert headers.get("location") == "/login"
        assert MARKER.encode() not in body and SAMPLE_MARKER.encode() not in body

    def test_dashboard_needs_login_with_a_crafted_host(self, fresh_app):
        app, ctx, _db = fresh_app
        _run(ctx)

        status, headers, body = _call(app, "GET", "/", [("host", "x/api")])

        assert status == 303
        assert MARKER.encode() not in body

    def test_export_needs_login_with_a_crafted_host(self, fresh_app):
        app, ctx, _db = fresh_app
        _run(ctx, status=RunStatus.READY)

        status, _headers, body = _call(app, "GET", f"/runs/{RUN_ID}/export/json", [("host", "x/api")])

        assert status == 303
        assert SAMPLE_MARKER.encode() not in body

    def test_logged_in_user_still_sees_the_run(self, fresh_app, logged_in_client):
        """Control: the marker is findable when the login is real."""
        app, ctx, _db = fresh_app
        _run(ctx)

        status, _headers, body = _call(
            app, "GET", f"/runs/{RUN_ID}",
            [("host", "testserver"), ("cookie", _session_cookie(logged_in_client))],
        )

        assert status == 200
        assert MARKER.encode() in body

    def test_api_still_answers_without_a_session(self, fresh_app):
        """Control: /api/* stays exempt from the session check (it has its
        own Bearer auth), so the fix did not just close everything."""
        app, _ctx, _db = fresh_app

        status, _headers, _body = _call(app, "GET", "/api/runs", [("host", "testserver")])

        assert status == 401


class TestCraftedHostCannotWrite:
    """Anonymous writes stay refused with a crafted Host header, even when a
    (junk) Bearer header is added to dodge the CSRF check."""

    def test_anonymous_lane_change_with_crafted_host_is_refused(self, fresh_app):
        app, ctx, _db = fresh_app
        _run(ctx)
        form = urlencode({"sample_ids": json.dumps(["s1"]), "lanes": json.dumps([2])}).encode()

        status, _headers, _body = _call(
            app, "POST", f"/runs/{RUN_ID}/samples/set-lanes",
            [("host", "x/api"), ("authorization", "Bearer junk"),
             ("content-type", "application/x-www-form-urlencoded")],
            form,
        )

        assert ctx.run_repo.get_by_id(RUN_ID).get_sample("s1").lanes == [1]
        assert status in (303, 403)


class TestCsrfUsesTheRoutedPath:
    """The CSRF exemption for Bearer-authenticated /api/* requests is decided
    on the routed path: a crafted Host no longer makes a page look like
    /api/*, so a logged-in POST with no Origin is refused."""

    def test_logged_in_post_without_origin_is_refused_despite_crafted_host(self, fresh_app, logged_in_client):
        app, ctx, _db = fresh_app
        _run(ctx)
        form = urlencode({"sample_ids": json.dumps(["s1"]), "lanes": json.dumps([2])}).encode()

        status, _headers, body = _call(
            app, "POST", f"/runs/{RUN_ID}/samples/set-lanes",
            [("host", "x/api"), ("authorization", "Bearer junk"),
             ("cookie", _session_cookie(logged_in_client)),
             ("content-type", "application/x-www-form-urlencoded")],
            form,
        )

        assert status == 403
        assert body == b"Forbidden"
        assert ctx.run_repo.get_by_id(RUN_ID).get_sample("s1").lanes == [1]


class TestDotSegmentsRefused:
    """"." and ".." segments are refused before the login decision."""

    @pytest.mark.parametrize("path", [
        f"/api/../runs/{RUN_ID}",
        f"/static/../runs/{RUN_ID}",
        f"/js/./../runs/{RUN_ID}",
        f"/runs/./{RUN_ID}",
    ])
    def test_dot_segment_path_is_400(self, fresh_app, path):
        app, ctx, _db = fresh_app
        _run(ctx)

        status, _headers, body = _call(app, "GET", path, [("host", "testserver")])

        assert status == 400
        assert MARKER.encode() not in body

    def test_a_dot_inside_a_segment_is_fine(self, fresh_app):
        """Control: only whole "." / ".." segments are refused, not names
        with dots in them (the favicon, versioned kit ids)."""
        app, _ctx, _db = fresh_app

        status, _headers, _body = _call(app, "GET", "/favicon.ico", [("host", "testserver")])

        assert status != 400
