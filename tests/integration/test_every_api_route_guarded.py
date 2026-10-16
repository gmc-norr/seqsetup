"""Every /api route asks for a Bearer token, and none hands out a Draft.

Closes a gap: the /api sub-app has no app-level login check (AuthMiddleware
lets /api/* through, app.py mounts the sub-app at /api), so each route is
guarded only by its own ``token: AuthToken``-style argument
(``make_bearer_auth`` in api/deps.py); a new route without one would be
public. And the API's Draft refusal (``_check_run_access`` in api/app.py) was
tested only on samplesheet-v2. These tests walk every route the sub-app
registers, so a new one is covered the day it is added.
"""

import re
from datetime import datetime

from fastapi.routing import iter_route_contexts
from starlette.testclient import TestClient

from seqsetup.models.api_token import ApiToken
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun

from .conftest import seed_stored_exports

# /api routes meant to answer without a token, each with its reason. None
# today: the schema and the Swagger page are token-gated too (api/app.py).
OPEN_API_ROUTES: dict[tuple[str, str], str] = {}

# The /api routes that serve no one run. Every other /api route is taken to
# serve a run, so it must take the run in its path and refuse a Draft; a new
# route that serves no run has to be added here on purpose.
NOT_PER_RUN = {
    ("GET", "/api/runs"),
    ("GET", "/api/openapi.json"),
    ("GET", "/api/docs"),
    ("GET", "/api/docs/init.js"),
}

# The per-run endpoints the API serves today (api/app.py).
PER_RUN_PATHS = {
    "/runs/{run_id}/samplesheet-v2",
    "/runs/{run_id}/samplesheet-v1",
    "/runs/{run_id}/json",
    "/runs/{run_id}/validation-report",
    "/runs/{run_id}/validation-pdf",
}

SHEET = "[Header]\nFileFormatVersion,2\n\n[Reads]\nRead1Cycles,151\n"


def _api(app):
    """The FastAPI sub-app mounted at /api."""
    (api,) = [route.app for route in app.routes if getattr(route, "path", "") == "/api"]
    return api


def _api_endpoints(app):
    """(method, path, route) for every route on the /api sub-app; the path is
    the one a client calls, /api included."""
    return [(method, "/api" + route.path, route)
            for route in iter_route_contexts(_api(app).routes)
            for method in sorted(route.methods or {"?"})]


def _url(path, run_id="dummy-1"):
    """The path with every path parameter, whatever its name, set to run_id."""
    return re.sub(r"\{[^}]+\}", run_id, path)


def _token(ctx) -> str:
    plaintext = ApiToken.generate_token()
    token_hash, token_prefix = ApiToken.hash_token(plaintext)
    ctx.api_token_repo.save(ApiToken(name="guard-walk", token_hash=token_hash,
                                     token_prefix=token_prefix, created_by="admin-test"))
    return plaintext


def _run(ctx, run_id, status):
    """A run with every export stored, so only the status check stands
    between a Draft and a 200."""
    run = SequencingRun(
        id=run_id, run_name=f"Guard {run_id}",
        instrument_platform=InstrumentPlatform.NOVASEQ_6000, flowcell_type="S4",
        run_cycles=RunCycles(151, 151, 8, 8), status=status,
        created_at=datetime(2026, 1, 10, 9, 0), updated_at=datetime(2026, 1, 10, 9, 0),
        exports=seed_stored_exports(
            ctx, run_id, samplesheet_v2=SHEET, samplesheet_v1=SHEET.replace("2", "1"),
            json='{"run_name": "x"}', validation_json='{"errors": []}',
            validation_pdf=b"%PDF-1.4\n%guard\n"),
    )
    run.add_sample(Sample(id=f"{run_id}-s1", sample_id="S1", lanes=[1]))
    ctx.run_repo.save(run)
    return run_id


def _uses(dependant, code):
    return any(getattr(d.call, "__code__", None) is code or _uses(d, code)
               for d in dependant.dependencies)


class TestEveryApiRouteNeedsAToken:
    """Every /api route, every method, answers 401 with no token, with a
    token that is not one, and with a non-Bearer Authorization header."""

    def _walk(self, fresh_app, headers):
        app, _ctx, _db = fresh_app
        anon = TestClient(app, base_url="http://testserver")
        checked, bad = [], []
        for method, path, _route in _api_endpoints(app):
            if (method, path) in OPEN_API_ROUTES:
                continue
            response = anon.request(method, _url(path), headers=headers, follow_redirects=False)
            checked.append((method, path))
            if (response.status_code != 401
                    or not response.headers.get("www-authenticate", "").startswith("Bearer")):
                bad.append((method, path, response.status_code))
        return checked, bad

    def test_no_token_gets_401(self, fresh_app):
        checked, bad = self._walk(fresh_app, {})
        assert len(checked) >= 8, checked
        assert bad == []

    def test_wrong_token_gets_401(self, fresh_app):
        checked, bad = self._walk(fresh_app, {"Authorization": "Bearer not-a-real-token"})
        assert len(checked) >= 8, checked
        assert bad == []

    def test_non_bearer_authorization_gets_401(self, fresh_app):
        checked, bad = self._walk(fresh_app, {"Authorization": "Basic YWRtaW46YWRtaW4="})
        assert len(checked) >= 8, checked
        assert bad == []

    def test_open_list_names_only_real_routes(self, fresh_app):
        app, _ctx, _db = fresh_app
        found = {(m, p) for m, p, _r in _api_endpoints(app)}
        assert set(OPEN_API_ROUTES) <= found

    def test_every_route_carries_the_bearer_dependency(self, fresh_app):
        """Structural: each route's dependency tree holds the Bearer check
        that make_bearer_auth builds, so a route added without its
        ``token: AuthToken`` argument fails here even before anyone calls it."""
        from seqsetup.api.deps import make_bearer_auth
        app, ctx, _db = fresh_app
        bearer_code = make_bearer_auth(ctx).__code__
        endpoints = _api_endpoints(app)
        missing = [(m, p) for m, p, r in endpoints
                   if (m, p) not in OPEN_API_ROUTES and not _uses(r.dependant, bearer_code)]
        assert len(endpoints) >= 8, [(m, p) for m, p, _r in endpoints]
        assert missing == []

    def test_a_valid_token_gets_through(self, fresh_app):
        """Control: the 401s above are the token check, not a broken route."""
        app, ctx, _db = fresh_app
        client = TestClient(app, base_url="http://testserver")
        auth = {"Authorization": f"Bearer {_token(ctx)}"}
        for path in ("/api/runs", "/api/openapi.json", "/api/docs", "/api/docs/init.js"):
            assert client.get(path, headers=auth).status_code == 200, path


class TestNoDraftThroughTheApi:
    """With a valid token, every per-run endpoint refuses a Draft (403) even
    when the Draft has every export stored, and the list never shows one;
    the same endpoints serve a Ready and an Archived run."""

    def _per_run(self, app):
        """Every /api route but the few that serve no one run, whatever its
        path parameter is called."""
        return sorted((m, p) for m, p, _r in _api_endpoints(app) if (m, p) not in NOT_PER_RUN)

    def test_every_route_serving_a_run_takes_it_in_its_path(self, fresh_app):
        """A route outside NOT_PER_RUN with no path parameter (a run picked by
        a query string, say) could not be walked with a Draft's id below; it
        must be named on purpose instead."""
        app, _ctx, _db = fresh_app
        found = {(m, p) for m, p, _r in _api_endpoints(app)}
        no_parameter = [(m, p) for m, p in self._per_run(app) if not re.search(r"\{[^}]+\}", p)]
        assert NOT_PER_RUN <= found, NOT_PER_RUN - found
        assert no_parameter == []

    def test_every_per_run_endpoint_refuses_a_draft(self, fresh_app):
        app, ctx, _db = fresh_app
        client = TestClient(app, base_url="http://testserver")
        auth = {"Authorization": f"Bearer {_token(ctx)}"}
        _run(ctx, "draft-run", RunStatus.DRAFT)
        endpoints = self._per_run(app)
        bad = []
        for method, path in endpoints:
            response = client.request(method, _url(path, "draft-run"), headers=auth)
            if response.status_code != 403:
                bad.append((method, path, response.status_code, response.text[:60]))
        assert {("GET", "/api" + p) for p in PER_RUN_PATHS} <= set(endpoints), endpoints
        assert bad == []

    def test_every_per_run_endpoint_serves_ready_and_archived(self, fresh_app):
        app, ctx, _db = fresh_app
        client = TestClient(app, base_url="http://testserver")
        auth = {"Authorization": f"Bearer {_token(ctx)}"}
        _run(ctx, "ready-run", RunStatus.READY)
        _run(ctx, "archived-run", RunStatus.ARCHIVED)
        endpoints = self._per_run(app)
        bad = []
        for run_id in ("ready-run", "archived-run"):
            for method, path in endpoints:
                response = client.request(method, _url(path, run_id), headers=auth)
                if response.status_code != 200 or not response.content:
                    bad.append((run_id, method, path, response.status_code))
        assert len(endpoints) >= 5, endpoints
        assert bad == []

    def test_the_list_never_shows_a_draft(self, fresh_app):
        app, ctx, _db = fresh_app
        client = TestClient(app, base_url="http://testserver")
        auth = {"Authorization": f"Bearer {_token(ctx)}"}
        _run(ctx, "draft-run", RunStatus.DRAFT)
        _run(ctx, "ready-run", RunStatus.READY)
        _run(ctx, "archived-run", RunStatus.ARCHIVED)

        listed = {}
        for query in ("", "?status=ready", "?status=archived"):
            response = client.get(f"/api/runs{query}", headers=auth)
            assert response.status_code == 200, query
            body = response.json()
            listed[query] = {item["id"] for item in body["items"]}
            assert "draft-run" not in listed[query], query
            assert body["total"] == len(listed[query]), query
        assert listed[""] == {"ready-run"}
        assert listed["?status=ready"] == {"ready-run"}
        assert listed["?status=archived"] == {"archived-run"}
        assert client.get("/api/runs?status=draft", headers=auth).status_code == 400
