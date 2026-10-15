"""Every route on the app asks for a login, and every admin route for an admin.

Closes a gap: the login was only spot-checked (``GET /``), nothing pinned
``PUBLIC_ROUTES`` / ``_STATIC_PREFIXES`` in ``middleware.py``, and the admin
check was only tried through each area's GET page. These tests walk every
route the app registers (every method), so a new route, or a new method on an
old path, is covered the day it is added.

The walk reads the routes the way the router serves them
(``fastapi.routing.iter_route_contexts``: an included router's routes with
its prefix and its router-level dependencies), so a dependency added at
include time counts and one that never runs does not.

Middleware order is Security -> Origin (CSRF) -> Session -> Auth (app.py), so a
POST/PUT/PATCH/DELETE without a good Origin is answered 403 by the CSRF check
before the login check runs. Every state-changing request here carries the
same-origin Origin header, so a missing login check cannot hide behind it.
The /api sub-app has its own Bearer check:
tests/integration/test_every_api_route_guarded.py.
"""

import re

from fastapi.routing import iter_route_contexts
from starlette.routing import Mount
from starlette.staticfiles import StaticFiles
from starlette.testclient import TestClient

ORIGIN = {"Origin": "http://testserver"}

# What the login lets through today, on purpose. Widening either set must
# change this test too.
EXPECTED_PUBLIC_ROUTES = {"/login", "/login/submit", "/favicon.ico"}
EXPECTED_STATIC_PREFIXES = {"/static/", "/css/", "/js/", "/img/"}

# The routes registered on those public paths, method by method.
EXPECTED_PUBLIC_ENDPOINTS = {
    ("GET", "/login"),
    ("POST", "/login/submit"),
    ("GET", "/favicon.ico"),
}

# Admin-only routes that do not live under /admin. CLAUDE.md: "Index kit
# upload requires admin" (routes/indexes.py: the upload, and its form).
ADMIN_ONLY_OUTSIDE_ADMIN = {
    ("GET", "/indexes/import"),
    ("POST", "/indexes/upload"),
}

_STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}


def _endpoints(app):
    """(method, path, route) for every route the app serves, mounts left out;
    plus the mounts, and any route this walk cannot read (no methods)."""
    endpoints, mounts, unknown = [], [], []
    for route in iter_route_contexts(app.routes):
        if isinstance(route.original_route, Mount):
            mounts.append(route.original_route)
            continue
        if not route.methods:
            unknown.append(route.path)
            continue
        for method in sorted(route.methods):
            endpoints.append((method, route.path, route))
    return endpoints, mounts, unknown


def _concrete(path):
    """A URL for a route path: each path parameter filled with a dummy value."""
    return re.sub(r"\{[^}]+\}", "dummy-1", path)


def _uses(dependant, fn):
    return any(d.call is fn or _uses(d, fn) for d in dependant.dependencies)


def _is_admin_path(path):
    return path == "/admin" or path.startswith("/admin/")


class TestThePublicList:
    """Only the login page, its form post and the favicon redirect are open,
    plus the static-asset folders; anything more must be added on purpose."""

    def test_public_routes_are_exactly_todays(self):
        from seqsetup.middleware import PUBLIC_ROUTES
        assert set(PUBLIC_ROUTES) == EXPECTED_PUBLIC_ROUTES

    def test_static_prefixes_are_exactly_todays(self):
        from seqsetup.middleware import _STATIC_PREFIXES
        assert set(_STATIC_PREFIXES) == EXPECTED_STATIC_PREFIXES
        assert len(_STATIC_PREFIXES) == len(EXPECTED_STATIC_PREFIXES)

    def test_public_paths_hold_only_the_public_endpoints(self, fresh_app):
        """No route sits on a public path or under a static prefix but the
        three public endpoints; the static prefixes hold only static-file
        mounts; and nothing but the API sub-app sits under /api, which the
        login check also lets through."""
        app, _ctx, _db = fresh_app
        endpoints, mounts, _unknown = _endpoints(app)

        public = {(m, p) for m, p, _r in endpoints
                  if p in EXPECTED_PUBLIC_ROUTES or p.startswith(tuple(EXPECTED_STATIC_PREFIXES))}
        assert public == EXPECTED_PUBLIC_ENDPOINTS

        under_api = [(m, p) for m, p, _r in endpoints if p == "/api" or p.startswith("/api/")]
        assert under_api == []

        static_mounts = {m.path + "/": type(m.app) for m in mounts if m.path != "/api"}
        assert static_mounts == {p: StaticFiles for p in EXPECTED_STATIC_PREFIXES}
        assert [m.path for m in mounts].count("/api") == 1

    def test_public_endpoints_answer_without_login(self, fresh_app):
        """Control for the walk below: the open routes do reach their
        handlers with no login, so a 303 to /login is the login check."""
        app, _ctx, _db = fresh_app
        anon = TestClient(app, base_url="http://testserver")
        assert anon.get("/login", follow_redirects=False).status_code == 200
        icon = anon.get("/favicon.ico", follow_redirects=False)
        assert (icon.status_code, icon.headers.get("location")) == (301, "/img/favicon.svg")
        refused = anon.post("/login/submit", data={"username": "nobody", "password": "wrong"},
                            headers=ORIGIN, follow_redirects=False)
        assert refused.status_code == 200


class TestEveryRouteNeedsALogin:
    """With no login, every route that is not public is turned away by
    AuthMiddleware before any handler runs: a page request gets a 303 to
    /login, and an HTMX request a 401 that puts "Your login has ended" in the
    page's error banner (adding "so this was not saved" for a change)."""

    def _walk(self, fresh_app, headers):
        app, _ctx, _db = fresh_app
        anon = TestClient(app, base_url="http://testserver")
        endpoints, _mounts, unknown = _endpoints(app)
        assert unknown == [], f"routes this walk cannot read; extend it: {unknown}"
        checked, responses = [], []
        for method, path, _route in endpoints:
            if (method, path) in EXPECTED_PUBLIC_ENDPOINTS:
                continue
            sent = dict(headers)
            if method in _STATE_CHANGING:
                sent.update(ORIGIN)
            response = anon.request(method, _concrete(path), headers=sent, follow_redirects=False)
            checked.append((method, path))
            responses.append((method, path, response))
        return checked, responses

    def test_every_page_request_is_sent_to_login(self, fresh_app):
        checked, responses = self._walk(fresh_app, {})
        bad = [(m, p, r.status_code, r.headers.get("location"))
               for m, p, r in responses
               if (r.status_code, r.headers.get("location")) != (303, "/login")]
        assert len(checked) >= 90, checked
        assert bad == []

    def test_every_htmx_request_gets_the_ended_login_banner(self, fresh_app):
        checked, responses = self._walk(fresh_app, {"HX-Request": "true"})
        bad = [(m, p, r.status_code, r.text[:80])
               for m, p, r in responses
               if r.status_code != 401
               or r.headers.get("HX-Retarget") != "#error-banner"
               or "Your login has ended" not in r.text
               or ("this was not saved" in r.text) != (m in _STATE_CHANGING)]
        assert len(checked) >= 90, checked
        assert bad == []


class TestEveryAdminRouteNeedsAnAdmin:
    """Every route under /admin, every method, and the index-kit upload and
    its form refuse a signed-in standard user with 403, and each one carries
    require_admin_dep so the refusal does not depend on its handler."""

    def test_standard_user_gets_403_everywhere_admin(self, fresh_app, logged_in_standard_client):
        app, _ctx, _db = fresh_app
        endpoints, _mounts, _unknown = _endpoints(app)
        targets = [(m, p) for m, p, _r in endpoints
                   if _is_admin_path(p) or (m, p) in ADMIN_ONLY_OUTSIDE_ADMIN]
        bad = []
        for method, path in targets:
            headers = ORIGIN if method in _STATE_CHANGING else {}
            response = logged_in_standard_client.request(
                method, _concrete(path), headers=headers, follow_redirects=False)
            if response.status_code != 403:
                bad.append((method, path, response.status_code))
        assert len(targets) >= 25, targets
        assert ADMIN_ONLY_OUTSIDE_ADMIN <= set(targets)
        assert bad == []

    def test_every_admin_route_carries_require_admin_dep(self, fresh_app):
        from seqsetup.routes.dependencies import require_admin_dep
        app, _ctx, _db = fresh_app
        endpoints, _mounts, _unknown = _endpoints(app)
        targets = [(m, p, r) for m, p, r in endpoints
                   if _is_admin_path(p) or (m, p) in ADMIN_ONLY_OUTSIDE_ADMIN]
        missing = [(m, p) for m, p, r in targets if not _uses(r.dependant, require_admin_dep)]
        assert len(targets) >= 25, [(m, p) for m, p, _r in targets]
        assert ADMIN_ONLY_OUTSIDE_ADMIN <= {(m, p) for m, p, _r in targets}
        assert missing == []
