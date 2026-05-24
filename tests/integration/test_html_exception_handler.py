"""HTTPException raised by a route/dep → HTML fragment, not JSON.

The HTML-aware handler is critical because the new
``require_admin_dep`` and ``get_editable_run`` deps raise
``HTTPException`` to short-circuit. FastAPI's default handler returns
JSON, which would surface as raw JSON in the browser — violating the
"no JSON in HTML routes" rule.

We exercise the handler via a TEMPORARY test-only route that raises
``HTTPException`` directly — NOT via ``/admin/users``, because in
Phase 0 the admin routes still use the old function-style
``require_admin(request) -> Response`` that returns directly. The new
``require_admin_dep`` only takes effect when admin routes migrate in
Phase 2. (The real admin-via-HTMX assertion lives in Phase 2's
``admin/users`` migration commit.)
"""

from fastapi import HTTPException
from starlette.responses import HTMLResponse


def test_http_exception_returns_html_fragment(logged_in_client, fresh_app):
    """An HTTPException from a route → HTML body, NOT JSON.

    Uses ``logged_in_client`` because the AuthMiddleware redirects
    unauthenticated requests to ``/login`` for any non-public HTML path
    (``__test_*`` paths aren't in PUBLIC_ROUTES). The temp route is
    installed on the same app the fixture booted, so the auth cookie
    set by ``logged_in_client`` lets us actually reach the handler.
    """
    app, _ctx, _db = fresh_app

    @app.get("/__test_http_exc")
    def _h():
        raise HTTPException(status_code=404, detail="Resource not found")

    response = logged_in_client.get("/__test_http_exc")
    assert response.status_code == 404
    # The Content-Type should be HTML, not JSON.
    assert "text/html" in response.headers.get("content-type", "")
    # Body contains the HTML error fragment.
    assert "<div" in response.text
    assert "Resource not found" in response.text


def test_http_exception_via_htmx_includes_retarget(logged_in_client, fresh_app):
    """HTMX clients hitting an HTTPException get HX-Retarget so the
    error lands in the page's error slot."""
    app, _ctx, _db = fresh_app

    @app.get("/__test_http_exc_htmx")
    def _h():
        raise HTTPException(status_code=403, detail="Admin access required")

    response = logged_in_client.get(
        "/__test_http_exc_htmx",
        headers={"HX-Request": "true"},
    )
    assert response.status_code == 403
    assert response.headers.get("HX-Retarget") == "#error-banner"
    assert response.headers.get("HX-Reswap") == "innerHTML"


def test_api_path_keeps_json_response(client):
    """``/api/*`` is the JSON API sub-app — should still return JSON
    on errors (different handler chain inside the sub-app)."""
    response = client.get(
        "/api/runs",
        headers={"Authorization": "Bearer invalid-token-here"},
    )
    # Unauthorized — sub-app handles, returns JSON.
    assert response.status_code == 401
    assert "application/json" in response.headers.get("content-type", "")


def test_http_exception_detail_is_html_escaped(logged_in_client, fresh_app):
    """SECURITY: any string in HTTPException.detail must be HTML-escaped
    before interpolation into the response body. Defence in depth —
    even though current detail strings are developer-controlled, a
    future raise with a user-controlled value must not produce XSS.
    """
    from fastapi import HTTPException

    app, _ctx, _db = fresh_app

    @app.get("/__test_xss")
    def _h():
        # Simulate the failure mode: a detail string that includes HTML.
        raise HTTPException(status_code=400, detail="<script>alert(1)</script>")

    response = logged_in_client.get("/__test_xss")
    assert response.status_code == 400
    # Tags MUST be escaped — raw <script> must not appear in the body.
    assert "<script>" not in response.text
    # Escaped form MUST be present.
    assert "&lt;script&gt;" in response.text
