"""First smoke test: verify the test fixture boots a working app at all.

If this passes, the integration-test infrastructure is sound and we can
build the workflow-coverage tests on top of it. If this fails, the fixture
needs surgery before the other tests are worth writing.
"""


def test_app_boots(fresh_app):
    """The fixture returns an app object."""
    app, ctx, db = fresh_app
    assert app is not None
    assert ctx is not None
    assert db is not None


def test_login_page_renders(client):
    """GET /login renders without auth — concrete marker, not a loose disjunction."""
    response = client.get("/login")
    assert response.status_code == 200
    # The page must contain the password input — that's the load-bearing
    # element of a login form. A three-way "or" disjunction would pass on
    # almost any HTML page.
    assert 'name="password"' in response.text


def test_unauthenticated_request_redirects_to_login(client):
    """A protected route without a session redirects to /login."""
    response = client.get("/", follow_redirects=False)
    assert response.status_code in (303, 302), f"Expected redirect, got {response.status_code}"
    assert "/login" in response.headers.get("location", "")


def test_security_headers_applied(client):
    """The SecurityHeadersMiddleware adds the expected headers to every response."""
    response = client.get("/login")
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
