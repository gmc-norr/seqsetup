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


def test_profiles_page_renders(logged_in_client):
    """GET /profiles renders the Tailwind-styled empty-state page."""
    response = logged_in_client.get("/profiles")
    assert response.status_code == 200
    # The page must contain the empty-state messages that pre-date the
    # Tailwind port — they're stable, user-visible text.
    assert "No test profiles available" in response.text
    assert "No application profiles available" in response.text
    # Confirm the new Tailwind structure landed (sanity that the new
    # template was actually rendered, not the old FT component).
    assert "space-y-6" in response.text


def test_profiles_page_renders_populated(fresh_app, logged_in_client):
    """GET /profiles renders the populated table rows when profiles exist."""
    from seqsetup.models.application_profile import ApplicationProfile
    from seqsetup.models.test_profile import ApplicationProfileReference, TestProfile

    app, ctx, db = fresh_app

    ap = ApplicationProfile(
        name="MyApp",
        version="1.0.0",
        application_type="Dragen",
        application_name="DragenGermline",
        settings={"SoftwareVersion": "4.2.0", "Foo": "bar"},
    )
    ctx.app_profile_repo.save(ap)

    tp = TestProfile(
        test_type="WGS",
        test_name="Whole Genome",
        description="A test profile",
        version="1.0.0",
        application_profiles=[
            ApplicationProfileReference(profile_name="MyApp", profile_version="~=1.0.0"),
            ApplicationProfileReference(profile_name="MissingApp", profile_version="~=1.0.0"),
        ],
    )
    ctx.test_profile_repo.save(tp)

    response = logged_in_client.get("/profiles")
    assert response.status_code == 200
    # Populated headings/counts
    assert "Test Profiles (1)" in response.text
    assert "Application Profiles (1)" in response.text
    # The resolved row should render with the resolved application name
    assert "DragenGermline" in response.text
    # The TestProfile card legend
    assert "Whole Genome" in response.text
    # The settings-summary cell with Foo: bar (SoftwareVersion is excluded)
    assert "Foo: bar" in response.text


def test_dashboard_renders(logged_in_client):
    """GET / renders the dashboard page (empty-state path)."""
    response = logged_in_client.get("/", follow_redirects=False)
    assert response.status_code == 200
    # Empty state — no runs seeded
    assert "No Runs Yet" in response.text
    assert 'id="dashboard"' in response.text


def test_dashboard_tab_swap_returns_fragment(logged_in_client):
    """GET /dashboard/tab/ready with HX-Request returns a block fragment,
    not the full app shell."""
    response = logged_in_client.get(
        "/dashboard/tab/ready",
        headers={"HX-Request": "true"},
    )
    assert response.status_code == 200
    # Fragment: NO <html>, NO <head> — just the dashboard_content block.
    assert "<html" not in response.text
    assert "<head" not in response.text
    # The #dashboard wrapper IS in the fragment (HTMX swap target).
    assert 'id="dashboard"' in response.text


def test_admin_instruments_renders(logged_in_client):
    """GET /admin/instruments renders for an admin."""
    response = logged_in_client.get("/admin/instruments")
    assert response.status_code == 200
    assert "Instruments" in response.text
    assert 'id="instruments-page"' in response.text


def test_admin_sample_api_renders(logged_in_client):
    """GET /admin/sample-api renders for admin (LIMS repo seeded by fresh_app)."""
    response = logged_in_client.get("/admin/sample-api")
    assert response.status_code == 200
    assert "LIMS Integration" in response.text
    assert 'id="sample-api-page"' in response.text
    assert 'id="sample-api-config-form"' in response.text


# Non-admin rejection test omitted: logged_in_client IS admin and there is
# no separate standard-user client fixture defined in conftest.py.
# A standard_user_seeded fixture exists for user seeding but no TestClient
# fixture builds a session for it. Adding one is out of scope for 2.3.
