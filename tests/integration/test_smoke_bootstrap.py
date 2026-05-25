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


def test_admin_instruments_rejects_standard_user(logged_in_standard_client):
    """Non-admin GET /admin/instruments returns 403."""
    response = logged_in_standard_client.get("/admin/instruments")
    assert response.status_code == 403


def test_admin_sample_api_rejects_standard_user(logged_in_standard_client):
    """Non-admin GET /admin/sample-api returns 403."""
    response = logged_in_standard_client.get("/admin/sample-api")
    assert response.status_code == 403


def test_admin_logs_rejects_standard_user(logged_in_standard_client):
    """Non-admin GET /admin/logs returns 403."""
    response = logged_in_standard_client.get("/admin/logs")
    assert response.status_code == 403


def test_admin_authentication_rejects_standard_user(logged_in_standard_client):
    """Non-admin GET /admin/authentication returns 403."""
    response = logged_in_standard_client.get("/admin/authentication")
    assert response.status_code == 403


def test_admin_config_sync_rejects_standard_user(logged_in_standard_client):
    """Non-admin GET /admin/config-sync returns 403."""
    response = logged_in_standard_client.get("/admin/config-sync")
    assert response.status_code == 403


def test_admin_users_rejects_standard_user(logged_in_standard_client):
    """Non-admin GET /admin/users returns 403."""
    response = logged_in_standard_client.get("/admin/users")
    assert response.status_code == 403


def test_admin_api_tokens_rejects_standard_user(logged_in_standard_client):
    """Non-admin GET /admin/api-tokens returns 403."""
    response = logged_in_standard_client.get("/admin/api-tokens")
    assert response.status_code == 403


def test_admin_users_delete_rejects_standard_user(logged_in_standard_client, fresh_app):
    """Non-admin DELETE on /admin/users/{username} returns 403."""
    response = logged_in_standard_client.delete(
        "/admin/users/some-user",
        headers={"Origin": "http://testserver"},
    )
    assert response.status_code == 403


def test_admin_logs_renders(logged_in_client):
    """GET /admin/logs renders the empty-state page for admin."""
    response = logged_in_client.get("/admin/logs")
    assert response.status_code == 200
    assert "Application Logs" in response.text
    assert 'id="logs-page"' in response.text


def test_admin_logs_htmx_returns_fragment(logged_in_client):
    """GET /admin/logs with HX-Request returns just the fragment."""
    response = logged_in_client.get(
        "/admin/logs",
        headers={"HX-Request": "true"},
    )
    assert response.status_code == 200
    assert "<html" not in response.text
    assert 'id="logs-page"' in response.text


def test_admin_api_tokens_renders(logged_in_client):
    """GET /admin/api-tokens renders the empty-state page for admin."""
    response = logged_in_client.get("/admin/api-tokens")
    assert response.status_code == 200
    assert "API Tokens" in response.text
    assert 'id="api-tokens-page"' in response.text
    assert "No API tokens have been created yet." in response.text


def test_admin_api_tokens_revoke_uses_delete_method(logged_in_client):
    """The new DELETE endpoint works (URL change from POST .../revoke)."""
    create_response = logged_in_client.post(
        "/admin/api-tokens/create",
        data={"name": "test-revoke-token", "expiry_days": "30"},
        headers={"Origin": "http://testserver"},
    )
    assert create_response.status_code == 200

    # Find the newly created token id via the list page
    list_response = logged_in_client.get("/admin/api-tokens")
    assert "test-revoke-token" in list_response.text
    import re
    m = re.search(r'hx-delete="/admin/api-tokens/([^"]+)"', list_response.text)
    assert m, "DELETE URL with token id not found in rendered page"
    token_id = m.group(1)

    # DELETE the token
    delete_response = logged_in_client.delete(
        f"/admin/api-tokens/{token_id}",
        headers={"Origin": "http://testserver"},
    )
    assert delete_response.status_code == 200
    assert "revoked" in delete_response.text.lower()


def test_admin_api_tokens_old_revoke_url_rejected(logged_in_client):
    """The OLD POST .../revoke endpoint no longer exists (regression test
    for the URL cleanup)."""
    response = logged_in_client.post(
        "/admin/api-tokens/some-id/revoke",
        headers={"Origin": "http://testserver"},
    )
    # Either 404 (no route) or 405 (method not allowed) is acceptable.
    assert response.status_code in (404, 405)


def test_admin_users_renders(logged_in_client):
    """GET /admin/users renders for admin (shows seeded admin user)."""
    response = logged_in_client.get("/admin/users")
    assert response.status_code == 200
    assert "Local Users" in response.text
    assert 'id="local-users-page"' in response.text
    # The conftest admin user should be in the table.
    assert "x-data=\"{ editing: false }\"" in response.text


def test_admin_users_delete_uses_delete_method(logged_in_client, fresh_app):
    """The new DELETE endpoint works (URL change from POST .../delete)."""
    from seqsetup.models.local_user import LocalUser
    from seqsetup.models.user import UserRole
    app, ctx, db = fresh_app

    # Seed a deletable standard user (the admin can't be deleted — last admin guard).
    target = LocalUser(username="todelete", display_name="To Delete", role=UserRole.STANDARD)
    target.set_password("Str0ngPassw0rd!2024")
    ctx.local_user_repo.save(target)

    response = logged_in_client.delete(
        "/admin/users/todelete",
        headers={"Origin": "http://testserver"},
    )
    assert response.status_code == 200
    assert "deleted" in response.text.lower()


def test_admin_users_old_delete_url_rejected(logged_in_client):
    """OLD POST /admin/users/{u}/delete must return 404/405 (URL cleanup)."""
    response = logged_in_client.post(
        "/admin/users/some-user/delete",
        headers={"Origin": "http://testserver"},
    )
    assert response.status_code in (404, 405)


def test_admin_config_sync_renders(logged_in_client):
    """GET /admin/config-sync renders for admin."""
    response = logged_in_client.get("/admin/config-sync")
    assert response.status_code == 200
    assert "Config Sync" in response.text or "GitHub Config Sync" in response.text
    assert 'id="config-sync-page"' in response.text


def test_admin_authentication_renders(logged_in_client):
    """GET /admin/authentication renders for admin."""
    response = logged_in_client.get("/admin/authentication")
    assert response.status_code == 200
    assert "Authentication" in response.text
    assert 'id="ldap-config-form"' in response.text
    # Auth-method radios present
    assert 'name="auth_method"' in response.text
    assert 'value="local"' in response.text


def test_admin_users_last_admin_cannot_be_deleted(logged_in_client, fresh_app):
    """Last-admin guard preserved across the URL rewrite."""
    app, ctx, db = fresh_app
    # The conftest seeds exactly one admin. Try to delete them.
    admins = [u for u in ctx.local_user_repo.list_all() if u.role.value == "admin"]
    assert len(admins) >= 1
    last_admin = admins[0]

    response = logged_in_client.delete(
        f"/admin/users/{last_admin.username}",
        headers={"Origin": "http://testserver"},
    )
    assert response.status_code == 200
    assert "last admin" in response.text.lower()


def test_admin_users_last_admin_cannot_be_demoted(logged_in_client, fresh_app):
    """The last admin cannot have their role changed to STANDARD via edit."""
    app, ctx, db = fresh_app
    admins = [u for u in ctx.local_user_repo.list_all() if u.role.value == "admin"]
    assert len(admins) >= 1
    last_admin = admins[0]

    response = logged_in_client.post(
        f"/admin/users/{last_admin.username}/edit",
        data={
            "display_name": last_admin.display_name,
            "email": last_admin.email or "",
            "role": "standard",
            "password": "",
        },
        headers={"Origin": "http://testserver"},
    )
    assert response.status_code == 200
    assert "last admin" in response.text.lower()


def test_indexes_list_renders(logged_in_client):
    """GET /indexes renders the empty-state page."""
    response = logged_in_client.get("/indexes")
    assert response.status_code == 200
    assert "Index Kits" in response.text
    assert 'id="indexes-page"' in response.text


def test_indexes_import_renders(logged_in_client):
    """GET /indexes/import renders the upload form."""
    response = logged_in_client.get("/indexes/import")
    assert response.status_code == 200
    assert "Import Index Kit" in response.text
    assert 'name="index_file"' in response.text


def test_indexes_delete_uses_delete_method(logged_in_client):
    """The DELETE endpoint responds — the key signal is not 405 Method Not Allowed."""
    response = logged_in_client.delete(
        "/indexes/kits/nonexistent/1.0.0",
        headers={"Origin": "http://testserver"},
    )
    # Admin deleting a nonexistent kit now raises 404 (consistent with non-admin path).
    assert response.status_code != 405


def test_indexes_old_delete_url_rejected(logged_in_client):
    """OLD POST .../delete must return 404/405 (URL cleanup regression)."""
    response = logged_in_client.post(
        "/indexes/kits/nonexistent/1.0.0/delete",
        headers={"Origin": "http://testserver"},
    )
    assert response.status_code in (404, 405)


def test_validation_page_renders_with_alpine_tabs(logged_in_client, fresh_app):
    """GET /runs/{id}/validation renders all tab contents in one response
    and includes the Alpine tab switcher state."""
    from seqsetup.models.sequencing_run import SequencingRun, InstrumentPlatform
    app, ctx, db = fresh_app
    run = SequencingRun(
        run_name="ValidationSmoke",
        instrument_platform=InstrumentPlatform.NOVASEQ_X,
        created_by="admin",
    )
    ctx.run_repo.save(run)

    response = logged_in_client.get(f"/runs/{run.id}/validation")
    assert response.status_code == 200
    assert "Validation: ValidationSmoke" in response.text
    # Alpine tab state
    assert 'x-data="{ activeTab: \'issues\' }"' in response.text
    # All four tab content slots are present (pre-rendered)
    assert "x-show=\"activeTab === 'issues'\"" in response.text
    assert "x-show=\"activeTab === 'heatmaps'\"" in response.text
    assert "x-show=\"activeTab === 'colorbalance'\"" in response.text
    assert "x-show=\"activeTab === 'darkcycles'\"" in response.text
    # Approval bar present
    assert 'id="validation-approval-bar"' in response.text


def test_validation_tab_swap_endpoint_removed(logged_in_client):
    """The HTMX tab-swap endpoint /validation/tab/{tab} is REMOVED.
    Alpine pre-renders all tabs; the swap endpoint no longer exists."""
    response = logged_in_client.get(
        "/runs/some-id/validation/tab/issues",
    )
    # Either 404 (no route) or some other non-200 — the key is "no HTMX swap path".
    assert response.status_code in (404, 405)


def test_indexes_kit_content_empty_selection(logged_in_client):
    """GET /indexes/kit-content with no selection returns the empty panel."""
    response = logged_in_client.get("/indexes/kit-content")
    assert response.status_code == 200
    assert "Select an index kit" in response.text
    assert 'id="index-kit-panel"' in response.text


def test_add_samples_step1_renders(logged_in_client, fresh_app):
    """GET /runs/{id}/samples/add/step/1 renders the new Jinja2 template."""
    from seqsetup.models.sequencing_run import SequencingRun, InstrumentPlatform
    app, ctx, db = fresh_app
    run = SequencingRun(
        run_name="AddSamplesSmoke",
        instrument_platform=InstrumentPlatform.NOVASEQ_X,
        created_by="admin",
    )
    ctx.run_repo.save(run)

    response = logged_in_client.get(f"/runs/{run.id}/samples/add/step/1")
    assert response.status_code == 200
    assert "Step 1: Add Samples" in response.text
    assert 'id="add-samples-nav"' in response.text
    assert 'id="add-samples-result"' in response.text


def test_add_samples_step2_renders(logged_in_client, fresh_app):
    """GET /runs/{id}/samples/add/step/2 renders the new Jinja2 template."""
    from seqsetup.models.sequencing_run import SequencingRun, InstrumentPlatform
    app, ctx, db = fresh_app
    run = SequencingRun(
        run_name="AddSamplesSmoke2",
        instrument_platform=InstrumentPlatform.NOVASEQ_X,
        created_by="admin",
    )
    ctx.run_repo.save(run)

    response = logged_in_client.get(f"/runs/{run.id}/samples/add/step/2")
    assert response.status_code == 200
    assert "Step 2: Assign Indexes" in response.text
    assert 'id="add-samples-nav"' in response.text


def test_edit_run_page_renders(logged_in_client, fresh_app):
    """GET /runs/{id} renders the edit-run page (Jinja2)."""
    from seqsetup.models.sequencing_run import SequencingRun, InstrumentPlatform
    app, ctx, db = fresh_app
    run = SequencingRun(
        run_name="EditRunSmoke",
        instrument_platform=InstrumentPlatform.NOVASEQ_X,
        created_by="admin",
    )
    ctx.run_repo.save(run)

    response = logged_in_client.get(f"/runs/{run.id}")
    assert response.status_code == 200
    assert "EditRunSmoke" in response.text
    assert 'id="run-status-bar"' in response.text
    assert 'id="export-panel"' in response.text
    assert 'id="sample-section"' in response.text


def test_new_run_wizard_step1_renders(logged_in_client, fresh_app):
    """GET /runs/new/step/1?run_id=... renders the Jinja2 wizard page."""
    from seqsetup.models.sequencing_run import SequencingRun, InstrumentPlatform
    app, ctx, db = fresh_app
    run = SequencingRun(
        run_name="WizardStep1Smoke",
        instrument_platform=InstrumentPlatform.NOVASEQ_X,
        created_by="admin",
    )
    ctx.run_repo.save(run)

    response = logged_in_client.get(f"/runs/new/step/1?run_id={run.id}")
    assert response.status_code == 200
    assert "Step 1: Run Configuration" in response.text
    assert 'id="flowcell-select"' in response.text
    assert 'id="reagent-kit-select"' in response.text
    assert 'id="cycle-config"' in response.text
    assert 'name="run_name"' in response.text
    # progress bar present
    assert "wizard-progress" in response.text


def test_tests_page_renders(logged_in_client):
    """GET /tests renders the tests-management page (empty-state default)."""
    response = logged_in_client.get("/tests")
    assert response.status_code == 200
    assert "Tests Management" in response.text
    # The empty-state message — load-bearing assertion that the
    # tests.html template (not the old FT path) is what renders.
    assert "No tests configured yet" in response.text
