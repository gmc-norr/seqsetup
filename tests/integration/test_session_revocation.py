"""Logins live server-side: logout, idle and age limits, and database-user
changes end them (security audit N-02, N-03, N-04, N-19)."""

import base64
import json
from datetime import timedelta

import pytest
from itsdangerous import TimestampSigner
from starlette.testclient import TestClient

from seqsetup.services import web_sessions

ORIGIN = {"Origin": "http://testserver"}


def _login(app, creds):
    c = TestClient(app, base_url="http://testserver")
    r = c.post("/login/submit", data=creds, headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/", r.text[:300]
    return c


def _copy(client, app):
    """A second client holding the same cookie (a copied cookie)."""
    c = TestClient(app, base_url="http://testserver")
    c.cookies.set("seqsetup_session", client.cookies.get("seqsetup_session"))
    return c


def _get(c, path, **kw):
    return c.get(path, follow_redirects=False, **kw)


@pytest.fixture
def clock(monkeypatch):
    """Move the login clock forward: clock.advance(minutes=31)."""
    class _Clock:
        now = web_sessions.utcnow()

        def advance(self, **kw):
            self.now += timedelta(**kw)
    c = _Clock()
    monkeypatch.setattr(web_sessions, "utcnow", lambda: c.now)
    return c


class TestLogout:
    """N-02: logout ends that login, everywhere it was copied."""

    def test_copied_cookie_is_refused_after_logout(self, fresh_app, admin_user_seeded):
        app, _ctx, _db = fresh_app
        c = _login(app, admin_user_seeded)
        thief = _copy(c, app)
        assert _get(thief, "/admin/users").status_code == 200
        c.post("/logout", headers=ORIGIN, follow_redirects=False)
        r = _get(thief, "/admin/users")
        assert (r.status_code, r.headers["location"]) == (303, "/login")

    def test_other_browser_of_same_user_stays(self, fresh_app, admin_user_seeded):
        app, _ctx, _db = fresh_app
        a, b = _login(app, admin_user_seeded), _login(app, admin_user_seeded)
        a.post("/logout", headers=ORIGIN, follow_redirects=False)
        assert _get(b, "/admin/users").status_code == 200

    def test_logout_is_audited_with_the_user(self, fresh_app, admin_user_seeded):
        app, ctx, _db = fresh_app
        c = _login(app, admin_user_seeded)
        c.post("/logout", headers=ORIGIN, follow_redirects=False)
        (ev,) = ctx.audit_event_repo.search(limit=1, event_prefix="logout")
        assert ev.actor == "admin-test"

    def test_failed_logout_still_clears_the_browser_and_says_so(
            self, fresh_app, admin_user_seeded, monkeypatch):
        """Review: if the server cannot end the login, the browser is still
        logged out, the user is told plainly, and the audit trail records it."""
        app, ctx, _db = fresh_app
        c = _login(app, admin_user_seeded)
        real_delete = ctx.web_session_repo.delete

        def boom(*a, **k):
            raise ConnectionError("db hiccup")
        monkeypatch.setattr(ctx.web_session_repo, "delete", boom)
        r = c.post("/logout", headers=ORIGIN, follow_redirects=False)
        assert r.status_code == 503
        assert "Logout did not finish on the server" in r.text
        assert "seqsetup_session=null" in r.headers.get("set-cookie", "")
        monkeypatch.setattr(ctx.web_session_repo, "delete", real_delete)
        (ev,) = ctx.audit_event_repo.search(limit=1, event_prefix="logout")
        assert (ev.actor, ev.outcome) == ("admin-test", "failure")

    def test_login_page_logs_a_database_error(self, fresh_app, admin_user_seeded,
                                              monkeypatch, caplog):
        import logging
        app, ctx, _db = fresh_app
        c = _login(app, admin_user_seeded)

        def boom(*a, **k):
            raise ConnectionError("db down")
        monkeypatch.setattr(ctx.web_session_repo, "get", boom)
        caplog.set_level(logging.WARNING, logger="seqsetup.routes.auth")
        assert _get(c, "/login").status_code == 200
        assert any("login" in r.getMessage().lower() for r in caplog.records
                   if r.name == "seqsetup.routes.auth")

    def test_login_page_redirects_only_a_live_login(self, fresh_app, admin_user_seeded):
        app, ctx, _db = fresh_app
        c = _login(app, admin_user_seeded)
        assert _get(c, "/login").headers.get("location") == "/"
        ctx.web_session_repo.delete_for_user("admin-test")
        assert _get(c, "/login").status_code == 200


class TestLimits:
    """N-19: 30 minutes unused, 8 hours in all."""

    def test_idle_31_minutes_is_refused(self, fresh_app, admin_user_seeded, clock):
        app, _ctx, _db = fresh_app
        c = _login(app, admin_user_seeded)
        clock.advance(minutes=29)
        assert _get(c, "/").status_code == 200
        clock.advance(minutes=31)
        assert _get(c, "/").status_code == 303

    def test_active_login_ends_after_8_hours(self, fresh_app, admin_user_seeded, clock):
        app, _ctx, _db = fresh_app
        c = _login(app, admin_user_seeded)
        for _ in range(16):                             # 16 x 29 min = 7 h 44 min
            clock.advance(minutes=29)
            assert _get(c, "/").status_code == 200
        clock.advance(minutes=17)                       # 8 h 01 min
        assert _get(c, "/").status_code == 303


class TestEndedLoginResponses:
    """How an ended login is answered."""

    def test_htmx_request_keeps_the_page(self, fresh_app, admin_user_seeded):
        app, ctx, _db = fresh_app
        c = _login(app, admin_user_seeded)
        ctx.web_session_repo.delete_for_user("admin-test")
        r = c.post("/runs/new", headers={**ORIGIN, "HX-Request": "true"},
                   follow_redirects=False)
        assert r.status_code == 401
        assert r.headers["HX-Retarget"] == "#error-banner"
        assert r.headers["HX-Reswap"] == "innerHTML"
        assert "Your login has ended, so this was not saved." in r.text
        assert "What you typed is still on this page." in r.text
        assert '<a href="/login" target="_blank" rel="noopener" class="underline">Log in again</a>' in r.text

    def test_plain_request_goes_to_login(self, fresh_app, admin_user_seeded):
        app, ctx, _db = fresh_app
        c = _login(app, admin_user_seeded)
        ctx.web_session_repo.delete_for_user("admin-test")
        assert _get(c, "/").headers.get("location") == "/login"

    @pytest.mark.parametrize("repo,method", [("web_session_repo", "get"),
                                             ("web_session_repo", "touch"),
                                             ("local_user_repo", "get_by_username")])
    def test_database_error_is_503_never_200(self, fresh_app, admin_user_seeded, monkeypatch,
                                             repo, method):
        app, ctx, _db = fresh_app
        c = _login(app, admin_user_seeded)

        def boom(*a, **k):
            raise ConnectionError("db down")
        monkeypatch.setattr(getattr(ctx, repo), method, boom)
        assert _get(c, "/").status_code == 503
        r = _get(c, "/", headers={"HX-Request": "true"})
        assert r.status_code == 503
        assert (r.headers["HX-Retarget"], r.headers["HX-Reselect"]) == ("#error-banner", "unset")

    def test_htmx_messages_show_whole_even_with_hx_select(self, fresh_app, admin_user_seeded):
        """HX-Reselect: unset stops an inherited hx-select from blanking the message."""
        app, ctx, _db = fresh_app
        c = _login(app, admin_user_seeded)
        ctx.web_session_repo.delete_for_user("admin-test")
        r = c.post("/runs/new", headers={**ORIGIN, "HX-Request": "true"},
                   follow_redirects=False)
        assert r.headers["HX-Reselect"] == "unset"

    def test_htmx_read_gets_read_wording(self, fresh_app, admin_user_seeded):
        app, ctx, _db = fresh_app
        c = _login(app, admin_user_seeded)
        ctx.web_session_repo.delete_for_user("admin-test")
        r = _get(c, "/", headers={"HX-Request": "true"})
        assert r.status_code == 401
        assert "Your login has ended." in r.text
        assert "not saved" not in r.text and "What you typed" not in r.text
        assert '<a href="/login" target="_blank" rel="noopener" class="underline">Log in again</a>' in r.text

    def test_old_style_cookie_is_refused(self, fresh_app):
        app, _ctx, _db = fresh_app
        payload = base64.b64encode(json.dumps({"user": {
            "username": "admin-test", "display_name": "x", "role": "admin",
            "email": None}}).encode())
        cookie = TimestampSigner("x" * 64).sign(payload).decode()
        c = TestClient(app, base_url="http://testserver")
        c.cookies.set("seqsetup_session", cookie)
        assert _get(c, "/").headers.get("location") == "/login"


# --- Deleting or changing a database user (N-03, N-04, review 1 and 2) ---

def _admin_edit(admin, username, **fields):
    data = {"display_name": fields.get("display_name", "Target"),
            "email": fields.get("email", ""), "role": fields.get("role", "standard"),
            "password": fields.get("password", "")}
    return admin.post(f"/admin/users/{username}/edit", data=data, headers=ORIGIN)


def _change(admin, change):
    if change == "delete":
        return admin.delete("/admin/users/target-admin", headers=ORIGIN)
    if change == "demote":
        return _admin_edit(admin, "target-admin", role="standard")
    return _admin_edit(admin, "target-admin", role="admin", password="Brand-N3w-Pass!")


@pytest.fixture
def two_admins(fresh_app, admin_user_seeded):
    """admin-test (acting, logged in) and target-admin (the one changed)."""
    from seqsetup.models.local_user import LocalUser
    from seqsetup.models.user import UserRole
    app, ctx, _db = fresh_app
    u = LocalUser(username="target-admin", display_name="Target", role=UserRole.ADMIN)
    u.set_password("Target-Adm1n!")
    ctx.local_user_repo.save(u)
    target = {"username": "target-admin", "password": "Target-Adm1n!"}
    return app, ctx, _login(app, admin_user_seeded), target


class TestAccountChangesEndLogins:
    """N-03, N-04 and password reset end the user's open logins."""

    def test_deleted_user_is_refused(self, two_admins):
        app, ctx, admin, target = two_admins
        victim = _login(app, target)
        r = _change(admin, "delete")
        assert "User &#39;target-admin&#39; deleted. Their open logins were ended." in r.text
        assert _get(victim, "/").headers.get("location") == "/login"

    def test_demoted_admin_is_refused_and_relogin_is_standard(self, two_admins):
        app, ctx, admin, target = two_admins
        victim = _login(app, target)
        r = _change(admin, "demote")
        assert "User &#39;target-admin&#39; updated. Their open logins were ended." in r.text
        assert _get(victim, "/admin/users").headers.get("location") == "/login"
        again = _login(app, target)
        assert _get(again, "/admin/users").status_code == 403
        r = again.post("/admin/api-tokens/create", data={"name": "x", "expiry_days": "30"},
                       headers=ORIGIN)
        assert r.status_code == 403
        assert ctx.api_token_repo.list_all() == []

    def test_password_reset_ends_logins(self, two_admins):
        app, ctx, admin, target = two_admins
        victim = _login(app, target)
        _change(admin, "password")
        assert _get(victim, "/").headers.get("location") == "/login"

    def test_name_only_edit_keeps_logins(self, two_admins):
        app, ctx, admin, target = two_admins
        victim = _login(app, target)
        r = _admin_edit(admin, "target-admin", role="admin", display_name="Renamed")
        assert "User &#39;target-admin&#39; updated." in r.text
        assert "Their open logins were ended." not in r.text
        assert _get(victim, "/").status_code == 200

    def test_audit_records_the_ending(self, two_admins):
        app, ctx, admin, target = two_admins
        _login(app, target)
        _change(admin, "delete")
        (ev,) = ctx.audit_event_repo.search(limit=1, event_prefix="user.deleted")
        assert ev.details["sessions_ended"] is True
        assert ev.details["session_rows_removed"] == 1

    def test_name_only_edit_is_audited_without_ending(self, two_admins):
        app, ctx, admin, target = two_admins
        _admin_edit(admin, "target-admin", role="admin", display_name="Renamed")
        (ev,) = ctx.audit_event_repo.search(limit=1, event_prefix="user.updated")
        assert "sessions_ended" not in ev.details


class TestRaceWithLogin:
    """Review 1: a login checked just before the change is still refused."""

    @pytest.mark.parametrize("change", ["delete", "demote", "password"])
    def test_login_racing_a_change(self, two_admins, monkeypatch, change):
        import sys
        app, ctx, admin, target = two_admins
        auth_service = sys.modules["seqsetup.app"].auth_service
        real = auth_service.authenticate

        def racing(username, password):
            user = real(username, password)       # password checked, old record read
            _change(admin, change)                # the admin acts before the row is written
            return user

        monkeypatch.setattr(auth_service, "authenticate", racing)
        late = _login(app, target)
        assert _get(late, "/admin/users").headers.get("location") == "/login"


class TestCleanupFailure:
    """Review 2: if deleting the rows fails, the logins are still refused."""

    @pytest.mark.parametrize("change", ["delete", "demote", "password"])
    def test_refused_even_when_cleanup_fails(self, two_admins, monkeypatch, change):
        app, ctx, admin, target = two_admins
        victim = _login(app, target)

        def boom(*a, **k):
            raise ConnectionError("db hiccup")
        monkeypatch.setattr(ctx.web_session_repo, "delete_for_user", boom)
        r = _change(admin, change)
        assert r.status_code == 200 and "Their open logins were ended." in r.text
        assert _get(victim, "/").headers.get("location") == "/login"

    def test_repeated_demotion_leaves_them_refused(self, two_admins, monkeypatch):
        app, ctx, admin, target = two_admins
        victim = _login(app, target)

        def boom(*a, **k):
            raise ConnectionError("db hiccup")
        monkeypatch.setattr(ctx.web_session_repo, "delete_for_user", boom)
        _change(admin, "demote")
        _change(admin, "demote")
        assert _get(victim, "/").headers.get("location") == "/login"

    def test_cleanup_failure_is_audited(self, two_admins, monkeypatch):
        app, ctx, admin, target = two_admins

        def boom(*a, **k):
            raise ConnectionError("db hiccup")
        monkeypatch.setattr(ctx.web_session_repo, "delete_for_user", boom)
        _change(admin, "delete")
        (ev,) = ctx.audit_event_repo.search(limit=1, event_prefix="user.deleted")
        assert ev.details["sessions_ended"] is True
        assert ev.details["session_rows_removed"] is None
