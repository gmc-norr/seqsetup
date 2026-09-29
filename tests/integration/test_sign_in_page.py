"""The sign-in page: one message, audited reasons, one name limit
(spec 2026-09-28 group 2b; review P3)."""

import ldap3
import pytest

from seqsetup.models.local_user import LocalUser
from seqsetup.models.user import UserRole
from seqsetup.services.auth import SIGN_IN_FAILED
from tests.fake_directory import ADMINS, PASSWORD, FakeDirectory, ad_account, use_directory

ORIGIN = {"Origin": "http://testserver"}
PW = "Cl1nical-Admin!"          # admin_user_seeded's password
LONG = "a" * 64


def _login(client, name, password):
    return client.post("/login/submit", data={"username": name, "password": password},
                       headers=ORIGIN, follow_redirects=False)


def _events(ctx, prefix):
    return ctx.audit_event_repo.search(limit=50, event_prefix=prefix)


@pytest.fixture
def directory(monkeypatch):
    d = FakeDirectory()
    monkeypatch.setattr(ldap3, "Connection", d.connection)
    return d


class TestOneMessage:
    """Every failed sign-in shows the same message; it never says which part failed."""

    def test_wrong_password_shows_the_one_message(self, client, admin_user_seeded):
        r = _login(client, "admin-test", "Wrong-Passw0rd!")
        assert r.status_code == 200 and SIGN_IN_FAILED in r.text

    def test_unknown_name_shows_the_same_message(self, client):
        r = _login(client, "nobody", PW)
        assert r.status_code == 200 and SIGN_IN_FAILED in r.text


class TestAudit:
    """The audit trail records why a sign-in failed, and where one came from."""

    def test_failure_is_audited_with_the_reason(self, client, admin_user_seeded, fresh_app):
        _app, ctx, _db = fresh_app
        _login(client, "admin-test", "Wrong-Passw0rd!")
        (event,) = _events(ctx, "login.failure")
        assert (event.actor, event.outcome, event.details["reason"]) == (
            "admin-test", "failure", "local_refused")

    def test_success_is_audited_with_the_name_and_source(self, client, admin_user_seeded,
                                                          fresh_app):
        _app, ctx, _db = fresh_app
        assert _login(client, "admin-test", PW).status_code == 303
        (event,) = _events(ctx, "login.success")
        assert (event.actor, event.details["source"]) == ("admin-test", "local")


class TestNameLimit:
    """One 64-character limit; a longer name is refused, never cut (review P3)."""

    def _seed(self, ctx, name):
        user = LocalUser(username=name, display_name="Long", role=UserRole.STANDARD)
        user.set_password(PW)
        ctx.local_user_repo.save(user)

    def test_65_characters_is_refused_not_cut(self, client, fresh_app):
        _app, ctx, _db = fresh_app
        self._seed(ctx, LONG)
        r = _login(client, LONG + "b", PW)
        assert r.status_code == 200 and SIGN_IN_FAILED in r.text
        (event,) = _events(ctx, "login.failure")
        assert event.details["reason"] == "bad_name"

    def test_64_characters_signs_in(self, client, fresh_app):
        _app, ctx, _db = fresh_app
        self._seed(ctx, LONG)
        assert _login(client, LONG, PW).status_code == 303

    def test_users_page_refuses_65_characters(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        logged_in_client.post("/admin/users/create", headers=ORIGIN, data={
            "username": LONG + "b", "display_name": "Long", "role": "standard",
            "password": "Strong-Passw0rd!"})
        assert not ctx.local_user_repo.exists(LONG + "b")

    def test_users_page_accepts_64_characters(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        logged_in_client.post("/admin/users/create", headers=ORIGIN, data={
            "username": LONG, "display_name": "Long", "role": "standard",
            "password": "Strong-Passw0rd!"})
        assert ctx.local_user_repo.exists(LONG)


class TestDirectorySignIn:
    """Directory accounts through the real sign-in page."""

    def test_directory_account_signs_in_with_its_role(self, client, fresh_app, directory):
        _app, ctx, _db = fresh_app
        use_directory(ctx)
        ad_account(directory, groups=(ADMINS,))
        assert _login(client, "Anna", PASSWORD).status_code == 303
        (event,) = _events(ctx, "login.success")
        assert (event.actor, event.details["source"]) == ("anna", "ldap")
        assert client.get("/admin/users").status_code == 200      # an admin

    def test_in_neither_group_is_refused_with_the_reason(self, client, fresh_app, directory):
        _app, ctx, _db = fresh_app
        use_directory(ctx, fallback=False)
        ad_account(directory, groups=())
        r = _login(client, "anna", PASSWORD)
        assert r.status_code == 200 and SIGN_IN_FAILED in r.text
        (event,) = _events(ctx, "login.failure")
        assert event.details["reason"] == "not_in_group"
        assert "local_tried" not in event.details

    def test_unreachable_directory_falls_back_to_local(self, client, fresh_app,
                                                       admin_user_seeded, directory):
        _app, ctx, _db = fresh_app
        use_directory(ctx, fallback=True)
        directory.unreachable = True
        assert _login(client, "admin-test", PW).status_code == 303
