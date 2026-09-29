"""Admin → Authentication (spec 2026-09-28 group 2b): no service account, the
warning, and the two test buttons."""

import ldap3
import pytest

from seqsetup.models.auth_config import AuthMethod
from tests.fake_directory import (ADMINS, AD_PATTERN, BASE, PASSWORD, USERS, FakeDirectory,
                                  ad_account, use_directory)

HX = {"Origin": "http://testserver", "HX-Request": "true"}
NOT_READY = "Directory sign-in is chosen but not fully set up, so everyone signs in with local accounts."
FORM = {"server_url": "ldaps://dc.example.org", "base_dn": BASE, "user_dn_pattern": AD_PATTERN,
        "user_group_dn": USERS, "admin_group_dn": ADMINS, "verify_ssl_cert": "on",
        "group_membership_attribute": "memberOf", "display_name_attribute": "displayName",
        "email_attribute": "mail", "connect_timeout": "10", "receive_timeout": "10"}


@pytest.fixture
def directory(monkeypatch):
    d = FakeDirectory()
    monkeypatch.setattr(ldap3, "Connection", d.connection)
    return d


def _choose(ctx, method):
    config = ctx.auth_config_repo.get()
    config.auth_method = method
    ctx.auth_config_repo.save(config)


def _page(client):
    r = client.get("/admin/authentication")
    assert r.status_code == 200
    return r.text


def _stored(ctx):
    """The stored LDAP settings, raw, as MongoDB holds them."""
    doc = ctx.auth_config_repo.collection.find_one({"_id": "auth_config"})
    return doc["config"]["ldap_config"]


def _events(ctx, prefix):
    return ctx.audit_event_repo.search(limit=50, event_prefix=prefix)


class TestSettingsForm:
    """The form keeps no service account and says what is missing."""

    def test_service_account_fields_are_gone(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        use_directory(ctx)
        page = _page(logged_in_client)
        for name in ("bind_dn", "bind_password", "user_search_base", "user_search_filter",
                     "username_attribute"):
            assert f'name="{name}"' not in page, name

    def test_group_attribute_is_shown_for_ldap_only(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        use_directory(ctx, method=AuthMethod.LDAP)
        assert 'name="group_membership_attribute"' in _page(logged_in_client)
        use_directory(ctx, method=AuthMethod.ACTIVE_DIRECTORY)
        assert 'name="group_membership_attribute"' not in _page(logged_in_client)

    def test_warning_lists_what_is_missing(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _choose(ctx, AuthMethod.ACTIVE_DIRECTORY)
        assert (f"{NOT_READY} Missing: server URL, base DN, sign-in name pattern, "
                f"Users group, Admins group.") in _page(logged_in_client)

    def test_no_warning_when_ready(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        use_directory(ctx)
        assert NOT_READY not in _page(logged_in_client)

    def test_no_warning_for_local_sign_in(self, logged_in_client):
        assert NOT_READY not in _page(logged_in_client)

    def test_save_keeps_no_secret(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        r = logged_in_client.post("/admin/settings/ldap", headers=HX, data={
            **FORM, "bind_dn": "cn=svc", "bind_password": "s3cret-Pw"})
        assert r.status_code == 200
        stored = _stored(ctx)
        assert "bind_dn" not in stored and "bind_password" not in stored
        assert "s3cret-Pw" not in str(stored)

    def test_save_drops_an_old_stored_password(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        ctx.auth_config_repo.collection.replace_one({"_id": "auth_config"}, {"_id": "auth_config", "config": {
            "auth_method": "active_directory",
            "ldap_config": {"server_url": "ldaps://old", "bind_password": "old-secret"}}},
            upsert=True)
        assert logged_in_client.post("/admin/settings/ldap", headers=HX, data=FORM).status_code == 200
        assert "old-secret" not in str(_stored(ctx))

    def test_save_refuses_a_bad_group_attribute(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        r = logged_in_client.post("/admin/settings/ldap", headers=HX, data={
            **FORM, "group_membership_attribute": "memberOf)(uid=*"})
        assert r.status_code == 400
        assert ctx.auth_config_repo.get().ldap_config.server_url == ""

    def test_save_accepts_a_upn_pattern(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        assert logged_in_client.post("/admin/settings/ldap", headers=HX, data=FORM).status_code == 200
        assert ctx.auth_config_repo.get().ldap_config.user_dn_pattern == AD_PATTERN

    def test_save_audit_names_the_groups(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        logged_in_client.post("/admin/settings/ldap", headers=HX, data=FORM)
        (event,) = _events(ctx, "auth.ldap_config.updated")
        assert (event.details["user_dn_pattern"], event.details["admin_group_dn"],
                event.details["user_group_dn"]) == (AD_PATTERN, ADMINS, USERS)
        assert "bind_dn" not in event.details


class TestButtons:
    """Test connection names the transport; Test sign-in shows role and groups."""

    def test_connection_test_names_the_transport(self, logged_in_client, fresh_app, directory):
        _app, ctx, _db = fresh_app
        use_directory(ctx)
        r = logged_in_client.post("/admin/settings/ldap/test", headers=HX)
        assert ("The server answered over an encrypted connection (TLS), and its "
                "certificate was checked.") in r.text

    def test_sign_in_test_when_not_ready(self, logged_in_client, fresh_app, directory):
        _app, ctx, _db = fresh_app
        _choose(ctx, AuthMethod.ACTIVE_DIRECTORY)
        r = logged_in_client.post("/admin/settings/ldap/test-auth", headers=HX, data={
            "test_username": "anna", "test_password": PASSWORD})
        assert ("Directory sign-in is not fully set up. Missing: server URL, base DN, "
                "sign-in name pattern, Users group, Admins group.") in r.text
        assert directory.connections == []

    def test_sign_in_test_with_local_sign_in(self, logged_in_client, directory):
        r = logged_in_client.post("/admin/settings/ldap/test-auth", headers=HX, data={
            "test_username": "anna", "test_password": PASSWORD})
        assert "Choose Active Directory or LDAP above first." in r.text

    def test_sign_in_test_shows_role_and_groups(self, logged_in_client, fresh_app, directory):
        _app, ctx, _db = fresh_app
        use_directory(ctx)
        ad_account(directory, groups=(USERS,))
        r = logged_in_client.post("/admin/settings/ldap/test-auth", headers=HX, data={
            "test_username": "anna", "test_password": PASSWORD})
        assert ("Signed in as Anna Svensson (anna@example.org). Role: standard. "
                "Admins group: no. Users group: yes.") in r.text

    def test_sign_in_test_names_the_refusal(self, logged_in_client, fresh_app, directory):
        _app, ctx, _db = fresh_app
        use_directory(ctx)
        ad_account(directory, groups=())
        r = logged_in_client.post("/admin/settings/ldap/test-auth", headers=HX, data={
            "test_username": "anna", "test_password": PASSWORD})
        assert ("The name and password are right, but the account is in neither the "
                "Users group nor the Admins group.") in r.text

    def test_sign_in_test_starts_no_session(self, logged_in_client, fresh_app, directory):
        _app, ctx, _db = fresh_app
        use_directory(ctx)
        ad_account(directory)
        before = ctx.web_session_repo.collection.count_documents({})
        logged_in_client.post("/admin/settings/ldap/test-auth", headers=HX, data={
            "test_username": "anna", "test_password": PASSWORD})
        assert ctx.web_session_repo.collection.count_documents({}) == before


class TestFallbackCheckbox:
    """Ticking Allow local user fallback saves it on its own, and never
    changes the sign-in method (2b handback, ESCALATE E1: the box had no
    trigger, while 2b's own text tells admins to turn it on)."""

    def test_the_checkbox_saves_itself(self, logged_in_client):
        page = _page(logged_in_client)
        start = page.index('name="allow_local_fallback"')
        box = page[page.rindex("<input", 0, start):page.index(">", start) + 1]
        assert 'hx-post="/admin/settings/auth-method"' in box
        assert 'hx-trigger="change"' in box

    @pytest.mark.parametrize("sent, fallback", [({"allow_local_fallback": "on"}, True), ({}, False)],
                             ids=["ticked", "unticked"])
    def test_the_checkbox_alone_keeps_the_method(self, logged_in_client, fresh_app, sent,
                                                 fallback):
        # The box sends only itself. The method must stay as it is, not
        # fall back to Local, which would switch directory sign-in off.
        _app, ctx, _db = fresh_app
        use_directory(ctx, fallback=not fallback)
        r = logged_in_client.post("/admin/settings/auth-method", headers=HX, data=sent)
        assert r.status_code == 200
        config = ctx.auth_config_repo.get()
        assert (config.auth_method, config.allow_local_fallback) == (
            AuthMethod.ACTIVE_DIRECTORY, fallback)

    def test_a_method_radio_still_changes_the_method(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        use_directory(ctx, fallback=False)
        logged_in_client.post("/admin/settings/auth-method", headers=HX,
                              data={"auth_method": "ldap", "allow_local_fallback": "on"})
        config = ctx.auth_config_repo.get()
        assert (config.auth_method, config.allow_local_fallback) == (AuthMethod.LDAP, True)

    def test_an_unknown_method_is_still_local(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        use_directory(ctx)
        logged_in_client.post("/admin/settings/auth-method", headers=HX,
                              data={"auth_method": "kerberos"})
        assert ctx.auth_config_repo.get().auth_method is AuthMethod.LOCAL
