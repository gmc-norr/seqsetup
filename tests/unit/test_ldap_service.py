"""Directory sign-in as the user (spec 2026-09-28 group 2b).

SeqSetup binds as the person signing in and never as itself; it reads the
person's own entry and asks the server about both groups over that one
connection. The fake directory answers searches only by their exact
(base, filter) pair, so group membership is decided "by the server".
"""

import ldap3
import pytest

from seqsetup.models.auth_config import LDAPConfig
from seqsetup.models.user import UserRole
from seqsetup.services.ldap import DirectorySignIn, LDAPError, LDAPService, SignInRefused
from tests.fake_directory import (ADMINS, AD_PATTERN, BASE, IN_CHAIN, LDAP_PATTERN, PASSWORD,
                                  USERS, FakeDirectory, FakeEntry, ad_account, ldap_account)


@pytest.fixture(autouse=True)
def _allow_cleartext_ldap_in_unit_tests(monkeypatch):
    """The transport-gate tests below build cleartext ldap:// servers; opt in
    so the gate (which fails closed in production) does not block them.
    Tests that assert the gate itself delete this var explicitly."""
    monkeypatch.setenv("SEQSETUP_LDAP_ALLOW_CLEARTEXT", "1")


@pytest.fixture
def directory(monkeypatch):
    d = FakeDirectory()
    monkeypatch.setattr(ldap3, "Connection", d.connection)
    return d


def _config(pattern, **changes):
    values = {"server_url": "ldaps://dc.example.org", "base_dn": BASE, "user_dn_pattern": pattern,
              "user_group_dn": USERS, "admin_group_dn": ADMINS}
    values.update(changes)
    return LDAPConfig(**values)


def _ad(**changes):
    return LDAPService(_config(AD_PATTERN, **changes), active_directory=True)


def _ldap(**changes):
    return LDAPService(_config(LDAP_PATTERN, **changes), active_directory=False)


def _searches(directory):
    return [entry[2] for entry in directory.log if entry[0] == "search"]


def _build_config() -> LDAPConfig:
    return LDAPConfig(
        server_url="ldap://test.example.com",
        use_ssl=False,
        base_dn="DC=example,DC=com",
        user_dn_pattern="CN={username},OU=Users,DC=example,DC=com",
        admin_group_dn="CN=SeqSetup-Admins,OU=Groups,DC=example,DC=com",
    )


class TestCleartextTransportGate:
    """Plaintext LDAP must be refused by default: every user's login password
    would otherwise traverse the wire in clear. Mirrors the LIMS plain-HTTP
    opt-in."""

    def test_cleartext_refused_without_optin(self, monkeypatch):
        monkeypatch.delenv("SEQSETUP_LDAP_ALLOW_CLEARTEXT", raising=False)
        svc = LDAPService(_build_config(), active_directory=False)  # ldap://, use_ssl=False
        with pytest.raises(LDAPError, match="(?i)cleartext|plaintext|tls|ssl"):
            svc._get_server()

    def test_cleartext_allowed_with_optin(self, monkeypatch):
        monkeypatch.setenv("SEQSETUP_LDAP_ALLOW_CLEARTEXT", "1")
        svc = LDAPService(_build_config(), active_directory=False)
        svc._get_server()  # no raise

    def test_ldaps_url_not_gated(self, monkeypatch):
        monkeypatch.delenv("SEQSETUP_LDAP_ALLOW_CLEARTEXT", raising=False)
        cfg = _build_config()
        cfg.server_url = "ldaps://secure.example.com"
        cfg.use_ssl = True
        svc = LDAPService(cfg, active_directory=False)
        svc._get_server()  # no raise — TLS transport

    def test_explicit_ldap_scheme_with_use_ssl_is_still_gated(self, monkeypatch):
        # ldap3 derives transport from the URL SCHEME, not the use_ssl kwarg:
        # Server('ldap://...', use_ssl=True) binds in CLEARTEXT (ssl=False).
        # The gate must key on the resolved transport, not trust use_ssl.
        monkeypatch.delenv("SEQSETUP_LDAP_ALLOW_CLEARTEXT", raising=False)
        cfg = _build_config()
        cfg.server_url = "ldap://dc.example.com"
        cfg.use_ssl = True
        svc = LDAPService(cfg, active_directory=False)
        with pytest.raises(LDAPError, match="(?i)cleartext|plaintext|tls|ssl"):
            svc._get_server()

    def test_bare_host_with_use_ssl_not_gated_and_resolves_to_ssl(self, monkeypatch):
        # No explicit scheme + use_ssl=True -> ldap3 honors use_ssl (ssl=True).
        monkeypatch.delenv("SEQSETUP_LDAP_ALLOW_CLEARTEXT", raising=False)
        cfg = _build_config()
        cfg.server_url = "dc.example.com"
        cfg.use_ssl = True
        server = LDAPService(cfg, active_directory=False)._get_server()  # no raise
        assert server.ssl is True  # actually uses TLS


class TestBindName:
    """A typed name becomes a bind name only through the pattern, lower-cased."""

    def test_ad_bind_name_is_the_upn(self):
        assert _ad().bind_name("Anna") == "anna@lab.example.org"

    def test_ldap_bind_name_is_the_dn(self):
        assert _ldap().bind_name("Anna") == "uid=anna,ou=people,dc=example,dc=org"

    @pytest.mark.parametrize("name", ["anna@lab.example.org", "eviluser,OU=Admins", "a+b",
                                      "anna smith", "", "åsa", "a" * 65])
    def test_other_names_are_refused(self, name):
        with pytest.raises(SignInRefused) as refused:
            _ad().bind_name(name)
        assert refused.value.reason == "bad_name"

    def test_64_characters_is_allowed(self):
        assert _ad().bind_name("a" * 64) == "a" * 64 + "@lab.example.org"


class TestOneConnectionAsTheUser:
    """No service account: one connection, with the person's own name and password."""

    def test_only_the_persons_own_credentials_are_used(self, directory):
        upn = ad_account(directory)
        _ad().sign_in("anna", PASSWORD)
        assert len(directory.connections) == 1
        made = directory.connections[0]
        assert (made["user"], made["password"], made["auto_referrals"]) == (upn, PASSWORD, False)

    def test_nothing_is_read_before_the_bind(self, directory):
        upn = ad_account(directory)
        _ad().sign_in("anna", PASSWORD)
        assert directory.log[0] == ("bind", upn)

    def test_empty_password_never_reaches_the_server(self, directory):
        ad_account(directory)
        with pytest.raises(SignInRefused) as refused:
            _ad().sign_in("anna", "")
        assert refused.value.reason == "directory_refused"
        assert directory.connections == []

    def test_bad_name_never_reaches_the_server(self, directory):
        with pytest.raises(SignInRefused):
            _ad().sign_in("anna,ou=admins", PASSWORD)
        assert directory.connections == []


class TestOwnEntry:
    """The person's own entry is read over their own connection."""

    def test_ad_reads_name_and_email(self, directory):
        ad_account(directory)
        user = _ad().sign_in("Anna", PASSWORD).user
        assert (user.username, user.display_name, user.email, user.source) == (
            "anna", "Anna Svensson", "anna@example.org", "ldap")

    def test_ldap_reads_name_and_email(self, directory):
        ldap_account(directory)
        user = _ldap().sign_in("anna", PASSWORD).user
        assert (user.username, user.display_name, user.email) == (
            "anna", "Anna Svensson", "anna@example.org")

    def test_ad_account_with_no_entry_is_not_found(self, directory):
        upn = ad_account(directory)
        directory.answer(BASE, f"(userPrincipalName={upn})")
        with pytest.raises(SignInRefused) as refused:
            _ad().sign_in("anna", PASSWORD)
        assert refused.value.reason == "not_found"

    def test_two_ad_entries_is_not_found(self, directory):
        upn = ad_account(directory)
        directory.answer(BASE, f"(userPrincipalName={upn})",
                         FakeEntry("cn=a," + BASE), FakeEntry("cn=b," + BASE))
        with pytest.raises(SignInRefused) as refused:
            _ad().sign_in("anna", PASSWORD)
        assert refused.value.reason == "not_found"

    def test_ldap_dn_outside_the_base_is_not_found(self, directory):
        service = LDAPService(_config("uid={username},ou=people,dc=other,dc=org"),
                              active_directory=False)
        directory.passwords["uid=anna,ou=people,dc=other,dc=org"] = PASSWORD
        with pytest.raises(SignInRefused) as refused:
            service.sign_in("anna", PASSWORD)
        assert refused.value.reason == "not_found"

    def test_missing_display_name_uses_the_name(self, directory):
        ad_account(directory, display_name=None)
        assert _ad().sign_in("anna", PASSWORD).user.display_name == "anna"


class TestGroups:
    """Two required groups; the server decides membership (F23, review P1)."""

    @pytest.mark.parametrize("groups, role", [
        ((ADMINS,), UserRole.ADMIN), ((USERS,), UserRole.STANDARD),
        ((ADMINS, USERS), UserRole.ADMIN),
    ])
    def test_ad_role_comes_from_the_groups(self, directory, groups, role):
        ad_account(directory, groups=groups)
        assert _ad().sign_in("anna", PASSWORD).user.role is role

    @pytest.mark.parametrize("groups, role", [
        ((ADMINS,), UserRole.ADMIN), ((USERS,), UserRole.STANDARD),
        ((ADMINS, USERS), UserRole.ADMIN),
    ])
    def test_ldap_role_comes_from_the_groups(self, directory, groups, role):
        ldap_account(directory, groups=groups)
        assert _ldap().sign_in("anna", PASSWORD).user.role is role

    def test_ad_in_neither_group_is_refused(self, directory):
        ad_account(directory, groups=())
        with pytest.raises(SignInRefused) as refused:
            _ad().sign_in("anna", PASSWORD)
        assert refused.value.reason == "not_in_group"

    def test_ldap_in_neither_group_is_refused(self, directory):
        ldap_account(directory, groups=())
        with pytest.raises(SignInRefused) as refused:
            _ldap().sign_in("anna", PASSWORD)
        assert refused.value.reason == "not_in_group"

    def test_ad_counts_groups_inside_groups(self, directory):
        upn = ad_account(directory)
        _ad().sign_in("anna", PASSWORD)
        asked = _searches(directory)
        assert f"(&(userPrincipalName={upn})(memberOf:{IN_CHAIN}:={ADMINS}))" in asked
        assert f"(&(userPrincipalName={upn})(memberOf:{IN_CHAIN}:={USERS}))" in asked

    def test_ldap_asks_the_server_about_each_group(self, directory):
        dn = ldap_account(directory)
        _ldap().sign_in("anna", PASSWORD)
        asked = [(e[1], e[2], e[3]) for e in directory.log if e[0] == "search"]
        assert (dn, f"(memberOf={ADMINS})", "BASE") in asked
        assert (dn, f"(memberOf={USERS})", "BASE") in asked

    def test_a_similar_group_name_does_not_count(self, directory):
        # "cn=SeqSetup\, Admins" and "cn=SeqSetup\,Admins" are two groups; the
        # old string compare made them equal (review P1). The entry lists only
        # the other one, and the server is asked about the configured one.
        configured = "cn=SeqSetup\\, Admins,ou=groups,dc=example,dc=org"
        other = "cn=SeqSetup\\,Admins,ou=groups,dc=example,dc=org"
        dn = ldap_account(directory, groups=(USERS,), member_of_listed=[other, USERS])
        directory.answer(dn, "(memberOf=cn=SeqSetup\\5c,Admins,ou=groups,dc=example,dc=org)",
                         FakeEntry(dn))
        result = _ldap(admin_group_dn=configured).sign_in("anna", PASSWORD)
        assert (result.in_admins, result.user.role) == (False, UserRole.STANDARD)
        assert ("(memberOf=cn=SeqSetup\\5c, Admins,ou=groups,dc=example,dc=org)"
                in _searches(directory))

    def test_group_dn_is_filter_escaped(self, directory):
        upn = ad_account(directory)
        _ad(admin_group_dn="cn=Lab (Seq)*,ou=groups,dc=example,dc=org").sign_in("anna", PASSWORD)
        assert (f"(&(userPrincipalName={upn})(memberOf:{IN_CHAIN}:="
                f"cn=Lab \\28Seq\\29\\2a,ou=groups,dc=example,dc=org))") in _searches(directory)

    def test_sign_in_reports_both_groups(self, directory):
        ad_account(directory, groups=(USERS,))
        result = _ad().sign_in("anna", PASSWORD)
        assert isinstance(result, DirectorySignIn)
        assert (result.in_admins, result.in_users) == (False, True)


class TestServerErrors:
    """Every directory failure is a refusal with a reason, never a crash."""

    def test_wrong_password_is_directory_refused(self, directory):
        ad_account(directory)
        with pytest.raises(SignInRefused) as refused:
            _ad().sign_in("anna", "Wrong-Horse-7")
        assert refused.value.reason == "directory_refused"

    def test_unreachable_server_is_a_server_error(self, directory):
        ad_account(directory)
        directory.unreachable = True
        with pytest.raises(SignInRefused) as refused:
            _ad().sign_in("anna", PASSWORD)
        assert refused.value.reason == "server_error"
        assert refused.value.message.startswith("Could not reach the directory server:")

    def test_refused_cleartext_is_a_server_error(self, directory, monkeypatch):
        monkeypatch.delenv("SEQSETUP_LDAP_ALLOW_CLEARTEXT", raising=False)
        ad_account(directory)
        with pytest.raises(SignInRefused) as refused:
            _ad(server_url="ldap://dc.example.org").sign_in("anna", PASSWORD)
        assert refused.value.reason == "server_error"
        assert "SEQSETUP_LDAP_ALLOW_CLEARTEXT" in refused.value.message
        assert directory.connections == []


def _answered_error(refused):
    return (refused.value.reason, refused.value.message)


class TestUnfinishedSearches:
    """A search the server did not finish is a server error, even when some
    entries came back (plan review 1, P1). ldap3 reports it in conn.result
    and does not raise, so SeqSetup must check every search."""

    def test_a_partial_admins_answer_does_not_make_an_admin(self, directory):
        upn = ad_account(directory, groups=())
        directory.answer(BASE, f"(&(userPrincipalName={upn})(memberOf:{IN_CHAIN}:={ADMINS}))",
                         FakeEntry(f"cn=anna,ou=staff,{BASE}"), result=4)
        with pytest.raises(SignInRefused) as refused:
            _ad().sign_in("anna", PASSWORD)
        assert _answered_error(refused) == ("server_error", (
            "The directory server answered with an error: sizeLimitExceeded (code 4) "
            "while checking the Admins group"))

    def test_access_denied_on_the_users_group_is_not_not_in_group(self, directory):
        upn = ad_account(directory, groups=())
        directory.answer(BASE, f"(&(userPrincipalName={upn})(memberOf:{IN_CHAIN}:={USERS}))",
                         result=50)
        with pytest.raises(SignInRefused) as refused:
            _ad().sign_in("anna", PASSWORD)
        assert _answered_error(refused) == ("server_error", (
            "The directory server answered with an error: insufficientAccessRights (code 50) "
            "while checking the Users group"))

    def test_access_denied_on_the_admins_group_is_not_a_standard_sign_in(self, directory):
        upn = ad_account(directory, groups=(ADMINS, USERS))
        directory.answer(BASE, f"(&(userPrincipalName={upn})(memberOf:{IN_CHAIN}:={ADMINS}))",
                         result=50)
        with pytest.raises(SignInRefused) as refused:
            _ad().sign_in("anna", PASSWORD)
        assert refused.value.reason == "server_error"

    def test_a_partial_own_entry_answer_is_a_server_error(self, directory):
        # One entry came back, but the server stopped early: there may be more.
        upn = ad_account(directory)
        directory.answer(BASE, f"(userPrincipalName={upn})",
                         FakeEntry(f"cn=anna,ou=staff,{BASE}",
                                   {"displayName": "Anna Svensson", "mail": "anna@example.org"}),
                         result=4)
        with pytest.raises(SignInRefused) as refused:
            _ad().sign_in("anna", PASSWORD)
        assert _answered_error(refused) == ("server_error", (
            "The directory server answered with an error: sizeLimitExceeded (code 4) "
            "while reading the account's own entry"))

    def test_ldap_access_denied_on_the_own_entry_is_not_not_found(self, directory):
        dn = ldap_account(directory)
        directory.answer(dn, "(objectClass=*)", result=50)
        with pytest.raises(SignInRefused) as refused:
            _ldap().sign_in("anna", PASSWORD)
        assert refused.value.reason == "server_error"

    def test_ldap_referral_on_a_group_does_not_make_an_admin(self, directory):
        dn = ldap_account(directory, groups=())
        directory.answer(dn, f"(memberOf={ADMINS})", FakeEntry(dn), result=10)
        with pytest.raises(SignInRefused) as refused:
            _ldap().sign_in("anna", PASSWORD)
        assert _answered_error(refused) == ("server_error", (
            "The directory server answered with an error: referral (code 10) "
            "while checking the Admins group"))


class TestTestConnection:
    """Test connection binds nobody and names the transport it used (review P4)."""

    def test_tls_with_the_certificate_checked(self, directory):
        assert _ad().test_connection() == (True, (
            "The server answered over an encrypted connection (TLS), and its certificate "
            "was checked. No password was checked; use Test sign-in for that."))

    def test_tls_without_the_certificate_check(self, directory):
        assert _ad(verify_ssl_cert=False).test_connection() == (True, (
            "The server answered over an encrypted connection (TLS), but its certificate "
            "was NOT checked (Verify certificate is off). No password was checked; use "
            "Test sign-in for that."))

    def test_cleartext_opt_in_says_unencrypted(self, directory, monkeypatch):
        monkeypatch.setenv("SEQSETUP_LDAP_ALLOW_CLEARTEXT", "1")
        assert _ad(server_url="ldap://dc.example.org").test_connection() == (True, (
            "The server answered over an UNENCRYPTED connection (allowed by "
            "SEQSETUP_LDAP_ALLOW_CLEARTEXT). Passwords would be sent readable. No password "
            "was checked; use Test sign-in for that."))

    def test_it_binds_nobody(self, directory):
        _ad().test_connection()
        assert directory.connections[0]["user"] is None
        assert ("open",) in directory.log
        assert not [entry for entry in directory.log if entry[0] == "bind"]

    def test_unreachable_server(self, directory):
        directory.unreachable = True
        ok, message = _ad().test_connection()
        assert not ok and message.startswith("Could not reach the directory server:")


class TestNoServiceAccount:
    """SeqSetup never signs in to the directory as itself (N-17)."""

    def test_the_service_account_code_is_gone(self):
        for name in ("_bind_connection", "_get_user_dn", "_get_user_groups",
                     "_determine_role", "search_users"):
            assert not hasattr(LDAPService, name), name


class TestEffectiveBindPassword:
    """The LDAP bind password must prefer the env var over the stored field
    so production deployments can keep the secret out of MongoDB.
    (Removed in Task 6, with the field.)"""

    def test_env_var_overrides_stored_password(self, monkeypatch):
        monkeypatch.setenv("SEQSETUP_LDAP_BIND_PASSWORD", "env-secret")
        cfg = LDAPConfig(bind_dn="CN=svc,DC=ex", bind_password="stored-secret")
        assert cfg.effective_bind_password() == "env-secret"

    def test_falls_back_to_stored_when_env_absent(self, monkeypatch):
        monkeypatch.delenv("SEQSETUP_LDAP_BIND_PASSWORD", raising=False)
        cfg = LDAPConfig(bind_dn="CN=svc,DC=ex", bind_password="stored-secret")
        assert cfg.effective_bind_password() == "stored-secret"

    def test_empty_env_value_treated_as_unset(self, monkeypatch):
        monkeypatch.setenv("SEQSETUP_LDAP_BIND_PASSWORD", "")
        cfg = LDAPConfig(bind_dn="CN=svc,DC=ex", bind_password="stored-secret")
        assert cfg.effective_bind_password() == "stored-secret"
