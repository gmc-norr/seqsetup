"""Directory settings: the sign-in name pattern, what is missing, and when
directory sign-in is on (spec 2026-09-28 group 2b, F23/F24)."""

import pytest

from seqsetup.models.auth_config import (AuthConfig, AuthMethod, LDAPConfig, pattern_fits,
                                         validate_attribute_name, validate_user_dn_pattern)

AD = AuthMethod.ACTIVE_DIRECTORY
LDAP = AuthMethod.LDAP
AD_PATTERN = "{username}@lab.example.org"
LDAP_PATTERN = "uid={username},ou=people,dc=example,dc=org"
USERS = "cn=SeqSetup-Users,ou=groups,dc=example,dc=org"
ADMINS = "cn=SeqSetup-Admins,ou=groups,dc=example,dc=org"
AD_SHAPE = "sign-in name pattern ({username}@domain for Active Directory)"
LDAP_SHAPE = ("sign-in name pattern (a DN like uid={username},ou=people,dc=example,dc=org "
              "for LDAP)")


def _ready(method, **changes):
    ldap = LDAPConfig(
        server_url="ldaps://dc.example.org", base_dn="dc=example,dc=org",
        user_dn_pattern=AD_PATTERN if method is AD else LDAP_PATTERN,
        user_group_dn=USERS, admin_group_dn=ADMINS,
    )
    for name, value in changes.items():
        setattr(ldap, name, value)
    return AuthConfig(auth_method=method, ldap_config=ldap)


class TestSignInNamePattern:
    """Active Directory signs in as {username}@domain; LDAP as a DN."""

    def test_upn_pattern_can_be_saved(self):
        validate_user_dn_pattern(AD_PATTERN)

    def test_username_twice_is_refused(self):
        with pytest.raises(ValueError, match="exactly once"):
            validate_user_dn_pattern("uid={username},cn={username},dc=example,dc=org")

    @pytest.mark.parametrize("method, pattern, fits", [
        (AD, AD_PATTERN, True),
        (AD, LDAP_PATTERN, False),
        (AD, "{username}@localhost", False),
        (AD, "{username}@lab.example.org,dc=org", False),
        (LDAP, LDAP_PATTERN, True),
        (LDAP, AD_PATTERN, False),
        (LDAP, "", False),
        (AuthMethod.LOCAL, LDAP_PATTERN, False),
    ])
    def test_pattern_fits_the_method(self, method, pattern, fits):
        assert pattern_fits(method, pattern) is fits


class TestMissingSettings:
    """Directory sign-in is on only when nothing it needs is missing (F24)."""

    @pytest.mark.parametrize("method", [AD, LDAP])
    def test_ready_config_misses_nothing(self, method):
        config = _ready(method)
        assert config.missing_settings() == [] and config.is_ldap_enabled

    @pytest.mark.parametrize("field, label", [
        ("server_url", "server URL"), ("base_dn", "base DN"),
        ("user_dn_pattern", "sign-in name pattern"),
        ("user_group_dn", "Users group"), ("admin_group_dn", "Admins group"),
    ])
    def test_each_missing_piece_is_named_and_keeps_it_off(self, field, label):
        config = _ready(AD, **{field: ""})
        assert config.missing_settings() == [label]
        assert not config.is_ldap_enabled

    @pytest.mark.parametrize("method, pattern, label", [
        (AD, LDAP_PATTERN, AD_SHAPE), (LDAP, AD_PATTERN, LDAP_SHAPE),
    ])
    def test_wrong_shape_names_the_right_shape(self, method, pattern, label):
        assert _ready(method, user_dn_pattern=pattern).missing_settings() == [label]

    def test_bad_group_attribute_is_missing_for_ldap_only(self):
        bad = "memberOf)(uid=*"
        assert _ready(LDAP, group_membership_attribute=bad).missing_settings() == ["group attribute"]
        assert _ready(AD, group_membership_attribute=bad).missing_settings() == []

    def test_everything_missing_in_order(self):
        assert AuthConfig(auth_method=AD).missing_settings() == [
            "server URL", "base DN", "sign-in name pattern", "Users group", "Admins group"]

    def test_local_method_is_never_directory_sign_in(self):
        config = _ready(AD)
        config.auth_method = AuthMethod.LOCAL
        assert not config.is_ldap_enabled and config.missing_settings() == []

    def test_old_configured_flag_no_longer_turns_it_on(self):
        config = AuthConfig.from_dict({
            "auth_method": "ldap", "ldap_configured": True,
            "ldap_config": {"server_url": "ldaps://x", "base_dn": "dc=x"},
        })
        assert not config.is_ldap_enabled
        assert "ldap_configured" not in config.to_dict()


class TestGroupAttributeName:
    """The group attribute goes into a search filter, so it must be a plain name."""

    @pytest.mark.parametrize("name", ["memberOf", "isMemberOf", "groupMembership"])
    def test_plain_names_are_accepted(self, name):
        validate_attribute_name(name)

    @pytest.mark.parametrize("name", ["", "memberOf)(uid=*", "member of", "1memberOf", "a" * 129])
    def test_anything_else_is_refused(self, name):
        with pytest.raises(ValueError):
            validate_attribute_name(name)


class TestNoServiceAccountSettings:
    """No bind DN or password is kept anywhere (N-17)."""

    REMOVED = ("bind_dn", "bind_password", "user_search_base", "user_search_filter",
               "username_attribute")

    def test_removed_keys_are_not_written(self):
        written = LDAPConfig().to_dict()
        assert [key for key in self.REMOVED if key in written] == []

    def test_an_old_document_loads_and_saves_without_them(self):
        old = {"server_url": "ldaps://x", "bind_dn": "cn=svc", "bind_password": "old-secret"}
        again = LDAPConfig.from_dict(old).to_dict()
        assert again["server_url"] == "ldaps://x"
        assert "old-secret" not in str(again)
