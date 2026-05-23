"""Tests for LDAP user_dn_pattern validation."""

import pytest

from seqsetup.models.auth_config import validate_user_dn_pattern


class TestValidateUserDnPattern:
    """The user_dn_pattern is a DN template used in LDAP binds. Disallow
    characters that could let an admin or attacker (with config write access)
    inject LDAP filter syntax or DN escapes."""

    def test_empty_pattern_allowed(self):
        # Empty means "fall back to search-based lookup" — fine.
        validate_user_dn_pattern("")

    def test_well_formed_pattern_allowed(self):
        validate_user_dn_pattern("CN={username},OU=Users,DC=example,DC=com")

    def test_pattern_without_username_placeholder_rejected(self):
        with pytest.raises(ValueError, match="username"):
            validate_user_dn_pattern("CN=admin,OU=Users,DC=example,DC=com")

    def test_wildcard_rejected(self):
        with pytest.raises(ValueError, match="disallowed"):
            validate_user_dn_pattern("CN=*,{username},DC=example,DC=com")

    def test_parens_rejected(self):
        with pytest.raises(ValueError, match="disallowed"):
            validate_user_dn_pattern("CN=({username}),DC=example,DC=com")

    def test_backslash_rejected(self):
        with pytest.raises(ValueError, match="disallowed"):
            validate_user_dn_pattern("CN={username}\\,OU=Users,DC=example,DC=com")

    def test_newline_rejected(self):
        with pytest.raises(ValueError, match="disallowed"):
            validate_user_dn_pattern("CN={username},\nOU=Users,DC=example,DC=com")

    def test_angle_brackets_rejected(self):
        with pytest.raises(ValueError, match="disallowed"):
            validate_user_dn_pattern("CN=<{username}>,DC=example,DC=com")


class TestVerifySslCertDefaults:
    """The verify_ssl_cert default must be True everywhere — dataclass
    default, from_dict() default, and admin form default. Inconsistencies
    silently disable TLS validation on existing configs (audit finding C3)."""

    def test_dataclass_default_is_true(self):
        from seqsetup.models.auth_config import LDAPConfig
        cfg = LDAPConfig()
        assert cfg.verify_ssl_cert is True

    def test_from_dict_default_is_true_when_field_missing(self):
        """A legacy MongoDB document missing this field loads with verification ON."""
        from seqsetup.models.auth_config import LDAPConfig
        # Simulate an existing doc that pre-dates the verify_ssl_cert field.
        legacy_doc = {
            "server_url": "ldaps://dc.example.com",
            "base_dn": "DC=example,DC=com",
            # verify_ssl_cert intentionally absent
        }
        cfg = LDAPConfig.from_dict(legacy_doc)
        assert cfg.verify_ssl_cert is True, (
            "Legacy configs missing verify_ssl_cert MUST default to True; "
            "anything else silently disables MITM protection."
        )

    def test_from_dict_explicit_false_preserved(self):
        """An admin-set False (for an internal-CA test scenario) round-trips."""
        from seqsetup.models.auth_config import LDAPConfig
        cfg = LDAPConfig.from_dict({"verify_ssl_cert": False})
        assert cfg.verify_ssl_cert is False
