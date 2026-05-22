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
