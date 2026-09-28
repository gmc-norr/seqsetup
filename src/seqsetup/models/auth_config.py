"""Authentication configuration models."""

import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# Env var that overrides the stored LDAP bind_password at use time. Setting
# this in production keeps the actual secret out of the MongoDB document.
_BIND_PASSWORD_ENV = "SEQSETUP_LDAP_BIND_PASSWORD"


# Allowed characters in a user_dn_pattern: letters/digits, RDN separators
# (= and ,), names/spacing chars (- . _ space), '@' for an Active Directory
# user principal name, and the {username} marker. Anything else — wildcards,
# parentheses, backslashes, control chars — can be used to inject LDAP
# filter syntax or DN escapes, so reject them at config-save time.
_USER_DN_PATTERN_RE = re.compile(r"^[A-Za-z0-9=,\-\._ {}@]+$")

# The Active Directory shape: {username}@domain, a user principal name
# (spec 2026-09-28 group 2b).
_AD_PATTERN_RE = re.compile(r"^\{username\}@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")

# An LDAP attribute name. The group attribute goes into a search filter,
# so it must be a plain name, never filter syntax.
_ATTRIBUTE_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,127}$")


def validate_user_dn_pattern(value: str) -> None:
    """Raise ValueError if ``value`` contains chars unsafe for a DN template.

    An empty value can be saved; directory sign-in stays off until a
    pattern of the right shape is set (``AuthConfig.missing_settings``).
    """
    if not value:
        return
    if value.count("{username}") != 1:
        raise ValueError(
            "user_dn_pattern must contain the '{username}' placeholder exactly once"
        )
    if not _USER_DN_PATTERN_RE.match(value):
        bad = sorted(set(value) - set("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                      "abcdefghijklmnopqrstuvwxyz"
                                      "0123456789=,-._ {}@"))
        raise ValueError(
            f"user_dn_pattern contains disallowed characters "
            f"({', '.join(repr(c) for c in bad)}). "
            f"Allowed: letters, digits, '=', ',', '-', '.', '_', '@', space, "
            f"and '{{username}}'."
        )


def validate_attribute_name(value: str) -> None:
    """Raise ValueError unless ``value`` is a plain LDAP attribute name."""
    if not _ATTRIBUTE_NAME_RE.match(value or ""):
        raise ValueError(
            "An attribute name is a letter followed by letters, digits or '-' "
            "(at most 128 characters)."
        )


class AuthMethod(Enum):
    """Authentication method."""

    LOCAL = "local"
    LDAP = "ldap"
    ACTIVE_DIRECTORY = "active_directory"


_PATTERN_SHAPES = {
    AuthMethod.ACTIVE_DIRECTORY:
        "sign-in name pattern ({username}@domain for Active Directory)",
    AuthMethod.LDAP:
        "sign-in name pattern (a DN like uid={username},ou=people,dc=example,dc=org for LDAP)",
}


def pattern_fits(method: AuthMethod, pattern: str) -> bool:
    """True if ``pattern`` has the shape ``method`` signs in with: a user
    principal name for Active Directory, a DN for LDAP."""
    if not pattern:
        return False
    try:
        validate_user_dn_pattern(pattern)
    except ValueError:
        return False
    if method is AuthMethod.ACTIVE_DIRECTORY:
        return bool(_AD_PATTERN_RE.match(pattern))
    if method is AuthMethod.LDAP:
        return "=" in pattern
    return False


@dataclass
class LDAPConfig:
    """LDAP/Active Directory configuration."""

    # Connection settings
    server_url: str = ""  # e.g., "ldap://dc.example.com" or "ldaps://dc.example.com:636"
    use_ssl: bool = True
    # Cert validation defaults to True — disabling lets a MitM intercept
    # the bind password and user credentials over LDAPS. Admins can opt out
    # for testing against an internal CA the host doesn't yet trust, but
    # the production deployment should leave this on.
    verify_ssl_cert: bool = True
    base_dn: str = ""  # e.g., "DC=example,DC=com"

    # Bind credentials (for searching users)
    bind_dn: str = ""  # e.g., "CN=ServiceAccount,OU=Services,DC=example,DC=com"
    bind_password: str = ""  # Legacy MongoDB storage; production should use SEQSETUP_LDAP_BIND_PASSWORD

    # User search settings
    user_search_base: str = ""  # e.g., "OU=Users,DC=example,DC=com"
    user_search_filter: str = "(sAMAccountName={username})"  # AD default
    user_dn_pattern: str = ""  # Alternative: direct DN pattern like "CN={username},OU=Users,DC=example,DC=com"

    # Attribute mappings
    username_attribute: str = "sAMAccountName"  # AD default
    display_name_attribute: str = "displayName"
    email_attribute: str = "mail"

    # Group settings for role mapping
    admin_group_dn: str = ""  # e.g., "CN=SeqSetup-Admins,OU=Groups,DC=example,DC=com"
    user_group_dn: str = ""  # e.g., "CN=SeqSetup-Users,OU=Groups,DC=example,DC=com"
    group_membership_attribute: str = "memberOf"

    # Connection settings
    connect_timeout: int = 10  # seconds
    receive_timeout: int = 10  # seconds

    def effective_bind_password(self) -> str:
        """Return the bind password to use at LDAP-bind time.

        Prefers SEQSETUP_LDAP_BIND_PASSWORD env var; falls back to the stored
        field for backward compatibility. New deployments should set the env
        var and leave the stored field empty so the secret never lives in
        the database backup.
        """
        env_value = os.environ.get(_BIND_PASSWORD_ENV, "")
        return env_value or self.bind_password

    def to_dict(self) -> dict:
        """Convert to dictionary for storage."""
        return {
            "server_url": self.server_url,
            "use_ssl": self.use_ssl,
            "verify_ssl_cert": self.verify_ssl_cert,
            "base_dn": self.base_dn,
            "bind_dn": self.bind_dn,
            "bind_password": self.bind_password,
            "user_search_base": self.user_search_base,
            "user_search_filter": self.user_search_filter,
            "user_dn_pattern": self.user_dn_pattern,
            "username_attribute": self.username_attribute,
            "display_name_attribute": self.display_name_attribute,
            "email_attribute": self.email_attribute,
            "admin_group_dn": self.admin_group_dn,
            "user_group_dn": self.user_group_dn,
            "group_membership_attribute": self.group_membership_attribute,
            "connect_timeout": self.connect_timeout,
            "receive_timeout": self.receive_timeout,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "LDAPConfig":
        """Create from dictionary."""
        return cls(
            server_url=data.get("server_url", ""),
            use_ssl=data.get("use_ssl", True),
            # Default True to match the dataclass default (line 65). Existing
            # MongoDB documents missing this field load with verification ON
            # — the safe default. Without this match, every legacy config
            # would silently disable TLS validation.
            verify_ssl_cert=data.get("verify_ssl_cert", True),
            base_dn=data.get("base_dn", ""),
            bind_dn=data.get("bind_dn", ""),
            bind_password=data.get("bind_password", ""),
            user_search_base=data.get("user_search_base", ""),
            user_search_filter=data.get("user_search_filter", "(sAMAccountName={username})"),
            user_dn_pattern=data.get("user_dn_pattern", ""),
            username_attribute=data.get("username_attribute", "sAMAccountName"),
            display_name_attribute=data.get("display_name_attribute", "displayName"),
            email_attribute=data.get("email_attribute", "mail"),
            admin_group_dn=data.get("admin_group_dn", ""),
            user_group_dn=data.get("user_group_dn", ""),
            group_membership_attribute=data.get("group_membership_attribute", "memberOf"),
            connect_timeout=data.get("connect_timeout", 10),
            receive_timeout=data.get("receive_timeout", 10),
        )


@dataclass
class AuthConfig:
    """Overall authentication configuration."""

    # Primary auth method
    auth_method: AuthMethod = AuthMethod.LOCAL

    # Allow local fallback when LDAP is primary
    allow_local_fallback: bool = True

    # LDAP configuration (used when auth_method is LDAP or ACTIVE_DIRECTORY)
    ldap_config: LDAPConfig = field(default_factory=LDAPConfig)

    # Whether the connection test has passed since the settings were saved
    ldap_tested: bool = False

    def to_dict(self) -> dict:
        """Convert to dictionary for storage."""
        return {
            "auth_method": self.auth_method.value,
            "allow_local_fallback": self.allow_local_fallback,
            "ldap_config": self.ldap_config.to_dict(),
            "ldap_tested": self.ldap_tested,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AuthConfig":
        """Create from dictionary."""
        auth_method_str = data.get("auth_method", "local")
        try:
            auth_method = AuthMethod(auth_method_str)
        except ValueError:
            auth_method = AuthMethod.LOCAL

        ldap_config_data = data.get("ldap_config", {})
        ldap_config = LDAPConfig.from_dict(ldap_config_data) if ldap_config_data else LDAPConfig()

        return cls(
            auth_method=auth_method,
            allow_local_fallback=data.get("allow_local_fallback", True),
            ldap_config=ldap_config,
            ldap_tested=data.get("ldap_tested", False),
        )

    def missing_settings(self, method: Optional[AuthMethod] = None) -> list[str]:
        """What directory sign-in still needs, in the page's order (F24).

        Empty for Local sign-in. A pattern of the wrong shape for the method
        is listed with the shape it needs.
        """
        method = method or self.auth_method
        if method not in (AuthMethod.LDAP, AuthMethod.ACTIVE_DIRECTORY):
            return []
        ldap = self.ldap_config
        missing = []
        if not ldap.server_url:
            missing.append("server URL")
        if not ldap.base_dn:
            missing.append("base DN")
        if not ldap.user_dn_pattern:
            missing.append("sign-in name pattern")
        elif not pattern_fits(method, ldap.user_dn_pattern):
            missing.append(_PATTERN_SHAPES[method])
        if not ldap.user_group_dn:
            missing.append("Users group")
        if not ldap.admin_group_dn:
            missing.append("Admins group")
        if method is AuthMethod.LDAP and not _ATTRIBUTE_NAME_RE.match(
                ldap.group_membership_attribute or ""):
            missing.append("group attribute")
        return missing

    @property
    def is_ldap_enabled(self) -> bool:
        """Directory sign-in is on: a directory method is chosen and nothing
        it needs is missing. Computed every time from the saved settings."""
        return (self.auth_method in (AuthMethod.LDAP, AuthMethod.ACTIVE_DIRECTORY)
                and not self.missing_settings())
