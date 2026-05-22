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
# (= and ,), names/spacing chars (- . _ space), and the {username} marker.
# Anything else — wildcards, parentheses, backslashes, control chars — can
# be used to inject LDAP filter syntax or DN escapes, so reject them at
# config-save time. Existing stored values are not re-validated.
_USER_DN_PATTERN_RE = re.compile(r"^[A-Za-z0-9=,\-\._ {}]+$")


def validate_user_dn_pattern(value: str) -> None:
    """Raise ValueError if ``value`` contains chars unsafe for a DN template.

    An empty value is OK — that means "fall back to search-based lookup".
    """
    if not value:
        return
    if "{username}" not in value:
        raise ValueError(
            "user_dn_pattern must contain the '{username}' placeholder"
        )
    if not _USER_DN_PATTERN_RE.match(value):
        bad = sorted(set(value) - set("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                      "abcdefghijklmnopqrstuvwxyz"
                                      "0123456789=,-._ {}"))
        raise ValueError(
            f"user_dn_pattern contains disallowed characters "
            f"({', '.join(repr(c) for c in bad)}). "
            f"Allowed: letters, digits, '=', ',', '-', '.', '_', space, "
            f"and '{{username}}'."
        )


class AuthMethod(Enum):
    """Authentication method."""

    LOCAL = "local"
    LDAP = "ldap"
    ACTIVE_DIRECTORY = "active_directory"


@dataclass
class LDAPConfig:
    """LDAP/Active Directory configuration."""

    # Connection settings
    server_url: str = ""  # e.g., "ldap://dc.example.com" or "ldaps://dc.example.com:636"
    use_ssl: bool = True
    verify_ssl_cert: bool = False  # Set to True in production for proper certificate validation
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
            verify_ssl_cert=data.get("verify_ssl_cert", False),
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

    # Whether the config has been saved/tested
    ldap_configured: bool = False
    ldap_tested: bool = False

    def to_dict(self) -> dict:
        """Convert to dictionary for storage."""
        return {
            "auth_method": self.auth_method.value,
            "allow_local_fallback": self.allow_local_fallback,
            "ldap_config": self.ldap_config.to_dict(),
            "ldap_configured": self.ldap_configured,
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
            ldap_configured=data.get("ldap_configured", False),
            ldap_tested=data.get("ldap_tested", False),
        )

    @property
    def is_ldap_enabled(self) -> bool:
        """Check if LDAP/AD authentication is enabled."""
        return self.auth_method in (AuthMethod.LDAP, AuthMethod.ACTIVE_DIRECTORY) and self.ldap_configured
