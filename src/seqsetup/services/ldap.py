"""LDAP/Active Directory sign-in (spec 2026-09-28 group 2b).

SeqSetup never signs in to the directory as itself and stores no directory
password. It binds as the person signing in, with the name and password
they typed, and reads their own entry and group membership over that one
connection. The directory server decides group membership with its own DN
matching rules; SeqSetup never compares group DNs itself (review P1).
"""

import os
import re
from dataclasses import dataclass
from typing import Optional, Tuple

from ..models.auth_config import LDAPConfig, validate_attribute_name
from ..models.user import User, UserRole

# A directory sign-in name: plain characters only, so it cannot change the
# shape of the bind name it is put into.
_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

# Active Directory's LDAP_MATCHING_RULE_IN_CHAIN: membership through groups
# inside groups counts.
_IN_CHAIN = "1.2.840.113556.1.4.1941"

_NO_PASSWORD_CHECKED = "No password was checked; use Test sign-in for that."
CONNECTION_TLS_CHECKED = (
    "The server answered over an encrypted connection (TLS), and its certificate "
    "was checked. " + _NO_PASSWORD_CHECKED)
CONNECTION_TLS_UNCHECKED = (
    "The server answered over an encrypted connection (TLS), but its certificate "
    "was NOT checked (Verify certificate is off). " + _NO_PASSWORD_CHECKED)
CONNECTION_CLEARTEXT = (
    "The server answered over an UNENCRYPTED connection (allowed by "
    "SEQSETUP_LDAP_ALLOW_CLEARTEXT). Passwords would be sent readable. "
    + _NO_PASSWORD_CHECKED)

# What Test sign-in shows for each refusal. The sign-in page shows none of
# them: every failed sign-in there gets one message.
REFUSAL_MESSAGES = {
    "bad_name": ("That name has characters that are not allowed. "
                 "Use letters, digits, '.', '_' and '-'."),
    "directory_refused": "The directory refused that name and password.",
    "not_found": ("Signed in, but could not read the account's own entry. Check the "
                  "base DN and the sign-in name pattern (on Active Directory it must "
                  "match the account's userPrincipalName)."),
    "not_in_group": ("The name and password are right, but the account is in neither "
                     "the Users group nor the Admins group."),
}


def _dn_parts(dn: str) -> list:
    """The DN's components (RDNs), each a tuple of (type, value) pairs, both
    lower-cased. Values joined by ``+`` stay one component, in the order
    written: ``ou=people+dc=example`` is one component, never the two
    components ``ou=people,dc=example`` (plan review 1, P2). Each value
    keeps its escapes exactly as written, so an escaped comma stays part of
    its value. Raises on a DN that cannot be parsed."""
    from ldap3.utils.dn import parse_dn

    parts, current = [], []
    for attr, value, separator in parse_dn(dn, strip=True):
        current.append((attr.lower(), value.lower()))
        if separator != "+":
            parts.append(tuple(current))
            current = []
    if current:
        raise ValueError("a DN cannot end with '+'")
    return parts


def _dn_is_within(dn: str, base: str) -> bool:
    """True if ``dn`` is ``base`` or below it (spec 2026-09-28 group 2b, review P1).

    Compares whole parsed components, never strings split on commas. A DN
    that cannot be parsed is never inside. A value written with different
    escapes (``\\,`` against ``\\2c``), or ``+``-joined values written in
    another order, count as different, so the check fails on the safe
    side. Empty ``base`` means no constraint.
    """
    if not base:
        return True
    try:
        dn_parts, base_parts = _dn_parts(dn), _dn_parts(base)
    except Exception:
        return False
    if len(dn_parts) < len(base_parts):
        return False
    return dn_parts[len(dn_parts) - len(base_parts):] == base_parts


class LDAPError(Exception):
    """Raised when LDAP operations fail."""

    pass


class SignInRefused(LDAPError):
    """A refused directory sign-in. ``reason`` goes to the audit trail:
    bad_name, directory_refused, not_found, not_in_group or server_error.
    ``answered`` marks a server_error where the server was reached and
    ended a search with an error (plan review 1, P1)."""

    def __init__(self, reason: str, detail: str = "", *, answered: bool = False):
        self.reason = reason
        self.detail = detail
        self.answered = answered
        super().__init__(f"{reason}: {detail}" if detail else reason)

    @property
    def message(self) -> str:
        """What Test sign-in shows an admin."""
        if self.reason == "server_error":
            if self.answered:
                return f"The directory server answered with an error: {self.detail}"
            return f"Could not reach the directory server: {self.detail}"
        return REFUSAL_MESSAGES[self.reason]


@dataclass(frozen=True)
class DirectorySignIn:
    """A successful directory sign-in and the groups that decided its role."""

    user: User
    in_admins: bool
    in_users: bool


class LDAPService:
    """Directory sign-in as the user, for Active Directory or LDAP."""

    @staticmethod
    def _escape_ldap_filter(value: str) -> str:
        """
        Escape special characters in LDAP filter values to prevent injection.

        Per RFC 4515, these characters must be escaped:
        * ( ) \\ NUL

        Args:
            value: The value to escape

        Returns:
            Escaped value safe for use in LDAP filters
        """
        # Escape backslash first to avoid double-escaping
        value = value.replace("\\", "\\5c")
        value = value.replace("*", "\\2a")
        value = value.replace("(", "\\28")
        value = value.replace(")", "\\29")
        value = value.replace("\x00", "\\00")
        return value

    @staticmethod
    def _escape_dn_value(value: str) -> str:
        """Escape a value for safe substitution into a DN's RDN (RFC 4514).

        The login username flows into ``user_dn_pattern`` as an RDN value, so
        DN metacharacters must be escaped or a crafted username could
        relocate/restructure the bind DN (LDAP/DN injection, CWE-90). This
        is distinct from ``_escape_ldap_filter`` (RFC 4515 *filter* escaping).
        """
        from ldap3.utils.dn import escape_rdn

        return escape_rdn(value)

    def __init__(self, ldap_config: LDAPConfig, *, active_directory: bool):
        self.config = ldap_config
        self.active_directory = active_directory

    def _uses_tls(self) -> bool:
        """Whether ldap3 will actually use TLS; refuses cleartext unless opted in.

        ldap3 derives ssl from the URL scheme when one is present:
        Server('ldap://...', use_ssl=True) still binds in cleartext. So an
        explicit ldap:// scheme is cleartext regardless of use_ssl; ldaps://
        is TLS regardless of use_ssl; a bare host honours use_ssl.
        (Case-insensitive, so 'LDAPS://' is recognised too.)
        """
        url = self.config.server_url.lower()
        if url.startswith("ldaps://"):
            uses_tls = True
        elif url.startswith("ldap://"):
            uses_tls = False
        else:
            uses_tls = self.config.use_ssl
        # Refuse cleartext LDAP by default: every user's login password would
        # be sent in plaintext. Mirrors the LIMS plain-HTTP opt-in.
        if not uses_tls:
            allow = os.environ.get("SEQSETUP_LDAP_ALLOW_CLEARTEXT", "").lower() in ("1", "true", "yes")
            if not allow:
                raise LDAPError(
                    "Refusing to connect to LDAP over cleartext (no SSL/TLS): every user's "
                    "password would be sent in plaintext. Use an ldaps:// URL or a host "
                    "with use_ssl enabled. To allow cleartext on a trusted, isolated "
                    "network, set SEQSETUP_LDAP_ALLOW_CLEARTEXT=1 (not for production)."
                )
        return uses_tls

    def _get_server(self):
        """The ldap3 Server, with TLS and the certificate check as configured."""
        try:
            from ldap3 import Server, Tls
            import ssl
        except ImportError:
            raise LDAPError("ldap3 package is not installed. Run: pip install ldap3")

        uses_tls = self._uses_tls()
        tls = None
        if uses_tls:
            # CERT_REQUIRED in production; CERT_NONE only when Verify certificate is off.
            cert_validation = ssl.CERT_REQUIRED if self.config.verify_ssl_cert else ssl.CERT_NONE
            tls = Tls(validate=cert_validation)
        return Server(
            self.config.server_url,
            use_ssl=uses_tls,
            tls=tls,
            connect_timeout=self.config.connect_timeout,
        )

    def test_connection(self) -> Tuple[bool, str]:
        """Open a connection and bind nobody. The message names the transport
        actually used, decided by the same code that builds the connection
        (review P4)."""
        try:
            from ldap3 import Connection

            uses_tls = self._uses_tls()
            conn = Connection(self._get_server(), auto_referrals=False,
                              receive_timeout=self.config.receive_timeout)
            conn.open()
            conn.unbind()
        except LDAPError as e:
            return False, str(e)
        except Exception as e:
            return False, f"Could not reach the directory server: {e}"
        if not uses_tls:
            return True, CONNECTION_CLEARTEXT
        if self.config.verify_ssl_cert:
            return True, CONNECTION_TLS_CHECKED
        return True, CONNECTION_TLS_UNCHECKED

    def bind_name(self, username: str) -> str:
        """The name to bind as: the lower-cased ``username`` put into the
        sign-in name pattern. Any name outside the rule is refused
        (bad_name) before anything is sent to the server."""
        if not isinstance(username, str) or not _NAME_RE.match(username):
            raise SignInRefused("bad_name")
        name = username.lower()
        if not self.active_directory:
            # The name becomes an RDN value: escape for DN context (RFC 4514).
            # A no-op for the allowed characters; kept as a second guard.
            name = self._escape_dn_value(name)
        return self.config.user_dn_pattern.replace("{username}", name)

    def sign_in(self, username: str, password: str) -> DirectorySignIn:
        """Bind as the person, read their own entry and ask about both groups,
        all over one connection with their own name and password.

        Raises SignInRefused for every failure, with its reason.
        """
        bind = self.bind_name(username)
        if not password:
            # A simple bind with a name and no password can succeed as an
            # "unauthenticated bind"; never send one.
            raise SignInRefused("directory_refused", "empty password")
        try:
            from ldap3 import Connection, SIMPLE

            conn = Connection(
                self._get_server(),
                user=bind,
                password=password,
                authentication=SIMPLE,
                read_only=True,
                receive_timeout=self.config.receive_timeout,
                # Never send the password on to a server a referral names.
                auto_referrals=False,
            )
            try:
                if not conn.bind():
                    raise SignInRefused("directory_refused")
                display_name, email = self._own_entry(conn, bind)
                in_admins = self._is_member(conn, bind, self.config.admin_group_dn, "Admins")
                in_users = self._is_member(conn, bind, self.config.user_group_dn, "Users")
            finally:
                conn.unbind()
        except SignInRefused:
            raise
        except Exception as e:
            raise SignInRefused("server_error", str(e)) from e

        if in_admins:
            role = UserRole.ADMIN
        elif in_users:
            role = UserRole.STANDARD
        else:
            raise SignInRefused("not_in_group")
        name = username.lower()
        return DirectorySignIn(
            user=User(username=name, display_name=display_name or name, role=role,
                      email=email, source="ldap"),
            in_admins=in_admins,
            in_users=in_users,
        )

    def authenticate(self, username: str, password: str) -> User:
        """The signed-in User; raises SignInRefused."""
        return self.sign_in(username, password).user

    @staticmethod
    def _search(conn, what: str, **search) -> list:
        """Run one search and return its entries, only when the server
        finished it.

        ldap3 reports a search the server did not finish (a size limit, an
        access error, a referral) in ``conn.result`` without raising, and
        may still hand back some entries. Any result but success is a
        server_error, so a partial or refused answer never decides a
        sign-in (plan review 1, P1).
        """
        conn.search(**search)
        result = conn.result or {}
        code = result.get("result")
        if code != 0:
            raise SignInRefused(
                "server_error",
                f"{result.get('description') or 'no result'} (code {code}) while {what}",
                answered=True)
        return list(conn.entries)

    def _own_entry(self, conn, bind: str) -> Tuple[Optional[str], Optional[str]]:
        """(display name, email) from the person's own entry, read over their
        own connection. Exactly one entry must come back (not_found otherwise)."""
        from ldap3 import BASE, SUBTREE

        attributes = [self.config.display_name_attribute, self.config.email_attribute]
        what = "reading the account's own entry"
        if self.active_directory:
            entries = self._search(
                conn, what,
                search_base=self.config.base_dn,
                search_filter=f"(userPrincipalName={self._escape_ldap_filter(bind)})",
                search_scope=SUBTREE,
                attributes=attributes,
            )
        else:
            if not _dn_is_within(bind, self.config.base_dn):
                raise SignInRefused("not_found", "the sign-in DN is outside the base DN")
            entries = self._search(conn, what, search_base=bind, search_filter="(objectClass=*)",
                                   search_scope=BASE, attributes=attributes)
        if len(entries) != 1:
            raise SignInRefused("not_found")
        entry = entries[0]
        return (self._text(entry, self.config.display_name_attribute),
                self._text(entry, self.config.email_attribute))

    def _is_member(self, conn, bind: str, group_dn: str, label: str) -> bool:
        """Ask the directory whether the signed-in person is in ``group_dn``
        (the ``label`` group: Admins or Users). The server compares the DNs
        with its own matching rules (review P1)."""
        from ldap3 import BASE, NO_ATTRIBUTES, SUBTREE

        group = self._escape_ldap_filter(group_dn)
        what = f"checking the {label} group"
        if self.active_directory:
            entries = self._search(
                conn, what,
                search_base=self.config.base_dn,
                search_filter=(f"(&(userPrincipalName={self._escape_ldap_filter(bind)})"
                               f"(memberOf:{_IN_CHAIN}:={group}))"),
                search_scope=SUBTREE,
                attributes=NO_ATTRIBUTES,
            )
        else:
            attribute = self.config.group_membership_attribute
            validate_attribute_name(attribute)
            entries = self._search(conn, what, search_base=bind,
                                   search_filter=f"({attribute}={group})",
                                   search_scope=BASE, attributes=NO_ATTRIBUTES)
        return len(entries) == 1

    @staticmethod
    def _text(entry, attribute: str) -> Optional[str]:
        if hasattr(entry, attribute):
            value = getattr(entry, attribute)
            if value and value.value:
                return str(value.value)
        return None
