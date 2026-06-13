"""LDAP/Active Directory authentication service."""

from typing import Optional, Tuple

from ..models.auth_config import AuthConfig, LDAPConfig
from ..models.user import User, UserRole


def _normalize_dn(dn: str) -> str:
    """Lowercase + collapse-whitespace canonicalisation for DN comparison.

    LDAP DNs are case-insensitive for both attribute names and (in most
    practical AD/OpenLDAP setups) the RDN values we care about for the
    base-tree check. We compare suffixes after stripping leading/trailing
    whitespace from each comma-delimited RDN. Anything that wants real
    RFC 4514 parsing should use ldap3.utils.dn.parse_dn; the structural
    check we need here is "does ``dn`` end with ``base``", which the
    lowercased suffix comparison handles correctly across whitespace
    variants.
    """
    return ",".join(rdn.strip().lower() for rdn in dn.split(","))


def _dn_is_within(dn: str, base: str) -> bool:
    """True if ``dn`` is the same as ``base`` or a descendant of it.

    Used to refuse a directory entry whose DN points outside the
    configured search base. Both sides are normalised before comparison.
    Empty ``base`` is treated as "no constraint" (the LDAP root); the
    caller should pass the actual configured base_dn, not "".
    """
    if not base:
        return True
    dn_n = _normalize_dn(dn)
    base_n = _normalize_dn(base)
    if dn_n == base_n:
        return True
    return dn_n.endswith("," + base_n)


class LDAPError(Exception):
    """Raised when LDAP operations fail."""

    pass


class LDAPService:
    """Service for authenticating users against LDAP/Active Directory."""

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
        DN metacharacters (',', '+', '=', '"', '\\', '<', '>', ';', leading/
        trailing space, leading '#') must be escaped or a crafted username
        could relocate/restructure the bind DN (LDAP/DN injection, CWE-90).
        This is distinct from ``_escape_ldap_filter`` (RFC 4515 *filter*
        escaping) — using the filter escaper on a DN leaves commas/equals
        unescaped.
        """
        from ldap3.utils.dn import escape_rdn

        return escape_rdn(value)

    def __init__(self, ldap_config: LDAPConfig):
        """
        Initialize LDAP service.

        Args:
            ldap_config: LDAP configuration settings
        """
        self.config = ldap_config
        self._connection = None

    def _get_server(self):
        """Get LDAP server configuration."""
        try:
            from ldap3 import Server, Tls
            import ssl
        except ImportError:
            raise LDAPError("ldap3 package is not installed. Run: pip install ldap3")

        # Determine the transport ldap3 will ACTUALLY use. ldap3 derives ssl from
        # the URL scheme when one is present: Server('ldap://...', use_ssl=True)
        # still binds in cleartext (ssl=False, port 389). So an explicit ldap://
        # scheme is cleartext regardless of use_ssl; an explicit ldaps:// is TLS
        # regardless of use_ssl; and a bare host honours use_ssl. (Case-insensitive
        # so 'LDAPS://' is recognised too.)
        url = self.config.server_url.lower()
        if url.startswith("ldaps://"):
            uses_tls = True
        elif url.startswith("ldap://"):
            uses_tls = False
        else:
            uses_tls = self.config.use_ssl

        # Refuse cleartext LDAP by default: with no TLS (and no StartTLS path
        # exists), the bind password AND every user's login password would be
        # sent in plaintext. Mirror the LIMS plain-HTTP opt-in so an isolated/
        # trusted network can deliberately allow it.
        if not uses_tls:
            import os
            allow = os.environ.get("SEQSETUP_LDAP_ALLOW_CLEARTEXT", "").lower() in ("1", "true", "yes")
            if not allow:
                raise LDAPError(
                    "Refusing to connect to LDAP over cleartext (no SSL/TLS): the bind "
                    "and user passwords would be sent in plaintext. Use an ldaps:// URL "
                    "or a host with use_ssl enabled. To allow cleartext on a trusted, "
                    "isolated network, set SEQSETUP_LDAP_ALLOW_CLEARTEXT=1 (not for production)."
                )

        tls = None
        if uses_tls:
            # Use CERT_REQUIRED for production security, CERT_NONE for development/testing
            cert_validation = ssl.CERT_REQUIRED if self.config.verify_ssl_cert else ssl.CERT_NONE
            tls = Tls(validate=cert_validation)

        return Server(
            self.config.server_url,
            use_ssl=uses_tls,
            tls=tls,
            connect_timeout=self.config.connect_timeout,
        )

    def _bind_connection(self):
        """Create a bound connection using service account credentials."""
        try:
            from ldap3 import Connection, SIMPLE
        except ImportError:
            raise LDAPError("ldap3 package is not installed. Run: pip install ldap3")

        server = self._get_server()
        conn = Connection(
            server,
            user=self.config.bind_dn,
            password=self.config.effective_bind_password(),
            authentication=SIMPLE,
            read_only=True,
            receive_timeout=self.config.receive_timeout,
        )

        if not conn.bind():
            raise LDAPError(f"Failed to bind to LDAP server: {conn.last_error}")

        return conn

    def test_connection(self) -> Tuple[bool, str]:
        """
        Test LDAP connection with configured credentials.

        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            conn = self._bind_connection()
            conn.unbind()
            return True, "Successfully connected to LDAP server"
        except LDAPError as e:
            return False, str(e)
        except Exception as e:
            return False, f"Connection failed: {e}"

    def _get_user_dn(self, username: str, conn) -> Optional[str]:
        """
        Find user DN by username.

        Args:
            username: Username to search for
            conn: LDAP connection

        Returns:
            User DN if found, None otherwise
        """
        try:
            from ldap3 import SUBTREE
        except ImportError:
            raise LDAPError("ldap3 package is not installed")

        # If direct DN pattern is configured, use it — the username becomes an
        # RDN value, so escape it for DN context (RFC 4514), not filter context.
        if self.config.user_dn_pattern:
            return self.config.user_dn_pattern.replace(
                "{username}", self._escape_dn_value(username)
            )

        # Otherwise search for the user — escape for LDAP filter context (RFC 4515).
        safe_username = self._escape_ldap_filter(username)
        search_filter = self.config.user_search_filter.replace("{username}", safe_username)
        search_base = self.config.user_search_base or self.config.base_dn

        conn.search(
            search_base=search_base,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=[
                self.config.username_attribute,
                self.config.display_name_attribute,
                self.config.email_attribute,
                self.config.group_membership_attribute,
            ],
        )

        if conn.entries:
            entry_dn = conn.entries[0].entry_dn
            # Pin the discovered DN below the configured search base so a
            # malicious directory entry cannot point us at a DN outside the
            # tree we're authorized to bind into. The check is structural,
            # not authenticating: a directory that returns an out-of-tree
            # DN for a search query is misconfigured (or compromised) and
            # we should refuse to bind as it.
            if not _dn_is_within(entry_dn, search_base):
                raise LDAPError(
                    f"LDAP search returned a DN outside the configured "
                    f"search base ({search_base!r}); refusing to bind as "
                    f"{entry_dn!r}"
                )
            return entry_dn

        return None

    def _get_user_groups(self, user_dn: str, conn) -> list[str]:
        """
        Get group DNs that a user belongs to.

        Args:
            user_dn: User's distinguished name
            conn: LDAP connection

        Returns:
            List of group DNs
        """
        try:
            from ldap3 import SUBTREE
        except ImportError:
            raise LDAPError("ldap3 package is not installed")

        # Search for user and get memberOf attribute
        conn.search(
            search_base=user_dn,
            search_filter="(objectClass=*)",
            search_scope="BASE",
            attributes=[self.config.group_membership_attribute],
        )

        if conn.entries:
            entry = conn.entries[0]
            member_of = getattr(entry, self.config.group_membership_attribute, None)
            if member_of:
                return list(member_of.values) if hasattr(member_of, "values") else []

        return []

    def _determine_role(self, group_dns: list[str]) -> UserRole:
        """
        Determine user role based on group membership.

        Args:
            group_dns: List of group DNs the user belongs to

        Returns:
            UserRole based on group membership
        """
        # Normalize group DNs for comparison (case-insensitive)
        normalized_groups = [g.lower() for g in group_dns]

        # Check admin group first
        if self.config.admin_group_dn:
            if self.config.admin_group_dn.lower() in normalized_groups:
                return UserRole.ADMIN

        # Default to standard user role
        return UserRole.STANDARD

    def authenticate(self, username: str, password: str) -> User:
        """
        Authenticate user against LDAP/Active Directory.

        Order of operations is security-relevant: the user-bind (password
        verification) MUST precede any attribute lookup whose result feeds
        role determination. If user_dn_pattern is a loose template that
        resolves to an unintended DN, fetching attributes against it before
        verifying the password would let those attributes (groups in
        particular) influence the final User.role.

        Args:
            username: Username (sAMAccountName for AD)
            password: User's password

        Returns:
            User object if authentication succeeds

        Raises:
            LDAPError: If authentication fails
        """
        try:
            from ldap3 import Connection, SIMPLE
        except ImportError:
            raise LDAPError("ldap3 package is not installed. Run: pip install ldap3")

        if not password:
            raise LDAPError("Password cannot be empty")

        # Resolve the candidate user DN. Search-based lookup needs a service
        # bind; pattern-based lookup does not — defer the service bind until
        # after we know we'll need it.
        if self.config.user_dn_pattern:
            # RDN-value substitution → escape for DN context (RFC 4514).
            user_dn = self.config.user_dn_pattern.replace(
                "{username}", self._escape_dn_value(username)
            )
        else:
            conn = self._bind_connection()
            try:
                user_dn = self._get_user_dn(username, conn)
            finally:
                conn.unbind()
            if not user_dn:
                raise LDAPError("Invalid username or password")

        # Verify the password by binding as the candidate user BEFORE trusting
        # the DN for any role-determining lookup.
        server = self._get_server()
        user_conn = Connection(
            server,
            user=user_dn,
            password=password,
            authentication=SIMPLE,
            read_only=True,
            receive_timeout=self.config.receive_timeout,
        )
        if not user_conn.bind():
            raise LDAPError("Invalid username or password")
        user_conn.unbind()

        # Password verified — now fetch attributes for display + role.
        display_name = username
        email = None
        groups = []

        conn = self._bind_connection()
        try:
            conn.search(
                search_base=user_dn,
                search_filter="(objectClass=*)",
                search_scope="BASE",
                attributes=[
                    self.config.username_attribute,
                    self.config.display_name_attribute,
                    self.config.email_attribute,
                    self.config.group_membership_attribute,
                ],
            )

            if conn.entries:
                user_entry = conn.entries[0]

                if hasattr(user_entry, self.config.display_name_attribute):
                    attr = getattr(user_entry, self.config.display_name_attribute)
                    if attr and attr.value:
                        display_name = str(attr.value)

                if hasattr(user_entry, self.config.email_attribute):
                    attr = getattr(user_entry, self.config.email_attribute)
                    if attr and attr.value:
                        email = str(attr.value)

                if hasattr(user_entry, self.config.group_membership_attribute):
                    attr = getattr(user_entry, self.config.group_membership_attribute)
                    if attr:
                        groups = list(attr.values) if hasattr(attr, "values") else []
        finally:
            conn.unbind()

        role = self._determine_role(groups)

        return User(
            username=username,
            display_name=display_name,
            role=role,
            email=email,
        )

    def search_users(self, search_term: str, limit: int = 50) -> list[dict]:
        """
        Search for users in LDAP directory.

        Args:
            search_term: Search term for username or display name
            limit: Maximum number of results

        Returns:
            List of user dictionaries with username, display_name, email
        """
        try:
            from ldap3 import SUBTREE
        except ImportError:
            raise LDAPError("ldap3 package is not installed")

        conn = self._bind_connection()

        try:
            search_base = self.config.user_search_base or self.config.base_dn

            # Escape search term to prevent LDAP injection
            safe_search_term = self._escape_ldap_filter(search_term)

            # Search by sAMAccountName or displayName
            search_filter = (
                f"(&(objectClass=user)(|"
                f"({self.config.username_attribute}=*{safe_search_term}*)"
                f"({self.config.display_name_attribute}=*{safe_search_term}*)))"
            )

            conn.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=[
                    self.config.username_attribute,
                    self.config.display_name_attribute,
                    self.config.email_attribute,
                ],
                size_limit=limit,
            )

            users = []
            for entry in conn.entries:
                username = ""
                display_name = ""
                email = ""

                if hasattr(entry, self.config.username_attribute):
                    attr = getattr(entry, self.config.username_attribute)
                    if attr and attr.value:
                        username = str(attr.value)

                if hasattr(entry, self.config.display_name_attribute):
                    attr = getattr(entry, self.config.display_name_attribute)
                    if attr and attr.value:
                        display_name = str(attr.value)

                if hasattr(entry, self.config.email_attribute):
                    attr = getattr(entry, self.config.email_attribute)
                    if attr and attr.value:
                        email = str(attr.value)

                if username:
                    users.append({
                        "username": username,
                        "display_name": display_name or username,
                        "email": email,
                    })

            return users

        finally:
            conn.unbind()
