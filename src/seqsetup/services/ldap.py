"""LDAP/Active Directory authentication service."""

from typing import Optional, Tuple

from ..models.auth_config import AuthConfig, LDAPConfig
from ..models.user import User, UserRole


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

        tls = None
        if self.config.use_ssl or self.config.server_url.startswith("ldaps://"):
            tls = Tls(validate=ssl.CERT_NONE)  # In production, use proper cert validation

        return Server(
            self.config.server_url,
            use_ssl=self.config.use_ssl,
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
            password=self.config.bind_password,
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

        # Escape username to prevent LDAP injection
        safe_username = self._escape_ldap_filter(username)

        # If direct DN pattern is configured, use it
        if self.config.user_dn_pattern:
            return self.config.user_dn_pattern.replace("{username}", safe_username)

        # Otherwise search for the user
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
            return conn.entries[0].entry_dn

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

        Args:
            username: Username (sAMAccountName for AD)
            password: User's password

        Returns:
            User object if authentication succeeds

        Raises:
            LDAPError: If authentication fails
        """
        try:
            from ldap3 import Connection, SIMPLE, SUBTREE
        except ImportError:
            raise LDAPError("ldap3 package is not installed. Run: pip install ldap3")

        if not password:
            raise LDAPError("Password cannot be empty")

        # First, bind with service account to search for user
        conn = self._bind_connection()

        try:
            # Escape username to prevent LDAP injection
            safe_username = self._escape_ldap_filter(username)

            # Search for user
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

            if not conn.entries:
                raise LDAPError("Invalid username or password")

            user_entry = conn.entries[0]
            user_dn = user_entry.entry_dn

            # Get user attributes
            display_name = username
            email = None
            groups = []

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

        # Now try to bind as the user to verify password
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

        # Determine role based on group membership
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
