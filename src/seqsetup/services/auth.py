"""Authentication service for user login and session management."""

import logging
from pathlib import Path
from typing import Callable, Optional

import yaml

logger = logging.getLogger(__name__)

from ..models.auth_config import AuthConfig, AuthMethod
from ..models.user import User, UserRole


class AuthenticationError(Exception):
    """Raised when authentication fails."""

    pass


class AuthService:
    """Service for authenticating users against config file, database, or LDAP."""

    def __init__(
        self,
        config_path: Path,
        get_auth_config: Optional[Callable[[], AuthConfig]] = None,
        get_local_user_repo: Optional[Callable] = None,
    ):
        """
        Initialize auth service.

        Args:
            config_path: Path to users.yaml config file
            get_auth_config: Optional callable to get auth configuration (for LDAP support)
            get_local_user_repo: Optional callable to get the local user repository (MongoDB)
        """
        self.config_path = config_path
        self._users_cache: Optional[dict] = None
        self._get_auth_config = get_auth_config
        self._get_local_user_repo = get_local_user_repo

    def _load_users(self) -> dict:
        """Load users from config file."""
        if self._users_cache is None:
            if not self.config_path.exists():
                raise FileNotFoundError(
                    f"User config file not found: {self.config_path}"
                )
            with open(self.config_path) as f:
                config = yaml.safe_load(f)
            self._users_cache = config.get("users", {})
        return self._users_cache

    def reload_config(self) -> None:
        """Force reload of user configuration."""
        self._users_cache = None

    def authenticate(self, username: str, password: str) -> User:
        """
        Authenticate user with username and password.

        Uses LDAP/AD if configured, otherwise falls back to local authentication.

        Args:
            username: Username to authenticate
            password: Plain-text password

        Returns:
            User object if authentication succeeds

        Raises:
            AuthenticationError: If credentials are invalid
        """
        # Check if LDAP authentication is configured
        auth_config = self._get_auth_config() if self._get_auth_config else None

        if auth_config and auth_config.is_ldap_enabled:
            # Try LDAP authentication first
            try:
                return self._authenticate_ldap(username, password, auth_config)
            except AuthenticationError:
                # If LDAP fails and local fallback is allowed, try local
                if auth_config.allow_local_fallback:
                    return self._authenticate_local(username, password)
                raise

        # Default to local authentication
        return self._authenticate_local(username, password)

    def _authenticate_ldap(self, username: str, password: str, auth_config: AuthConfig) -> User:
        """
        Authenticate user against LDAP/Active Directory.

        Args:
            username: Username to authenticate
            password: Plain-text password
            auth_config: Authentication configuration

        Returns:
            User object if authentication succeeds

        Raises:
            AuthenticationError: If credentials are invalid
        """
        from .ldap import LDAPService, LDAPError

        try:
            ldap_service = LDAPService(auth_config.ldap_config)
            return ldap_service.authenticate(username, password)
        except LDAPError as e:
            raise AuthenticationError(str(e))

    def _authenticate_local(self, username: str, password: str) -> User:
        """
        Authenticate user against local sources.

        Checks MongoDB users first, then falls back to users.yaml config file.

        Args:
            username: Username to authenticate
            password: Plain-text password

        Returns:
            User object if authentication succeeds

        Raises:
            AuthenticationError: If credentials are invalid
        """
        # Try MongoDB users first
        if self._get_local_user_repo:
            try:
                repo = self._get_local_user_repo()
                local_user = repo.get_by_username(username)
                if local_user and local_user.verify_password(password):
                    return local_user.to_user()
            except (ConnectionError, OSError) as e:
                logger.warning("Local user database unavailable, falling back to YAML auth: %s", e)
            except Exception as e:
                logger.error("Unexpected error during local user lookup: %s", e)

        # Fall back to YAML config file
        try:
            users = self._load_users()
        except FileNotFoundError:
            raise AuthenticationError("Invalid username or password")

        if username not in users:
            raise AuthenticationError("Invalid username or password")

        user_data = users[username]
        stored_hash = user_data.get("password_hash", "")

        # Verify password using bcrypt
        if not self._verify_password(password, stored_hash):
            raise AuthenticationError("Invalid username or password")

        return User(
            username=username,
            display_name=user_data.get("display_name", username),
            role=UserRole(user_data.get("role", "standard")),
            email=user_data.get("email"),
        )

    def _verify_password(self, password: str, stored_hash: str) -> bool:
        """Verify password against stored hash."""
        try:
            import bcrypt

            return bcrypt.checkpw(
                password.encode("utf-8"), stored_hash.encode("utf-8")
            )
        except (ValueError, TypeError) as e:
            logger.warning("Password verification failed (invalid hash format): %s", e)
            return False

    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hash a password for storage.

        Utility method for creating config file entries.

        Args:
            password: Plain-text password to hash

        Returns:
            bcrypt hash string
        """
        import bcrypt

        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")
