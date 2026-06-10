"""Authentication service for user login and session management."""

import logging
from pathlib import Path
from typing import Callable, Optional

import yaml

logger = logging.getLogger(__name__)

from ..models.auth_config import AuthConfig, AuthMethod
from ..models.user import User, UserRole


# Sentinel bcrypt hash for timing equalisation. Computed once on first use so
# an unknown-username login still incurs a bcrypt comparison (no enumeration
# via response timing). Lazy so module import stays cheap and bcrypt-free.
_DUMMY_BCRYPT_HASH: Optional[str] = None


def _dummy_bcrypt_hash() -> str:
    global _DUMMY_BCRYPT_HASH
    if _DUMMY_BCRYPT_HASH is None:
        import bcrypt

        _DUMMY_BCRYPT_HASH = bcrypt.hashpw(
            b"seqsetup-timing-sentinel", bcrypt.gensalt(rounds=12)
        ).decode("utf-8")
    return _DUMMY_BCRYPT_HASH


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
                config = yaml.safe_load(f) or {}

            if not isinstance(config, dict):
                raise ValueError("Invalid user config format: expected a mapping at top level")

            users = config.get("users", {})
            if not isinstance(users, dict):
                raise ValueError("Invalid user config format: 'users' must be a mapping")

            self._users_cache = users
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
            # Log the underlying LDAP error (includes server-side detail
            # such as bind hostnames) but surface only a generic message
            # to the user — the response template echoes this string into
            # the login page, where exposing infra detail is harmful.
            import logging
            logging.getLogger(__name__).warning(
                "LDAP authentication failed: %s", e, exc_info=True,
            )
            raise AuthenticationError("Invalid username or password")

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
        # Track whether any real bcrypt comparison ran. If the username is
        # unknown, we still run one comparison against a sentinel hash before
        # failing so response timing doesn't reveal account existence (user
        # enumeration). Mirrors ApiTokenRepository.verify_token's sentinel.
        did_verify = False

        # Try MongoDB users first
        if self._get_local_user_repo:
            try:
                repo = self._get_local_user_repo()
                local_user = repo.get_by_username(username)
                if local_user:
                    did_verify = True
                    if local_user.verify_password(password):
                        return local_user.to_user()
            except (ConnectionError, OSError) as e:
                logger.warning("Local user database unavailable, falling back to YAML auth: %s", e)
            except Exception as e:
                logger.error("Unexpected error during local user lookup: %s", e)

        # Fall back to YAML config file
        try:
            users = self._load_users()
        except (FileNotFoundError, ValueError, yaml.YAMLError):
            logger.error("Invalid YAML user configuration in %s", self.config_path)
            users = {}

        user_data = users.get(username)
        if user_data is not None:
            did_verify = True
            stored_hash = user_data.get("password_hash", "")
            if self._verify_password(password, stored_hash):
                return User(
                    username=username,
                    display_name=user_data.get("display_name", username),
                    role=UserRole(user_data.get("role", "standard")),
                    email=user_data.get("email"),
                )

        # Authentication failed. If we never ran a real bcrypt comparison
        # (unknown username on every source), run one against a sentinel hash
        # so the unknown-user path costs the same as wrong-password.
        if not did_verify:
            self._verify_password(password, _dummy_bcrypt_hash())
        raise AuthenticationError("Invalid username or password")

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

        # Pinned cost factor — keep in sync with LocalUser._BCRYPT_ROUNDS.
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")
