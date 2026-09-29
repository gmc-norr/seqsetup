"""Sign-in: directory accounts and local (database) accounts.

Spec 2026-09-28 group 2b: local accounts live only in the database; the
old users file is no longer read. Every refusal carries a reason for the
audit trail, while the sign-in page shows one message.
"""

import dataclasses
import logging
from typing import Callable, Optional

from ..models.auth_config import AuthConfig, AuthMethod
from ..models.local_user import MAX_USERNAME_LENGTH
from ..models.user import User

logger = logging.getLogger(__name__)

# The one message every failed sign-in shows. It never says which part failed.
SIGN_IN_FAILED = ("Sign-in failed. Check your name and password, or ask an admin "
                  "whether you have access to SeqSetup.")


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
    """A refused sign-in. Its text is always SIGN_IN_FAILED.

    ``reason`` is for the audit trail only: bad_name, directory_refused,
    not_found, not_in_group, server_error or local_refused. ``local_tried``
    is True when the directory refused and the local fallback was also
    tried and refused.
    """

    def __init__(self, reason: str = "local_refused", local_tried: bool = False):
        super().__init__(SIGN_IN_FAILED)
        self.reason = reason
        self.local_tried = local_tried


class AuthService:
    """Checks a sign-in against the directory (when set up) and the local accounts."""

    def __init__(
        self,
        get_auth_config: Optional[Callable[[], AuthConfig]] = None,
        get_local_user_repo: Optional[Callable] = None,
    ):
        self._get_auth_config = get_auth_config
        self._get_local_user_repo = get_local_user_repo

    def authenticate(self, username: str, password: str) -> User:
        """The signed-in User, or AuthenticationError.

        A name longer than MAX_USERNAME_LENGTH is refused first, never cut
        (review P3). With directory sign-in on, the directory is asked first;
        when it refuses for any reason (an unreachable server included) and
        local fallback is on, the local accounts are tried.
        """
        if len(username) > MAX_USERNAME_LENGTH:
            raise AuthenticationError("bad_name")
        auth_config = self._get_auth_config() if self._get_auth_config else None
        if auth_config and auth_config.is_ldap_enabled:
            try:
                return self._authenticate_ldap(username, password, auth_config)
            except AuthenticationError as refused:
                if not auth_config.allow_local_fallback:
                    raise
                try:
                    return self._authenticate_local(username, password)
                except AuthenticationError:
                    raise AuthenticationError(refused.reason, local_tried=True) from None
        return self._authenticate_local(username, password)

    def _authenticate_ldap(self, username: str, password: str, auth_config: AuthConfig) -> User:
        """A directory sign-in as the person (services/ldap.py)."""
        from .ldap import LDAPService, SignInRefused

        try:
            ldap_service = LDAPService(
                auth_config.ldap_config,
                active_directory=auth_config.auth_method is AuthMethod.ACTIVE_DIRECTORY)
            return dataclasses.replace(ldap_service.authenticate(username, password), source="ldap")
        except SignInRefused as e:
            # The detail can name a host; it goes to the server log, never to
            # the sign-in page.
            logger.warning("Directory sign-in refused: %s", e)
            raise AuthenticationError(e.reason) from None
        except Exception:
            logger.warning("Directory sign-in failed unexpectedly", exc_info=True)
            raise AuthenticationError("server_error") from None

    def _authenticate_local(self, username: str, password: str) -> User:
        """A database account. An unknown name still costs one bcrypt
        comparison, so timing does not reveal which accounts exist."""
        did_verify = False
        if self._get_local_user_repo:
            try:
                local_user = self._get_local_user_repo().get_by_username(username)
                if local_user:
                    did_verify = True
                    if local_user.verify_password(password):
                        return local_user.to_user()
            except (ConnectionError, OSError) as e:
                logger.warning("Local user database unavailable: %s", e)
            except Exception as e:
                logger.error("Unexpected error during local user lookup: %s", e)
        if not did_verify:
            self._verify_password(password, _dummy_bcrypt_hash())
        raise AuthenticationError("local_refused")

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
