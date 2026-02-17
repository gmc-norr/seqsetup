"""Repository for authentication configuration."""

from ..models.auth_config import AuthConfig
from .base import SingletonConfigRepository


class AuthConfigRepository(SingletonConfigRepository[AuthConfig]):
    """Repository for managing authentication configuration in MongoDB."""

    CONFIG_ID = "auth_config"
    MODEL_CLASS = AuthConfig

    def update_ldap_tested(self, tested: bool) -> None:
        """Update just the ldap_tested flag."""
        config = self.get()
        config.ldap_tested = tested
        self.save(config)
