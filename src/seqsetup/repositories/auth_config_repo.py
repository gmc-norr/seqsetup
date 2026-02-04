"""Repository for authentication configuration."""

from typing import Optional

from pymongo.database import Database

from ..models.auth_config import AuthConfig


class AuthConfigRepository:
    """Repository for managing authentication configuration in MongoDB."""

    CONFIG_ID = "auth_config"

    def __init__(self, db: Database):
        self.collection = db["settings"]

    def get(self) -> AuthConfig:
        """Get the authentication configuration, creating default if not exists."""
        doc = self.collection.find_one({"_id": self.CONFIG_ID})
        if doc:
            return AuthConfig.from_dict(doc.get("config", {}))
        return AuthConfig()

    def save(self, config: AuthConfig) -> None:
        """Save authentication configuration."""
        self.collection.replace_one(
            {"_id": self.CONFIG_ID},
            {"_id": self.CONFIG_ID, "config": config.to_dict()},
            upsert=True,
        )

    def update_ldap_tested(self, tested: bool) -> None:
        """Update just the ldap_tested flag."""
        config = self.get()
        config.ldap_tested = tested
        self.save(config)
