"""Repository for sample API configuration."""

from pymongo.database import Database

from ..models.sample_api_config import SampleApiConfig


class SampleApiConfigRepository:
    """Repository for managing sample API configuration in MongoDB.

    Uses singleton pattern - only one configuration document exists.
    """

    CONFIG_ID = "sample_api_config"

    def __init__(self, db: Database):
        self.collection = db["settings"]

    def get(self) -> SampleApiConfig:
        """Get the sample API configuration, creating default if not exists."""
        doc = self.collection.find_one({"_id": self.CONFIG_ID})
        if doc:
            return SampleApiConfig.from_dict(doc.get("config", {}))
        return SampleApiConfig()

    def save(self, config: SampleApiConfig) -> None:
        """Save sample API configuration."""
        self.collection.replace_one(
            {"_id": self.CONFIG_ID},
            {"_id": self.CONFIG_ID, "config": config.to_dict()},
            upsert=True,
        )
