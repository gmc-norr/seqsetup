"""Repository for instrument visibility configuration."""

from pymongo.database import Database

from ..models.instrument_config import InstrumentConfig


class InstrumentConfigRepository:
    """Repository for managing instrument visibility configuration in MongoDB."""

    CONFIG_ID = "instrument_config"

    def __init__(self, db: Database):
        self.collection = db["settings"]

    def get(self) -> InstrumentConfig:
        """Get instrument configuration, creating default if not exists."""
        doc = self.collection.find_one({"_id": self.CONFIG_ID})
        if doc:
            return InstrumentConfig.from_dict(doc.get("config", {}))
        return InstrumentConfig()

    def save(self, config: InstrumentConfig) -> None:
        """Save instrument configuration."""
        self.collection.replace_one(
            {"_id": self.CONFIG_ID},
            {"_id": self.CONFIG_ID, "config": config.to_dict()},
            upsert=True,
        )
