"""Repository for InstrumentDefinition database operations."""

from typing import Optional

from ..models.instrument_definition import InstrumentDefinition
from .base import BaseRepository


class InstrumentDefinitionRepository(BaseRepository[InstrumentDefinition]):
    """Repository for managing InstrumentDefinition documents in MongoDB.

    Stores instrument definitions synced from GitHub.
    """

    COLLECTION = "instrument_definitions"
    MODEL_CLASS = InstrumentDefinition

    def get_by_name(self, name: str) -> Optional[InstrumentDefinition]:
        """Get an instrument definition by name."""
        doc = self.collection.find_one({"name": name})
        if doc:
            return InstrumentDefinition.from_dict(doc)
        return None

    def delete_all(self) -> int:
        """Delete all instrument definitions. Used for full resync."""
        result = self.collection.delete_many({})
        return result.deleted_count

    def bulk_save(self, instruments: list[InstrumentDefinition]) -> int:
        """Save multiple instruments efficiently.

        Uses replace_one with upsert for each instrument.
        Returns number of instruments saved.
        """
        count = 0
        for instrument in instruments:
            self.save(instrument)
            count += 1
        return count

    def count(self) -> int:
        """Return the number of instrument definitions."""
        return self.collection.count_documents({})

    def has_instruments(self) -> bool:
        """Check if any instrument definitions exist."""
        return self.count() > 0

    def list_enabled(self) -> list[InstrumentDefinition]:
        """Get all enabled instrument definitions."""
        docs = self.collection.find({"enabled": True})
        return [InstrumentDefinition.from_dict(doc) for doc in docs]

    def set_enabled(self, instrument_id: str, enabled: bool) -> bool:
        """Set the enabled status of an instrument.

        Args:
            instrument_id: The instrument ID
            enabled: Whether the instrument should be enabled

        Returns:
            True if the instrument was found and updated
        """
        result = self.collection.update_one(
            {"_id": instrument_id},
            {"$set": {"enabled": enabled}},
        )
        return result.modified_count > 0

    def set_enabled_by_name(self, name: str, enabled: bool) -> bool:
        """Set the enabled status of an instrument by name.

        Args:
            name: The instrument name
            enabled: Whether the instrument should be enabled

        Returns:
            True if the instrument was found and updated
        """
        result = self.collection.update_one(
            {"name": name},
            {"$set": {"enabled": enabled}},
        )
        return result.modified_count > 0
