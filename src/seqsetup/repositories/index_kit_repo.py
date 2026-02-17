"""Repository for IndexKit database operations."""

from typing import Optional

from pymongo import ReplaceOne

from ..models.index import Index, IndexKit, IndexPair
from .base import BaseRepository


class IndexKitRepository(BaseRepository[IndexKit]):
    """Repository for managing IndexKit documents in MongoDB."""

    COLLECTION = "index_kits"
    MODEL_CLASS = IndexKit

    def _get_id(self, item: IndexKit) -> str:
        """Index kits use kit_id (name:version) as document ID."""
        return item.kit_id

    def get_by_name(self, name: str) -> Optional[IndexKit]:
        """Get the first index kit matching a name (any version)."""
        doc = self.collection.find_one({"name": name})
        if doc:
            return IndexKit.from_dict(doc)
        return None

    def get_by_name_and_version(self, name: str, version: str) -> Optional[IndexKit]:
        """Get an index kit by name and version."""
        kit_id = f"{name}:{version}"
        doc = self.collection.find_one({"_id": kit_id})
        if not doc:
            # Fall back: match by name and version fields (handles legacy _id format)
            doc = self.collection.find_one({"name": name, "version": version})
        if doc:
            return IndexKit.from_dict(doc)
        return None

    def get_by_kit_id(self, kit_id: str) -> Optional[IndexKit]:
        """Get an index kit by its composite ID (name:version)."""
        return self.get_by_id(kit_id)

    def exists(self, name: str, version: str) -> bool:
        """Check if a kit with the given name and version already exists."""
        kit_id = f"{name}:{version}"
        if self.collection.count_documents({"_id": kit_id}) > 0:
            return True
        # Fall back: match by name and version fields (handles legacy _id format)
        return self.collection.count_documents({"name": name, "version": version}) > 0

    def delete(self, name: str, version: str) -> bool:
        """Delete an index kit by name and version."""
        kit_id = f"{name}:{version}"
        result = self.collection.delete_one({"_id": kit_id})
        if result.deleted_count > 0:
            return True
        # Fall back: match by name and version fields (handles legacy _id format)
        result = self.collection.delete_one({"name": name, "version": version})
        return result.deleted_count > 0

    def find_index_pair(self, pair_id: str) -> Optional[IndexPair]:
        """Find an index pair across all kits by its ID."""
        doc = self.collection.find_one({"index_pairs.id": pair_id})
        if doc:
            kit = IndexKit.from_dict(doc)
            return kit.get_index_pair_by_id(pair_id)
        return None

    def find_index_pair_with_kit(self, pair_id: str) -> tuple[Optional[IndexPair], Optional["IndexKit"]]:
        """
        Find an index pair across all kits by its ID and return the kit.

        Returns:
            Tuple of (IndexPair, IndexKit) or (None, None) if not found.
        """
        doc = self.collection.find_one({"index_pairs.id": pair_id})
        if doc:
            kit = IndexKit.from_dict(doc)
            pair = kit.get_index_pair_by_id(pair_id)
            if pair:
                return pair, kit
        return None, None

    def find_index(self, index_id: str) -> Optional[Index]:
        """
        Find an individual index across all kits by its ID.

        Index IDs are formatted as: {kit_name}_{i7|i5}_{index_name}
        """
        kit = self._find_kit_for_index(index_id)
        if kit:
            return kit.get_index_by_id(index_id)
        return None

    def find_index_with_kit(self, index_id: str) -> tuple[Optional[Index], Optional["IndexKit"]]:
        """
        Find an individual index across all kits by its ID and return the kit.

        Index IDs are formatted as: {kit_name}_{i7|i5}_{index_name}

        Returns:
            Tuple of (Index, IndexKit) or (None, None) if not found.
        """
        kit = self._find_kit_for_index(index_id)
        if kit:
            index = kit.get_index_by_id(index_id)
            if index:
                return index, kit
        return None, None

    def _find_kit_for_index(self, index_id: str) -> Optional[IndexKit]:
        """Find the kit containing an individual index by parsing the index ID.

        Index IDs are formatted as: {kit_name}_{i7|i5}_{index_name}
        Try to extract the kit name and query by name first; fall back to scanning all kits.
        """
        # Try to extract kit name from index_id by finding _i7_ or _i5_ separator
        for separator in ("_i7_", "_i5_"):
            pos = index_id.find(separator)
            if pos > 0:
                kit_name = index_id[:pos]
                # Query kits by name (may return multiple versions)
                for doc in self.collection.find({"name": kit_name}):
                    kit = IndexKit.from_dict(doc)
                    if kit.get_index_by_id(index_id):
                        return kit

        # Fall back: scan all kits if name parsing didn't work
        for kit in self.list_all():
            if kit.get_index_by_id(index_id):
                return kit
        return None

    def delete_synced(self) -> int:
        """Delete all synced index kits (source == 'github').

        Returns:
            Number of kits deleted.
        """
        result = self.collection.delete_many({"source": "github"})
        return result.deleted_count

    def bulk_save(self, kits: list[IndexKit]) -> int:
        """Save multiple index kits efficiently using bulk write.

        Returns:
            Number of kits processed.
        """
        if not kits:
            return 0
        operations = [
            ReplaceOne({"_id": kit.kit_id}, kit.to_dict(), upsert=True)
            for kit in kits
        ]
        result = self.collection.bulk_write(operations)
        return result.upserted_count + result.modified_count

    def list_synced(self) -> list[IndexKit]:
        """Get all synced index kits (source == 'github')."""
        docs = self.collection.find({"source": "github"})
        return [IndexKit.from_dict(doc) for doc in docs]

    def list_user_uploaded(self) -> list[IndexKit]:
        """Get all user-uploaded index kits (source != 'github')."""
        docs = self.collection.find({"source": {"$ne": "github"}})
        return [IndexKit.from_dict(doc) for doc in docs]
