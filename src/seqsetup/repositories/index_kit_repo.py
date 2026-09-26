"""Repository for IndexKit database operations."""

from typing import Optional

from pymongo import ReplaceOne

from ..models.index import IndexKit
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

    def find_kits_with_index_pair(self, pair_id: str) -> list[IndexKit]:
        """Every kit holding an index pair with this ID.

        Pair IDs are formatted as: {kit_name}_{pair_name}, so every version
        of one kit holds the same IDs.
        """
        docs = self.collection.find({"index_pairs.id": pair_id})
        return [IndexKit.from_dict(doc) for doc in docs]

    def find_kits_with_index(self, index_id: str) -> list[IndexKit]:
        """Every kit holding an individual index with this ID.

        Index IDs are formatted as: {kit_name}_{i7|i5}_{index_name}, so every
        version of one kit holds the same IDs.
        """
        return [kit for kit in self.list_all() if kit.get_index_by_id(index_id)]

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
