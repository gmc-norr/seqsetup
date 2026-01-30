"""Repository for IndexKit database operations."""

from typing import Optional

from pymongo.database import Database

from ..models.index import Index, IndexKit, IndexPair


class IndexKitRepository:
    """Repository for managing IndexKit documents in MongoDB."""

    def __init__(self, db: Database):
        self.collection = db["index_kits"]

    def list_all(self) -> list[IndexKit]:
        """Get all index kits."""
        docs = self.collection.find()
        return [IndexKit.from_dict(doc) for doc in docs]

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
        doc = self.collection.find_one({"_id": kit_id})
        if doc:
            return IndexKit.from_dict(doc)
        return None

    def exists(self, name: str, version: str) -> bool:
        """Check if a kit with the given name and version already exists."""
        kit_id = f"{name}:{version}"
        if self.collection.count_documents({"_id": kit_id}) > 0:
            return True
        # Fall back: match by name and version fields (handles legacy _id format)
        return self.collection.count_documents({"name": name, "version": version}) > 0

    def save(self, kit: IndexKit) -> None:
        """Insert or update an index kit."""
        self.collection.replace_one(
            {"_id": kit.kit_id},
            kit.to_dict(),
            upsert=True,
        )

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
        for kit in self.list_all():
            pair = kit.get_index_pair_by_id(pair_id)
            if pair:
                return pair
        return None

    def find_index_pair_with_kit(self, pair_id: str) -> tuple[Optional[IndexPair], Optional["IndexKit"]]:
        """
        Find an index pair across all kits by its ID and return the kit.

        Returns:
            Tuple of (IndexPair, IndexKit) or (None, None) if not found.
        """
        for kit in self.list_all():
            pair = kit.get_index_pair_by_id(pair_id)
            if pair:
                return pair, kit
        return None, None

    def find_index(self, index_id: str) -> Optional[Index]:
        """
        Find an individual index across all kits by its ID.

        Index IDs are formatted as: {kit_name}_{i7|i5}_{index_name}
        """
        for kit in self.list_all():
            index = kit.get_index_by_id(index_id)
            if index:
                return index
        return None

    def find_index_with_kit(self, index_id: str) -> tuple[Optional[Index], Optional["IndexKit"]]:
        """
        Find an individual index across all kits by its ID and return the kit.

        Index IDs are formatted as: {kit_name}_{i7|i5}_{index_name}

        Returns:
            Tuple of (Index, IndexKit) or (None, None) if not found.
        """
        for kit in self.list_all():
            index = kit.get_index_by_id(index_id)
            if index:
                return index, kit
        return None, None
