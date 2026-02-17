"""Base repository classes for MongoDB data access."""

from typing import ClassVar, Generic, Optional, TypeVar

from pymongo.database import Database

T = TypeVar("T")
C = TypeVar("C")


class BaseRepository(Generic[T]):
    """Base class for collection-backed repositories.

    Provides standard CRUD operations. Subclasses must set:
        COLLECTION: MongoDB collection name
        MODEL_CLASS: Model class with from_dict()/to_dict() methods

    Override _get_id() for models where the document ID isn't item.id.
    """

    COLLECTION: ClassVar[str]
    MODEL_CLASS: ClassVar[type]

    def __init__(self, db: Database):
        self.collection = db[self.COLLECTION]

    def _get_id(self, item: T) -> str:
        """Get the document ID for an item. Override for non-standard IDs."""
        return item.id

    def list_all(self) -> list[T]:
        """Get all documents."""
        return [self.MODEL_CLASS.from_dict(doc) for doc in self.collection.find()]

    def get_by_id(self, item_id: str) -> Optional[T]:
        """Get a document by ID."""
        doc = self.collection.find_one({"_id": item_id})
        if doc:
            return self.MODEL_CLASS.from_dict(doc)
        return None

    def save(self, item: T) -> None:
        """Insert or update a document."""
        item_id = self._get_id(item)
        doc = item.to_dict()
        doc["_id"] = item_id
        self.collection.replace_one(
            {"_id": item_id},
            doc,
            upsert=True,
        )

    def delete(self, item_id: str) -> bool:
        """Delete a document by ID."""
        result = self.collection.delete_one({"_id": item_id})
        return result.deleted_count > 0


class SingletonConfigRepository(Generic[C]):
    """Base class for singleton configuration repositories.

    Stores a single configuration document in the 'settings' collection.
    Subclasses must set:
        CONFIG_ID: Unique document ID within the settings collection
        MODEL_CLASS: Config model class with from_dict()/to_dict() methods
    """

    CONFIG_ID: ClassVar[str]
    MODEL_CLASS: ClassVar[type]

    def __init__(self, db: Database):
        self.collection = db["settings"]

    def get(self) -> C:
        """Get the configuration, creating default if not exists."""
        doc = self.collection.find_one({"_id": self.CONFIG_ID})
        if doc:
            return self.MODEL_CLASS.from_dict(doc.get("config", {}))
        return self.MODEL_CLASS()

    def save(self, config: C) -> None:
        """Save configuration."""
        self.collection.replace_one(
            {"_id": self.CONFIG_ID},
            {"_id": self.CONFIG_ID, "config": config.to_dict()},
            upsert=True,
        )
