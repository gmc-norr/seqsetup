"""Repository for local user database operations."""

from typing import Optional

from pymongo.database import Database

from ..models.local_user import LocalUser
from ..models.user import UserRole


class LocalUserRepository:
    """Repository for managing local users in MongoDB."""

    COLLECTION = "local_users"

    def __init__(self, db: Database):
        self.collection = db[self.COLLECTION]

    def list_all(self) -> list[LocalUser]:
        """Get all local users."""
        docs = self.collection.find()
        return [LocalUser.from_dict(doc) for doc in docs]

    def get_by_username(self, username: str) -> Optional[LocalUser]:
        """Get a user by username."""
        doc = self.collection.find_one({"_id": username})
        if doc:
            return LocalUser.from_dict(doc)
        return None

    def save(self, user: LocalUser) -> None:
        """Insert or update a local user."""
        self.collection.replace_one(
            {"_id": user.username},
            user.to_dict(),
            upsert=True,
        )

    def delete(self, username: str) -> bool:
        """Delete a local user by username."""
        result = self.collection.delete_one({"_id": username})
        return result.deleted_count > 0

    def exists(self, username: str) -> bool:
        """Check if a user with the given username exists."""
        return self.collection.count_documents({"_id": username}) > 0

    def count_admins(self) -> int:
        """Count the number of admin users."""
        return self.collection.count_documents({"role": UserRole.ADMIN.value})
