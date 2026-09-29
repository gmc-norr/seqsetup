"""Repository for local user database operations."""

from typing import Optional

from ..models.local_user import LocalUser
from ..models.user import UserRole
from .base import BaseRepository


class LocalUserRepository(BaseRepository[LocalUser]):
    """Repository for managing local users in MongoDB."""

    COLLECTION = "local_users"
    MODEL_CLASS = LocalUser

    def _get_id(self, item: LocalUser) -> str:
        """Local users use username as document ID."""
        return item.username

    def get_by_username(self, username: str) -> Optional[LocalUser]:
        """Get a user by username."""
        return self.get_by_id(username)

    def exists(self, username: str) -> bool:
        """Check if a user with the given username exists."""
        return self.collection.count_documents({"_id": username}) > 0

    def create(self, user: LocalUser) -> bool:
        """Insert a new user. False, with nothing written, if the name is taken:
        never replaces an existing account."""
        from pymongo.errors import DuplicateKeyError

        doc = user.to_dict()
        doc["_id"] = user.username
        try:
            self.collection.insert_one(doc)
        except DuplicateKeyError:
            return False
        return True

    def count_admins(self) -> int:
        """Count the number of admin users."""
        return self.collection.count_documents({"role": UserRole.ADMIN.value})
