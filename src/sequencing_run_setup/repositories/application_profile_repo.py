"""Repository for ApplicationProfile database operations."""

from typing import Optional

from pymongo.database import Database

from ..models.application_profile import ApplicationProfile


class ApplicationProfileRepository:
    """Repository for managing ApplicationProfile documents in MongoDB."""

    def __init__(self, db: Database):
        self.collection = db["application_profiles"]

    def list_all(self) -> list[ApplicationProfile]:
        """Get all application profiles."""
        docs = self.collection.find()
        return [ApplicationProfile.from_dict(doc) for doc in docs]

    def get_by_id(self, profile_id: str) -> Optional[ApplicationProfile]:
        """Get an application profile by ID."""
        doc = self.collection.find_one({"_id": profile_id})
        if doc:
            return ApplicationProfile.from_dict(doc)
        return None

    def get_by_name_version(self, name: str, version: str) -> Optional[ApplicationProfile]:
        """Get an application profile by name and version.

        This is the primary lookup method for resolving TestProfile references.
        """
        doc = self.collection.find_one({
            "name": name,
            "version": str(version),
        })
        if doc:
            return ApplicationProfile.from_dict(doc)
        return None

    def get_by_name(self, name: str) -> list[ApplicationProfile]:
        """Get all versions of an application profile by name."""
        docs = self.collection.find({"name": name})
        return [ApplicationProfile.from_dict(doc) for doc in docs]

    def save(self, profile: ApplicationProfile) -> None:
        """Insert or update an application profile."""
        self.collection.replace_one(
            {"_id": profile.id},
            profile.to_dict(),
            upsert=True,
        )

    def delete(self, profile_id: str) -> bool:
        """Delete an application profile by ID."""
        result = self.collection.delete_one({"_id": profile_id})
        return result.deleted_count > 0

    def delete_all(self) -> int:
        """Delete all application profiles. Used for full resync."""
        result = self.collection.delete_many({})
        return result.deleted_count

    def bulk_save(self, profiles: list[ApplicationProfile]) -> int:
        """Save multiple profiles efficiently.

        Uses replace_one with upsert for each profile.
        Returns number of profiles saved.
        """
        count = 0
        for profile in profiles:
            self.save(profile)
            count += 1
        return count
