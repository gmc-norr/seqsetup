"""Repository for TestProfile database operations."""

from typing import Optional

from pymongo.database import Database

from ..models.test_profile import TestProfile


class TestProfileRepository:
    """Repository for managing TestProfile documents in MongoDB."""

    def __init__(self, db: Database):
        self.collection = db["test_profiles"]

    def list_all(self) -> list[TestProfile]:
        """Get all test profiles."""
        docs = self.collection.find()
        return [TestProfile.from_dict(doc) for doc in docs]

    def get_by_id(self, profile_id: str) -> Optional[TestProfile]:
        """Get a test profile by ID."""
        doc = self.collection.find_one({"_id": profile_id})
        if doc:
            return TestProfile.from_dict(doc)
        return None

    def get_by_test_type(self, test_type: str) -> Optional[TestProfile]:
        """Get a test profile by test type.

        This is used to match sample.test_id to a TestProfile.
        """
        doc = self.collection.find_one({"test_type": test_type})
        if doc:
            return TestProfile.from_dict(doc)
        return None

    def save(self, profile: TestProfile) -> None:
        """Insert or update a test profile."""
        self.collection.replace_one(
            {"_id": profile.id},
            profile.to_dict(),
            upsert=True,
        )

    def delete(self, profile_id: str) -> bool:
        """Delete a test profile by ID."""
        result = self.collection.delete_one({"_id": profile_id})
        return result.deleted_count > 0

    def delete_all(self) -> int:
        """Delete all test profiles. Used for full resync."""
        result = self.collection.delete_many({})
        return result.deleted_count

    def bulk_save(self, profiles: list[TestProfile]) -> int:
        """Save multiple profiles efficiently.

        Uses replace_one with upsert for each profile.
        Returns number of profiles saved.
        """
        count = 0
        for profile in profiles:
            self.save(profile)
            count += 1
        return count
