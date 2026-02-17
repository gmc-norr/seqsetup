"""Repository for TestProfile database operations."""

from typing import Optional

from ..models.test_profile import TestProfile
from .base import BaseRepository


class TestProfileRepository(BaseRepository[TestProfile]):
    """Repository for managing TestProfile documents in MongoDB."""

    COLLECTION = "test_profiles"
    MODEL_CLASS = TestProfile

    def get_by_test_type(self, test_type: str) -> Optional[TestProfile]:
        """Get a test profile by test type.

        This is used to match sample.test_id to a TestProfile.
        """
        doc = self.collection.find_one({"test_type": test_type})
        if doc:
            return TestProfile.from_dict(doc)
        return None

    def delete_all(self) -> int:
        """Delete all test profiles. Used for full resync."""
        result = self.collection.delete_many({})
        return result.deleted_count

    def bulk_save(self, profiles: list[TestProfile]) -> int:
        """Save multiple profiles efficiently."""
        count = 0
        for profile in profiles:
            self.save(profile)
            count += 1
        return count
