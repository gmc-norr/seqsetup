"""Repository for TestProfile database operations."""

from ..models.test_profile import TestProfile
from .base import BaseRepository


class TestProfileRepository(BaseRepository[TestProfile]):
    """Repository for managing TestProfile documents in MongoDB."""

    COLLECTION = "test_profiles"
    MODEL_CLASS = TestProfile

    def list_by_test_type(self, test_type: str) -> list[TestProfile]:
        """Every stored version of a test. Which one a sample gets is
        services/versioned_tests.resolve_test's to decide."""
        return [TestProfile.from_dict(doc) for doc in self.collection.find({"test_type": test_type})]

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
