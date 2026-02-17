"""Repository for Test database operations."""

from ..models.test import Test
from .base import BaseRepository


class TestRepository(BaseRepository[Test]):
    """Repository for managing Test documents in MongoDB."""

    COLLECTION = "tests"
    MODEL_CLASS = Test

    def create_test(self, name: str, description: str = "") -> Test:
        """Create a new test and save to database."""
        test = Test(name=name, description=description)
        self.save(test)
        return test
