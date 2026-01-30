"""Repository for Test database operations."""

from typing import Optional

from pymongo.database import Database

from ..models.test import Test


class TestRepository:
    """Repository for managing Test documents in MongoDB."""

    def __init__(self, db: Database):
        self.collection = db["tests"]

    def list_all(self) -> list[Test]:
        """Get all tests."""
        docs = self.collection.find()
        return [Test.from_dict(doc) for doc in docs]

    def get_by_id(self, test_id: str) -> Optional[Test]:
        """Get a test by ID."""
        doc = self.collection.find_one({"_id": test_id})
        if doc:
            return Test.from_dict(doc)
        return None

    def save(self, test: Test) -> None:
        """Insert or update a test."""
        self.collection.replace_one(
            {"_id": test.id},
            test.to_dict(),
            upsert=True,
        )

    def delete(self, test_id: str) -> bool:
        """Delete a test by ID."""
        result = self.collection.delete_one({"_id": test_id})
        return result.deleted_count > 0

    def create_test(self, name: str, description: str = "") -> Test:
        """Create a new test and save to database."""
        test = Test(name=name, description=description)
        self.save(test)
        return test
