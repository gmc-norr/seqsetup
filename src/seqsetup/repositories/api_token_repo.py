"""Repository for API token management."""

from typing import Optional

from pymongo.database import Database

from ..models.api_token import ApiToken
from .base import BaseRepository


class ApiTokenRepository(BaseRepository[ApiToken]):
    """Repository for managing API tokens in MongoDB."""

    COLLECTION = "api_tokens"
    MODEL_CLASS = ApiToken

    def __init__(self, db: Database):
        super().__init__(db)
        self._ensure_indexes()

    def _ensure_indexes(self) -> None:
        """Create indexes for efficient token lookup."""
        self.collection.create_index("token_prefix", sparse=True)

    def verify_token(self, plaintext: str) -> Optional[ApiToken]:
        """Verify a plaintext token against stored hashes.

        Uses token_prefix for fast filtering before expensive bcrypt comparison.
        Falls back to full scan for legacy tokens without a prefix.

        Returns the matching ApiToken if found, otherwise None.
        """
        prefix = plaintext[:8]

        # First: try tokens matching the prefix (fast path)
        for doc in self.collection.find({"token_prefix": prefix}):
            token = ApiToken.from_dict(doc)
            try:
                if token.verify(plaintext):
                    return token
            except Exception:
                continue

        # Fallback: check legacy tokens without a prefix
        for doc in self.collection.find({"$or": [{"token_prefix": ""}, {"token_prefix": {"$exists": False}}]}):
            token = ApiToken.from_dict(doc)
            try:
                if token.verify(plaintext):
                    return token
            except Exception:
                continue

        return None
