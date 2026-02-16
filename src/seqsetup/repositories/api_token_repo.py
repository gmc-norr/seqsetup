"""Repository for API token management."""

from typing import Optional

from pymongo.database import Database

from ..models.api_token import ApiToken


class ApiTokenRepository:
    """Repository for managing API tokens in MongoDB."""

    COLLECTION = "api_tokens"

    def __init__(self, db: Database):
        self.collection = db[self.COLLECTION]
        self._ensure_indexes()

    def _ensure_indexes(self) -> None:
        """Create indexes for efficient token lookup."""
        self.collection.create_index("token_prefix", sparse=True)

    def list_all(self) -> list[ApiToken]:
        """List all tokens (without plaintext)."""
        docs = self.collection.find()
        return [ApiToken.from_dict(doc) for doc in docs]

    def get_by_id(self, token_id: str) -> Optional[ApiToken]:
        """Get a single token by ID."""
        doc = self.collection.find_one({"_id": token_id})
        if doc:
            return ApiToken.from_dict(doc)
        return None

    def save(self, token: ApiToken) -> None:
        """Insert or upsert a token."""
        self.collection.replace_one(
            {"_id": token.id},
            token.to_dict(),
            upsert=True,
        )

    def delete(self, token_id: str) -> None:
        """Delete (revoke) a token."""
        self.collection.delete_one({"_id": token_id})

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
