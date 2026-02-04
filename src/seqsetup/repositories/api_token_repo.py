"""Repository for API token management."""

from typing import Optional

from pymongo.database import Database

from ..models.api_token import ApiToken


class ApiTokenRepository:
    """Repository for managing API tokens in MongoDB."""

    COLLECTION = "api_tokens"

    def __init__(self, db: Database):
        self.collection = db[self.COLLECTION]

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
        """Verify a plaintext token against all stored hashes.

        Returns the matching ApiToken if found, otherwise None.
        """
        for token in self.list_all():
            try:
                if token.verify(plaintext):
                    return token
            except Exception:
                continue
        return None
