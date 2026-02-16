"""API token model for programmatic API access."""

import secrets
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import uuid

import bcrypt


@dataclass
class ApiToken:
    """An API token for Bearer authentication on API endpoints.

    The plaintext token is only available at creation time. Only the
    bcrypt hash is stored. A prefix of the plaintext is stored for
    fast lookup without needing to bcrypt-compare against every token.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    token_hash: str = ""
    token_prefix: str = ""  # First 8 chars of plaintext for fast lookup
    created_by: str = ""
    created_at: datetime = field(default_factory=datetime.now)

    def verify(self, plaintext_token: str) -> bool:
        """Check whether a plaintext token matches this token's hash."""
        return bcrypt.checkpw(
            plaintext_token.encode("utf-8"),
            self.token_hash.encode("utf-8"),
        )

    def to_dict(self) -> dict:
        """Convert to dictionary for MongoDB storage."""
        return {
            "_id": self.id,
            "name": self.name,
            "token_hash": self.token_hash,
            "token_prefix": self.token_prefix,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ApiToken":
        """Create from dictionary."""
        created_at = data.get("created_at")
        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at)
        elif created_at is None:
            created_at = datetime.now()

        return cls(
            id=data.get("_id") or data.get("id") or str(uuid.uuid4()),
            name=data.get("name", ""),
            token_hash=data.get("token_hash", ""),
            token_prefix=data.get("token_prefix", ""),
            created_by=data.get("created_by", ""),
            created_at=created_at,
        )

    @staticmethod
    def generate_token() -> str:
        """Generate a new random plaintext token."""
        return secrets.token_urlsafe(32)

    @staticmethod
    def hash_token(plaintext_token: str) -> tuple[str, str]:
        """Hash a plaintext token using bcrypt.

        Returns:
            Tuple of (bcrypt_hash, prefix) where prefix is the first 8 chars
            of the plaintext token for fast lookup.
        """
        hashed = bcrypt.hashpw(
            plaintext_token.encode("utf-8"),
            bcrypt.gensalt(),
        ).decode("utf-8")
        prefix = plaintext_token[:8]
        return hashed, prefix
