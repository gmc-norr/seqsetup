"""Local user model for database-managed users."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

import bcrypt

from .user import User, UserRole


@dataclass
class LocalUser:
    """A locally managed user stored in MongoDB."""

    username: str
    display_name: str
    role: UserRole = UserRole.STANDARD
    password_hash: str = ""
    email: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)

    def set_password(self, plaintext: str) -> None:
        """Hash and store a plaintext password."""
        self.password_hash = bcrypt.hashpw(
            plaintext.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")
        self.updated_at = datetime.now()

    def verify_password(self, plaintext: str) -> bool:
        """Verify a plaintext password against the stored hash."""
        if not self.password_hash:
            return False
        try:
            return bcrypt.checkpw(
                plaintext.encode("utf-8"), self.password_hash.encode("utf-8")
            )
        except Exception:
            return False

    def to_user(self) -> User:
        """Convert to a User object for session storage."""
        return User(
            username=self.username,
            display_name=self.display_name,
            role=self.role,
            email=self.email or None,
        )

    def to_dict(self) -> dict:
        """Convert to dictionary for MongoDB storage."""
        return {
            "_id": self.username,
            "username": self.username,
            "display_name": self.display_name,
            "role": self.role.value,
            "password_hash": self.password_hash,
            "email": self.email,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "LocalUser":
        """Create from dictionary."""
        return cls(
            username=data.get("username", data.get("_id", "")),
            display_name=data.get("display_name", ""),
            role=UserRole(data.get("role", "standard")),
            password_hash=data.get("password_hash", ""),
            email=data.get("email", ""),
            created_at=data.get("created_at", datetime.now()),
            updated_at=data.get("updated_at", datetime.now()),
        )
