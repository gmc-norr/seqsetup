"""User-related data models."""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class UserRole(Enum):
    """User authorization roles."""

    ADMIN = "admin"
    STANDARD = "standard"


@dataclass
class User:
    """Authenticated user information."""

    username: str
    display_name: str
    role: UserRole
    email: Optional[str] = None

    @property
    def is_admin(self) -> bool:
        """Check if user has admin privileges."""
        return self.role == UserRole.ADMIN

    def to_dict(self) -> dict:
        """Convert to dictionary for session storage."""
        return {
            "username": self.username,
            "display_name": self.display_name,
            "role": self.role.value,
            "email": self.email,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "User":
        """Create User from dictionary (session data)."""
        return cls(
            username=data["username"],
            display_name=data["display_name"],
            role=UserRole(data["role"]),
            email=data.get("email"),
        )
