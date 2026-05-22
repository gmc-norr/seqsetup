"""Local user model for database-managed users."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

import bcrypt

from .user import User, UserRole


# Pinned bcrypt work factor. Raise deliberately after a clinical-impact review;
# never let it drift below 12 with a silent library default change.
_BCRYPT_ROUNDS = 12

# Minimum acceptable password length.
_MIN_PASSWORD_LENGTH = 8

# Well-known weak/default passwords. Not exhaustive — defends against the
# most obvious clinical-deployment footguns (default admin/admin123,
# operator who picks "password", etc.). Always lowercased for comparison.
_WEAK_PASSWORDS = frozenset({
    "password", "passw0rd", "p@ssw0rd", "p@ssword",
    "admin", "admin123", "administrator",
    "12345678", "123456789", "1234567890",
    "qwerty", "qwerty123", "qwertyuiop",
    "letmein", "letmein1", "letmein123",
    "welcome", "welcome1", "welcome123",
    "iloveyou", "abc12345", "asdfghjkl",
    "seqsetup", "sequencing",
    "changeme", "changeme1",
})


class WeakPasswordError(ValueError):
    """Raised when a password fails the weak-password policy."""


def assert_password_strong(plaintext: str) -> None:
    """Raise WeakPasswordError if ``plaintext`` is too short or too obvious.

    A clinical deployment that accepted "admin123" as the admin password
    would defeat every other auth control in this codebase. This policy is
    minimal but blocks the most common operator footguns.
    """
    if not isinstance(plaintext, str) or len(plaintext) < _MIN_PASSWORD_LENGTH:
        raise WeakPasswordError(
            f"Password must be at least {_MIN_PASSWORD_LENGTH} characters."
        )
    lower = plaintext.lower()
    if lower in _WEAK_PASSWORDS:
        raise WeakPasswordError(
            "Password is on the list of well-known weak/default passwords."
        )
    # All-same-character or all-digit passwords are trivially guessable.
    if len(set(plaintext)) == 1:
        raise WeakPasswordError("Password cannot be a single repeated character.")
    if plaintext.isdigit():
        raise WeakPasswordError("Password cannot be all digits.")


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
        """Hash and store a plaintext password.

        Rejects passwords that fail the weak-password policy
        (see assert_password_strong). Callers must surface WeakPasswordError
        to the user with a clear message.
        """
        assert_password_strong(plaintext)
        self.password_hash = bcrypt.hashpw(
            plaintext.encode("utf-8"), bcrypt.gensalt(rounds=_BCRYPT_ROUNDS)
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
