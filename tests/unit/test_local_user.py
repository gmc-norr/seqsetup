"""Tests for LocalUser model."""

import pytest

from seqsetup.models.local_user import LocalUser
from seqsetup.models.user import UserRole


class TestLocalUserPassword:
    """Tests for password hashing and verification."""

    def test_set_password_stores_hash(self):
        user = LocalUser(username="test", display_name="Test")
        user.set_password("mypassword")
        assert user.password_hash
        assert user.password_hash.startswith("$2")
        assert user.password_hash != "mypassword"

    def test_set_password_pins_bcrypt_rounds(self):
        """The bcrypt cost factor must be pinned, not left to the library default.

        bcrypt's default may change between releases; without an explicit value
        a future package upgrade could silently lower the work factor below
        clinical-grade. The hash prefix encodes the rounds as $2b$<rounds>$.
        """
        user = LocalUser(username="test", display_name="Test")
        user.set_password("mypassword")
        # Prefix format: $2b$<rounds>$<salt+hash>
        parts = user.password_hash.split("$")
        rounds = int(parts[2])
        assert rounds == 12, (
            f"Expected pinned bcrypt rounds=12, got {rounds}. "
            f"Update _BCRYPT_ROUNDS (and the assertion) only after a deliberate review."
        )


class TestWeakPasswordPolicy:
    """The weak-password policy on set_password defends clinical deployments
    against the easiest operator footguns (default `admin/admin123`, etc.)."""

    def test_known_weak_password_rejected(self):
        from seqsetup.models.local_user import WeakPasswordError
        user = LocalUser(username="test", display_name="Test")
        for weak in ("admin", "admin123", "password", "welcome1", "letmein"):
            with pytest.raises(WeakPasswordError):
                user.set_password(weak)

    def test_weak_password_check_is_case_insensitive(self):
        from seqsetup.models.local_user import WeakPasswordError
        user = LocalUser(username="test", display_name="Test")
        with pytest.raises(WeakPasswordError):
            user.set_password("PASSWORD")
        with pytest.raises(WeakPasswordError):
            user.set_password("AdMiN123")

    def test_short_password_rejected(self):
        from seqsetup.models.local_user import WeakPasswordError
        user = LocalUser(username="test", display_name="Test")
        with pytest.raises(WeakPasswordError, match="at least"):
            user.set_password("short1")  # 6 chars

    def test_repeated_character_rejected(self):
        from seqsetup.models.local_user import WeakPasswordError
        user = LocalUser(username="test", display_name="Test")
        with pytest.raises(WeakPasswordError):
            user.set_password("aaaaaaaa")

    def test_all_digits_rejected(self):
        from seqsetup.models.local_user import WeakPasswordError
        user = LocalUser(username="test", display_name="Test")
        with pytest.raises(WeakPasswordError):
            user.set_password("19940215")

    def test_strong_password_accepted(self):
        user = LocalUser(username="test", display_name="Test")
        user.set_password("Clin1cal-Op3rator!")
        # No exception; hash stored.
        assert user.password_hash.startswith("$2")

    def test_mixed_password_at_minimum_length_accepted(self):
        user = LocalUser(username="test", display_name="Test")
        user.set_password("Strong-1")  # exactly 8 chars
        assert user.password_hash

    def test_verify_correct_password(self):
        user = LocalUser(username="test", display_name="Test")
        user.set_password("mypassword")
        assert user.verify_password("mypassword") is True

    def test_verify_wrong_password(self):
        user = LocalUser(username="test", display_name="Test")
        user.set_password("mypassword")
        assert user.verify_password("wrongpassword") is False

    def test_verify_empty_password(self):
        user = LocalUser(username="test", display_name="Test")
        user.set_password("mypassword")
        assert user.verify_password("") is False

    def test_verify_no_hash_set(self):
        user = LocalUser(username="test", display_name="Test")
        assert user.verify_password("anything") is False

    def test_set_password_updates_timestamp(self):
        user = LocalUser(username="test", display_name="Test")
        original_updated = user.updated_at
        user.set_password("newpassword")
        assert user.updated_at >= original_updated


class TestLocalUserConversion:
    """Tests for converting LocalUser to User."""

    def test_to_user_admin(self):
        local = LocalUser(
            username="admin",
            display_name="Admin User",
            role=UserRole.ADMIN,
            email="admin@example.com",
        )
        user = local.to_user()
        assert user.username == "admin"
        assert user.display_name == "Admin User"
        assert user.role == UserRole.ADMIN
        assert user.email == "admin@example.com"
        assert user.is_admin is True

    def test_to_user_standard(self):
        local = LocalUser(
            username="user1",
            display_name="User One",
            role=UserRole.STANDARD,
        )
        user = local.to_user()
        assert user.username == "user1"
        assert user.role == UserRole.STANDARD
        assert user.is_admin is False

    def test_to_user_empty_email(self):
        local = LocalUser(
            username="user1",
            display_name="User One",
            email="",
        )
        user = local.to_user()
        assert user.email is None


class TestLocalUserSerialization:
    """Tests for to_dict / from_dict round-trip."""

    def test_to_dict_has_expected_keys(self):
        user = LocalUser(
            username="jdoe",
            display_name="Jane Doe",
            role=UserRole.ADMIN,
            email="jdoe@example.com",
            password_hash="hash123",
        )
        d = user.to_dict()
        assert d["_id"] == "jdoe"
        assert d["username"] == "jdoe"
        assert d["display_name"] == "Jane Doe"
        assert d["role"] == "admin"
        assert d["email"] == "jdoe@example.com"
        assert d["password_hash"] == "hash123"
        assert "created_at" in d
        assert "updated_at" in d

    def test_round_trip(self):
        original = LocalUser(
            username="jdoe",
            display_name="Jane Doe",
            role=UserRole.ADMIN,
            email="jdoe@example.com",
            password_hash="hash123",
        )
        d = original.to_dict()
        restored = LocalUser.from_dict(d)
        assert restored.username == original.username
        assert restored.display_name == original.display_name
        assert restored.role == original.role
        assert restored.email == original.email
        assert restored.password_hash == original.password_hash

    def test_from_dict_missing_fields(self):
        user = LocalUser.from_dict({})
        assert user.username == ""
        assert user.display_name == ""
        assert user.role == UserRole.STANDARD
        assert user.password_hash == ""

    def test_from_dict_uses_id_fallback(self):
        user = LocalUser.from_dict({"_id": "fallback_user"})
        assert user.username == "fallback_user"
