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
