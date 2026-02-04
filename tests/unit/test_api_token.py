"""Tests for API token model."""

import pytest

from seqsetup.models.api_token import ApiToken


class TestApiTokenGeneration:
    """Tests for token generation and hashing."""

    def test_generate_token_returns_string(self):
        token = ApiToken.generate_token()
        assert isinstance(token, str)
        assert len(token) > 20

    def test_generate_token_unique(self):
        tokens = {ApiToken.generate_token() for _ in range(10)}
        assert len(tokens) == 10

    def test_hash_token_returns_bcrypt_hash(self):
        plaintext = ApiToken.generate_token()
        hashed = ApiToken.hash_token(plaintext)
        assert isinstance(hashed, str)
        assert hashed.startswith("$2")

    def test_hash_token_different_each_time(self):
        plaintext = "test-token"
        hash1 = ApiToken.hash_token(plaintext)
        hash2 = ApiToken.hash_token(plaintext)
        assert hash1 != hash2  # different salts


class TestApiTokenVerify:
    """Tests for token verification."""

    def test_verify_correct_token(self):
        plaintext = ApiToken.generate_token()
        token = ApiToken(
            name="test",
            token_hash=ApiToken.hash_token(plaintext),
        )
        assert token.verify(plaintext) is True

    def test_verify_wrong_token(self):
        plaintext = ApiToken.generate_token()
        token = ApiToken(
            name="test",
            token_hash=ApiToken.hash_token(plaintext),
        )
        assert token.verify("wrong-token") is False

    def test_verify_empty_token(self):
        plaintext = ApiToken.generate_token()
        token = ApiToken(
            name="test",
            token_hash=ApiToken.hash_token(plaintext),
        )
        assert token.verify("") is False


class TestApiTokenSerialization:
    """Tests for to_dict / from_dict round-trip."""

    def test_to_dict_has_expected_keys(self):
        token = ApiToken(name="my-token", token_hash="hash", created_by="admin")
        d = token.to_dict()
        assert d["_id"] == token.id
        assert d["name"] == "my-token"
        assert d["token_hash"] == "hash"
        assert d["created_by"] == "admin"
        assert "created_at" in d

    def test_round_trip(self):
        original = ApiToken(name="round-trip", token_hash="hash123", created_by="user1")
        d = original.to_dict()
        restored = ApiToken.from_dict(d)
        assert restored.id == original.id
        assert restored.name == original.name
        assert restored.token_hash == original.token_hash
        assert restored.created_by == original.created_by

    def test_from_dict_missing_fields(self):
        token = ApiToken.from_dict({})
        assert token.name == ""
        assert token.token_hash == ""
        assert token.created_by == ""

    def test_from_dict_uses_id_fallback(self):
        token = ApiToken.from_dict({"id": "abc123"})
        assert token.id == "abc123"
