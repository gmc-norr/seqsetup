"""Tests for AuthService config loading edge cases."""

import pytest

from seqsetup.services.auth import AuthService, AuthenticationError


def _write_users_file(tmp_path, content: str):
    path = tmp_path / "users.yaml"
    path.write_text(content, encoding="utf-8")
    return path


class TestAuthServiceConfigLoading:
    """Coverage for YAML edge cases in file-based auth fallback."""

    def test_load_users_empty_yaml_returns_empty_mapping(self, tmp_path):
        path = _write_users_file(tmp_path, "")
        service = AuthService(path)
        assert service._load_users() == {}

    def test_load_users_rejects_non_mapping_top_level(self, tmp_path):
        path = _write_users_file(tmp_path, "- not-a-mapping")
        service = AuthService(path)
        with pytest.raises(ValueError):
            service._load_users()

    def test_load_users_rejects_non_mapping_users_section(self, tmp_path):
        path = _write_users_file(tmp_path, "users:\n  - bad-entry")
        service = AuthService(path)
        with pytest.raises(ValueError):
            service._load_users()

    def test_authenticate_masks_invalid_yaml_structure(self, tmp_path):
        path = _write_users_file(tmp_path, "- not-a-mapping")
        service = AuthService(path)
        with pytest.raises(AuthenticationError):
            service.authenticate("admin", "secret")


class TestLoginTimingEqualisation:
    """An unknown username must still incur a bcrypt comparison so response
    timing doesn't reveal whether the account exists (user enumeration).
    """

    def _service_with_one_user(self, tmp_path):
        from seqsetup.services.auth import AuthService as _AS

        path = _write_users_file(
            tmp_path,
            "users:\n"
            "  alice:\n"
            f"    password_hash: \"{_AS.hash_password('correct-pw')}\"\n"
            "    role: standard\n",
        )
        return AuthService(path)

    def test_unknown_user_still_runs_bcrypt(self, tmp_path, monkeypatch):
        service = self._service_with_one_user(tmp_path)
        calls = []
        orig = service._verify_password
        monkeypatch.setattr(
            service,
            "_verify_password",
            lambda pw, h: (calls.append(h), orig(pw, h))[1],
        )
        with pytest.raises(AuthenticationError):
            service.authenticate("ghost-user", "whatever")
        # A bcrypt comparison ran even though the user does not exist.
        assert len(calls) == 1

    def test_known_user_wrong_password_runs_bcrypt_once(self, tmp_path, monkeypatch):
        service = self._service_with_one_user(tmp_path)
        calls = []
        orig = service._verify_password
        monkeypatch.setattr(
            service,
            "_verify_password",
            lambda pw, h: (calls.append(h), orig(pw, h))[1],
        )
        with pytest.raises(AuthenticationError):
            service.authenticate("alice", "wrong-pw")
        # Exactly one bcrypt comparison (the real hash); no extra dummy run.
        assert len(calls) == 1

    def test_correct_credentials_still_authenticate(self, tmp_path):
        service = self._service_with_one_user(tmp_path)
        user = service.authenticate("alice", "correct-pw")
        assert user.username == "alice"
