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
