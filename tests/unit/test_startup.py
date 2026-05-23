"""Tests for application startup helpers."""

import os
import stat
from pathlib import Path
from unittest.mock import patch

import pytest

from seqsetup import startup


class TestResolveSessionSecret:
    """The session secret can come from env var (preferred), an existing
    .sesskey file, or be freshly generated. Generated files must not be
    world- or group-readable — anyone with FS access could forge sessions.
    """

    def test_env_var_used_when_set(self, tmp_path, monkeypatch):
        # Must be >= 32 chars per the length check.
        env_secret = "a" * 64
        monkeypatch.setenv("SEQSETUP_SESSION_SECRET", env_secret)
        with patch.object(startup, "SESSKEY_PATH", tmp_path / "ignored.sesskey"):
            secret = startup.resolve_session_secret()
        assert secret == env_secret
        # Env var must not cause a file write.
        assert not (tmp_path / "ignored.sesskey").exists()

    def test_short_env_var_secret_rejected(self, tmp_path, monkeypatch):
        """Refuse a too-short env-var secret rather than silently weaken signing."""
        monkeypatch.setenv("SEQSETUP_SESSION_SECRET", "tiny")
        with patch.object(startup, "SESSKEY_PATH", tmp_path / "ignored.sesskey"):
            with pytest.raises(RuntimeError, match="too short"):
                startup.resolve_session_secret()

    def test_existing_file_used_when_present(self, tmp_path, monkeypatch):
        import os
        monkeypatch.delenv("SEQSETUP_SESSION_SECRET", raising=False)
        keyfile = tmp_path / ".sesskey"
        file_secret = "b" * 64
        keyfile.write_text(file_secret)
        os.chmod(keyfile, 0o600)  # match the on-disk expectation
        with patch.object(startup, "SESSKEY_PATH", keyfile):
            secret = startup.resolve_session_secret()
        assert secret == file_secret

    def test_insecure_sesskey_file_permissions_rejected(self, tmp_path, monkeypatch):
        """A pre-existing .sesskey with group/world-readable perms is refused."""
        import os
        monkeypatch.delenv("SEQSETUP_SESSION_SECRET", raising=False)
        keyfile = tmp_path / ".sesskey"
        keyfile.write_text("c" * 64)
        os.chmod(keyfile, 0o644)  # group/world readable — must be refused
        with patch.object(startup, "SESSKEY_PATH", keyfile):
            with pytest.raises(RuntimeError, match="insecure permissions"):
                startup.resolve_session_secret()

    def test_short_file_secret_rejected(self, tmp_path, monkeypatch):
        import os
        monkeypatch.delenv("SEQSETUP_SESSION_SECRET", raising=False)
        keyfile = tmp_path / ".sesskey"
        keyfile.write_text("only-31-chars-which-is-too-shrt")
        os.chmod(keyfile, 0o600)
        with patch.object(startup, "SESSKEY_PATH", keyfile):
            with pytest.raises(RuntimeError, match="too short"):
                startup.resolve_session_secret()

    def test_generated_file_is_owner_only(self, tmp_path, monkeypatch):
        """A fresh .sesskey must be 0600 — readable/writable only by the owner."""
        monkeypatch.delenv("SEQSETUP_SESSION_SECRET", raising=False)
        keyfile = tmp_path / ".sesskey"
        assert not keyfile.exists()
        with patch.object(startup, "SESSKEY_PATH", keyfile):
            secret = startup.resolve_session_secret()
        assert secret  # non-empty
        assert keyfile.exists()
        mode = stat.S_IMODE(keyfile.stat().st_mode)
        assert mode == 0o600, (
            f"Expected 0o600 (owner read+write only), got {oct(mode)}. "
            f"World/group access to .sesskey lets anyone forge sessions."
        )
