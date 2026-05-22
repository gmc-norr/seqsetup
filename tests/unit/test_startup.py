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
        monkeypatch.setenv("SEQSETUP_SESSION_SECRET", "env-secret-value")
        with patch.object(startup, "SESSKEY_PATH", tmp_path / "ignored.sesskey"):
            secret = startup.resolve_session_secret()
        assert secret == "env-secret-value"
        # Env var must not cause a file write.
        assert not (tmp_path / "ignored.sesskey").exists()

    def test_existing_file_used_when_present(self, tmp_path, monkeypatch):
        monkeypatch.delenv("SEQSETUP_SESSION_SECRET", raising=False)
        keyfile = tmp_path / ".sesskey"
        keyfile.write_text("file-secret-value")
        with patch.object(startup, "SESSKEY_PATH", keyfile):
            secret = startup.resolve_session_secret()
        assert secret == "file-secret-value"

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
