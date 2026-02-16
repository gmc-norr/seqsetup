"""Tests for route utility functions."""

import pytest

from seqsetup.models.sequencing_run import RunStatus, SequencingRun
from seqsetup.routes.utils import (
    check_run_editable,
    get_username,
    require_admin,
    sanitize_filename,
)


# ---------------------------------------------------------------------------
# Helpers — lightweight request/user stubs
# ---------------------------------------------------------------------------


class _FakeUser:
    def __init__(self, username="testuser", role=None):
        self.username = username
        from seqsetup.models.user import UserRole
        self.role = role or UserRole.STANDARD


class _FakeApiToken:
    def __init__(self, name="my-token"):
        self.name = name


class _FakeRequest:
    """Minimal request stub with a scope dict."""

    def __init__(self, auth=None, api_token=None):
        self.scope = {}
        if auth is not None:
            self.scope["auth"] = auth
        if api_token is not None:
            self.scope["api_token"] = api_token


# ---------------------------------------------------------------------------
# get_username
# ---------------------------------------------------------------------------


class TestGetUsername:
    """Tests for get_username()."""

    def test_returns_username_from_auth(self):
        req = _FakeRequest(auth=_FakeUser(username="alice"))
        assert get_username(req) == "alice"

    def test_returns_api_token_name(self):
        req = _FakeRequest(api_token=_FakeApiToken(name="pipeline-bot"))
        assert get_username(req) == "api:pipeline-bot"

    def test_auth_takes_precedence_over_api_token(self):
        req = _FakeRequest(
            auth=_FakeUser(username="alice"),
            api_token=_FakeApiToken(name="bot"),
        )
        assert get_username(req) == "alice"

    def test_returns_empty_when_no_auth(self):
        req = _FakeRequest()
        assert get_username(req) == ""


# ---------------------------------------------------------------------------
# check_run_editable
# ---------------------------------------------------------------------------


class TestCheckRunEditable:
    """Tests for check_run_editable()."""

    def test_draft_run_is_editable(self):
        run = SequencingRun(status=RunStatus.DRAFT)
        assert check_run_editable(run) is None

    def test_ready_run_is_not_editable(self):
        run = SequencingRun(status=RunStatus.READY)
        resp = check_run_editable(run)
        assert resp is not None
        assert resp.status_code == 403

    def test_archived_run_is_not_editable(self):
        run = SequencingRun(status=RunStatus.ARCHIVED)
        resp = check_run_editable(run)
        assert resp is not None
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# require_admin
# ---------------------------------------------------------------------------


class TestRequireAdmin:
    """Tests for require_admin()."""

    def test_admin_user_allowed(self):
        from seqsetup.models.user import UserRole
        req = _FakeRequest(auth=_FakeUser(role=UserRole.ADMIN))
        assert require_admin(req) is None

    def test_standard_user_rejected(self):
        from seqsetup.models.user import UserRole
        req = _FakeRequest(auth=_FakeUser(role=UserRole.STANDARD))
        resp = require_admin(req)
        assert resp is not None
        assert resp.status_code == 403

    def test_no_auth_rejected(self):
        req = _FakeRequest()
        resp = require_admin(req)
        assert resp is not None
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# sanitize_filename
# ---------------------------------------------------------------------------


class TestSanitizeFilename:
    """Tests for sanitize_filename()."""

    def test_normal_filename_unchanged(self):
        assert sanitize_filename("MyRun_001") == "MyRun_001"

    def test_spaces_replaced_with_underscores(self):
        assert sanitize_filename("My Run 001") == "My_Run_001"

    def test_special_chars_stripped(self):
        result = sanitize_filename("run<>:\"/\\|?*name")
        # Only word chars, hyphens, dots, spaces (which become underscores) survive
        assert "<" not in result
        assert ">" not in result
        assert "/" not in result
        assert "\\" not in result
        assert "?" not in result
        assert "*" not in result

    def test_empty_string_returns_default(self):
        assert sanitize_filename("") == "export"

    def test_empty_string_returns_custom_default(self):
        assert sanitize_filename("", default="samplesheet") == "samplesheet"

    def test_all_special_chars_returns_default(self):
        assert sanitize_filename("!@#$%^&*()") == "export"

    def test_truncated_to_100_chars(self):
        long_name = "A" * 200
        result = sanitize_filename(long_name)
        assert len(result) == 100

    def test_directory_traversal_stripped(self):
        result = sanitize_filename("../../../etc/passwd")
        assert ".." not in result
        assert "/" not in result

    def test_header_injection_stripped(self):
        result = sanitize_filename("file\r\nContent-Type: text/html")
        assert "\r" not in result
        assert "\n" not in result

    def test_leading_trailing_dots_stripped(self):
        result = sanitize_filename("...hidden...")
        assert not result.startswith(".")
        assert not result.endswith(".")

    def test_hyphen_and_dot_preserved(self):
        assert sanitize_filename("run-001.csv") == "run-001.csv"
