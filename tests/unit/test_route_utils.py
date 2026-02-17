"""Tests for route utility functions."""

import pytest

from seqsetup.models.sequencing_run import RunStatus, SequencingRun
from seqsetup.routes.utils import (
    check_run_editable,
    get_username,
    require_admin,
    sanitize_filename,
    sanitize_string,
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

# ---------------------------------------------------------------------------
# sanitize_string
# ---------------------------------------------------------------------------


class TestSanitizeString:
    """Tests for sanitize_string()."""

    def test_plain_text_unchanged(self):
        assert sanitize_string("hello world") == "hello world"

    def test_empty_string_returns_empty(self):
        assert sanitize_string("") == ""

    def test_whitespace_stripped_leading(self):
        assert sanitize_string("  hello") == "hello"

    def test_whitespace_stripped_trailing(self):
        assert sanitize_string("hello  ") == "hello"

    def test_whitespace_stripped_both_sides(self):
        assert sanitize_string("  hello world  ") == "hello world"

    def test_tabs_and_newlines_stripped(self):
        assert sanitize_string("\t\nhello\n\t") == "hello"

    def test_internal_whitespace_preserved(self):
        assert sanitize_string("hello  world") == "hello  world"

    def test_default_max_length_256(self):
        long_str = "A" * 300
        result = sanitize_string(long_str)
        assert len(result) == 256
        assert result == "A" * 256

    def test_custom_max_length_applied(self):
        long_str = "B" * 500
        result = sanitize_string(long_str, max_len=100)
        assert len(result) == 100
        assert result == "B" * 100

    def test_max_length_1024(self):
        long_str = "C" * 2000
        result = sanitize_string(long_str, max_len=1024)
        assert len(result) == 1024

    def test_max_length_4096(self):
        long_str = "D" * 5000
        result = sanitize_string(long_str, max_len=4096)
        assert len(result) == 4096

    def test_max_length_128(self):
        long_str = "E" * 200
        result = sanitize_string(long_str, max_len=128)
        assert len(result) == 128

    def test_max_length_1_edge_case(self):
        result = sanitize_string("hello", max_len=1)
        assert result == "h"
        assert len(result) == 1

    def test_max_length_0_edge_case(self):
        result = sanitize_string("hello", max_len=0)
        assert result == ""

    def test_unicode_characters_preserved(self):
        assert sanitize_string("café") == "café"

    def test_emoji_preserved(self):
        emoji_str = "run 🧪 test"
        assert sanitize_string(emoji_str) == emoji_str

    def test_unicode_with_length_limit(self):
        # 3-char emoji + 3 ASCII = 6 "chars" by len(), but emoji is multi-byte
        unicode_str = "🧪🧪🧪abc"
        result = sanitize_string(unicode_str, max_len=6)
        assert len(result) == 6

    def test_special_characters_preserved(self):
        special = "run@domain.com"
        assert sanitize_string(special) == special

    def test_punctuation_preserved(self):
        punct = "patient#123 (control); test-1"
        assert sanitize_string(punct) == punct

    def test_quotes_preserved(self):
        quotes = 'sample "ABC" / \'XYZ\''
        assert sanitize_string(quotes) == quotes

    def test_dna_sequence_preserved(self):
        dna = "ATCGATCGATCG"
        assert sanitize_string(dna) == dna

    def test_mixed_case_preserved(self):
        mixed = "MiXeD CaSe TeSt"
        assert sanitize_string(mixed) == mixed

    def test_numbers_preserved(self):
        nums = "sample_123_456_789"
        assert sanitize_string(nums) == nums

    def test_html_content_not_escaped(self):
        """sanitize_string does NOT escape HTML - that's a separate function."""
        html = "<script>alert('test')</script>"
        # sanitize_string just strips whitespace and limits length
        assert sanitize_string(html) == html

    def test_sql_injection_not_escaped(self):
        """sanitize_string does NOT escape SQL - that's the ORM's job."""
        sql = "'; DROP TABLE users; --"
        assert sanitize_string(sql) == sql

    def test_newline_preserved(self):
        """Internal newlines are preserved (unlike sanitize_filename)."""
        multiline = "line1\nline2"
        assert sanitize_string(multiline) == multiline

    def test_carriage_return_preserved(self):
        """Carriage returns are preserved."""
        crlf = "line1\rline2"
        assert sanitize_string(crlf) == crlf

    def test_null_bytes_preserved(self):
        """Null bytes are preserved (for db compatibility)."""
        with_null = "hello\x00world"
        assert sanitize_string(with_null) == with_null

    def test_rtrim_lstrip_only(self):
        """Only left/right whitespace is trimmed, internal is preserved."""
        s = "  a  b  c  "
        result = sanitize_string(s)
        assert result == "a  b  c"

    def test_truncation_happens_after_strip(self):
        """Strip before limit - don't count leading spaces in truncation."""
        s = "   " + "A" * 300
        result = sanitize_string(s, max_len=256)
        # After strip: 300 A's, truncate to 256
        assert len(result) == 256
        assert result == "A" * 256

    def test_clinical_example_patient_name(self):
        """Real-world example: clinical patient name with strip & limit."""
        name = "   John Q. O'Brien-Smith III   "
        result = sanitize_string(name, max_len=50)
        assert result == "John Q. O'Brien-Smith III"

    def test_clinical_example_dna_sequence(self):
        """Real-world example: DNA sequence with limit."""
        seq = "ATCGATCGATCGATCGATCGATCGATCG  "
        result = sanitize_string(seq, max_len=20)
        assert result == "ATCGATCGATCGATCGATCG"

    def test_clinical_example_test_id_with_spaces(self):
        """Real-world example: test ID with spaces."""
        test_id = "  TEST-2024-001234  "
        result = sanitize_string(test_id, max_len=256)
        assert result == "TEST-2024-001234"

    def test_long_description_truncation(self):
        """Real-world example: long description gets truncated at max_len=4096."""
        long_desc = "A" * 5000
        result = sanitize_string(long_desc, max_len=4096)
        assert len(result) == 4096

    def test_url_preserved(self):
        url = "https://github.com/user/repo.git"
        assert sanitize_string(url) == url

    def test_file_path_preserved(self):
        path = "/path/to/file.txt"
        assert sanitize_string(path) == path

    def test_ipv4_address_preserved(self):
        ip = "192.168.1.1"
        assert sanitize_string(ip) == ip

    def test_json_like_content_preserved(self):
        """Real-world: JSON config in field doesn't get escaped."""
        json_str = '{"key":"value","num":123}'
        assert sanitize_string(json_str) == json_str

    def test_very_long_max_len(self):
        """Edge case: very large max_len."""
        s = "A" * 100
        result = sanitize_string(s, max_len=999999)
        assert result == s  # Not truncated

    def test_zero_length_string_empty_max(self):
        """Both zero."""
        assert sanitize_string("", max_len=0) == ""

    def test_idempotent_double_sanitize(self):
        """Sanitizing twice gives same result as once."""
        s = "  test  "
        once = sanitize_string(s, max_len=256)
        twice = sanitize_string(once, max_len=256)
        assert once == twice