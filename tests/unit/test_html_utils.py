"""Tests for HTML and JavaScript escaping utilities."""

import pytest

from seqsetup.utils.html import escape_html_attr, escape_js_string


# ---------------------------------------------------------------------------
# escape_js_string
# ---------------------------------------------------------------------------


class TestEscapeJsString:
    """Tests for escape_js_string()."""

    def test_plain_text_unchanged(self):
        assert escape_js_string("hello world") == "hello world"

    def test_empty_string(self):
        assert escape_js_string("") == ""

    def test_single_quotes_escaped(self):
        assert escape_js_string("it's") == "it\\'s"

    def test_double_quotes_escaped(self):
        assert escape_js_string('say "hello"') == 'say \\"hello\\"'

    def test_backslash_escaped(self):
        assert escape_js_string("a\\b") == "a\\\\b"

    def test_newlines_escaped(self):
        assert escape_js_string("line1\nline2") == "line1\\nline2"

    def test_carriage_return_escaped(self):
        assert escape_js_string("line1\rline2") == "line1\\rline2"

    def test_angle_brackets_escaped(self):
        result = escape_js_string("<script>alert(1)</script>")
        assert "<" not in result
        assert ">" not in result
        assert "\\x3c" in result
        assert "\\x3e" in result

    def test_combined_xss_payload(self):
        payload = "');alert('XSS');//"
        result = escape_js_string(payload)
        # Single quotes must be escaped
        assert "'" not in result or result.count("\\'") == result.count("'")

    def test_backslash_before_quote(self):
        """Backslash is escaped first, so \\' becomes \\\\\\'."""
        result = escape_js_string("\\'")
        # Input is: \' (backslash + single quote)
        # Step 1: \ -> \\ gives: \\'
        # Step 2: ' -> \' gives: \\\'
        assert result == "\\\\\\'"


# ---------------------------------------------------------------------------
# escape_html_attr
# ---------------------------------------------------------------------------


class TestEscapeHtmlAttr:
    """Tests for escape_html_attr()."""

    def test_plain_text_unchanged(self):
        assert escape_html_attr("hello") == "hello"

    def test_empty_string(self):
        assert escape_html_attr("") == ""

    def test_ampersand_escaped(self):
        assert escape_html_attr("a&b") == "a&amp;b"

    def test_angle_brackets_escaped(self):
        result = escape_html_attr("<script>")
        assert "&lt;" in result
        assert "&gt;" in result

    def test_double_quotes_escaped(self):
        assert escape_html_attr('say "hi"') == "say &quot;hi&quot;"

    def test_single_quotes_escaped(self):
        result = escape_html_attr("it's")
        assert "&#x27;" in result or "&apos;" in result or "'" not in result.replace("&#x27;", "").replace("&apos;", "")

    def test_combined_html_injection(self):
        payload = '" onmouseover="alert(1)" foo="'
        result = escape_html_attr(payload)
        assert '"' not in result  # all quotes should be entity-encoded
