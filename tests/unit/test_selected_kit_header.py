"""The X-Selected-Kit request header: what selected_kit_id() reads from it.

app.js puts the kit the page's index-kit dropdown shows on every HTMX
request, URI-encoded (header values must be Latin-1, kit names need not
be). The server decodes it and caps its length; the value is only ever
compared with existing kit ids.
"""

from urllib.parse import quote

from starlette.requests import Request

from seqsetup.routes.utils import selected_kit_id


def _request(value: str) -> Request:
    """A request carrying ``value`` as the X-Selected-Kit header."""
    return Request({"type": "http", "headers": [(b"x-selected-kit", value.encode("latin-1"))]})


class TestSelectedKitId:
    """Reads the header, URI-decodes it, caps the decoded value at 512."""

    def test_returns_empty_string_without_the_header(self):
        assert selected_kit_id(Request({"type": "http", "headers": []})) == ""

    def test_returns_an_ascii_kit_id_unchanged(self):
        assert selected_kit_id(_request(quote("TestKit:1.0"))) == "TestKit:1.0"

    def test_decodes_a_uri_encoded_non_ascii_kit_id(self):
        assert selected_kit_id(_request(quote("Kit — ü:1.0"))) == "Kit — ü:1.0"

    def test_caps_a_long_value_at_512_characters(self):
        assert selected_kit_id(_request(quote("A" * 600))) == "A" * 512

    def test_caps_the_decoded_value_not_the_encoded_one(self):
        # quote("ü") is six characters, so 600 of them encode to 3600 — the
        # cap has to run after unquote to leave 512 characters.
        encoded = quote("ü" * 600)
        assert len(encoded) == 3600
        assert selected_kit_id(_request(encoded)) == "ü" * 512

    def test_an_empty_header_value_is_empty(self):
        assert selected_kit_id(_request("")) == ""
