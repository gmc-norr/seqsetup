"""Tests for the binary-content check on index kit uploads.

Index kits must be text (YAML/CSV/TSV). The admin-supplied extension is
unreliable as a signal; content sniffing catches a mis-selected PDF / xlsx /
exe before the parser eats it.
"""

import pytest

from seqsetup.routes.indexes import _reject_binary_upload


class TestRejectBinaryUpload:
    def test_empty_content_allowed(self):
        # An empty file is handled by the upstream "no file" check; this helper passes through.
        assert _reject_binary_upload(b"") is None

    def test_plain_yaml_allowed(self):
        assert _reject_binary_upload(b"name: Test\nversion: '1.0'\n") is None

    def test_plain_csv_allowed(self):
        assert _reject_binary_upload(b"Sample_ID,Index1,Index2\nS1,ATCG,GCTA\n") is None

    def test_plain_tsv_allowed(self):
        assert _reject_binary_upload(b"Sample_ID\tIndex1\tIndex2\nS1\tATCG\tGCTA\n") is None

    def test_yaml_with_utf8_chars_allowed(self):
        # Non-ASCII text is fine — valid UTF-8.
        assert _reject_binary_upload("description: Café Kit\n".encode("utf-8")) is None

    def test_pdf_rejected(self):
        assert "binary" in _reject_binary_upload(b"%PDF-1.4\n%abc\n").lower()

    def test_xlsx_zip_rejected(self):
        # Excel files are zip archives starting with PK
        msg = _reject_binary_upload(b"PK\x03\x04rest-of-zip")
        assert msg is not None
        assert "binary" in msg.lower()

    def test_png_rejected(self):
        assert _reject_binary_upload(b"\x89PNG\r\n\x1a\nrest") is not None

    def test_gzip_rejected(self):
        assert _reject_binary_upload(b"\x1f\x8b\x08\x00rest") is not None

    def test_elf_rejected(self):
        assert _reject_binary_upload(b"\x7fELFrest") is not None

    def test_pe_exe_rejected(self):
        assert _reject_binary_upload(b"MZrest-of-exe") is not None

    def test_nul_byte_rejected(self):
        # Plain text shouldn't contain NUL — UTF-16 docs do.
        assert _reject_binary_upload(b"some text\x00more text") is not None

    def test_invalid_utf8_rejected(self):
        # Random binary garbage that's not a known magic-byte signature.
        assert _reject_binary_upload(b"\xc3\x28\xc3\x28\xc3\x28") is not None

    def test_long_valid_yaml_allowed(self):
        # Make sure the 8KB sniff isn't itself rejecting valid input.
        content = ("# comment\n" * 5000).encode("utf-8")
        assert _reject_binary_upload(content) is None
