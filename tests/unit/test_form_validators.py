"""Tests for shared Pydantic form validators."""

import pytest

from seqsetup.forms.validators import (
    clamp,
    dna_upper_or_reject,
    json_list,
    strip_and_truncate,
)


class TestStripAndTruncate:
    def test_strips_whitespace(self):
        assert strip_and_truncate(256)("  hello  ") == "hello"

    def test_truncates_to_max_len(self):
        assert strip_and_truncate(5)("hello world") == "hello"

    def test_strip_happens_before_truncate(self):
        assert strip_and_truncate(5)("   hello world   ") == "hello"

    def test_none_becomes_empty(self):
        assert strip_and_truncate(256)(None) == ""

    def test_empty_becomes_empty(self):
        assert strip_and_truncate(256)("") == ""


class TestClamp:
    def test_in_range_unchanged(self):
        assert clamp(0, 10)(5) == 5

    def test_below_min_clamps_up(self):
        assert clamp(0, 10)(-5) == 0

    def test_above_max_clamps_down(self):
        assert clamp(0, 10)(99) == 10

    def test_string_int_accepted(self):
        assert clamp(0, 10)("5") == 5

    def test_non_int_raises(self):
        with pytest.raises(ValueError):
            clamp(0, 10)("not an int")


class TestDnaUpperOrReject:
    def test_lowercase_is_uppercased(self):
        assert dna_upper_or_reject("acgtn") == "ACGTN"

    def test_already_uppercase_unchanged(self):
        assert dna_upper_or_reject("ACGT") == "ACGT"

    def test_whitespace_stripped(self):
        assert dna_upper_or_reject("  ACGT  ") == "ACGT"

    def test_empty_ok(self):
        assert dna_upper_or_reject("") == ""

    def test_none_ok(self):
        assert dna_upper_or_reject(None) == ""

    def test_invalid_base_rejected(self):
        with pytest.raises(ValueError):
            dna_upper_or_reject("ACGTX")

    def test_digit_rejected(self):
        with pytest.raises(ValueError):
            dna_upper_or_reject("ACGT1")


class TestJsonList:
    def test_passes_list_through(self):
        assert json_list()(["a", "b"]) == ["a", "b"]

    def test_decodes_json_string(self):
        assert json_list()('["a","b"]') == ["a", "b"]

    def test_empty_array(self):
        assert json_list()("[]") == []

    def test_bad_json_raises(self):
        with pytest.raises(ValueError):
            json_list()("not json")

    def test_json_object_rejected(self):
        with pytest.raises(ValueError):
            json_list()('{"a": 1}')

    def test_non_string_non_list_rejected(self):
        with pytest.raises(ValueError):
            json_list()(42)
