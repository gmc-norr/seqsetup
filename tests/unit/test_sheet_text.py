"""The rules for text written into a Sample Sheet (audit 2026-09 N-10, N-11, N-12)."""

import pytest

from seqsetup.services.sheet_text import (
    PLAIN_NAME_RE,
    PLAIN_VERSION_RE,
    describe,
    hidden_characters,
    refuse_hidden_characters,
    starts_a_section,
)


class TestPlainName:
    """A name written into the sheet's structure: letters, digits, '_' and '-'."""

    @pytest.mark.parametrize("value", ["BCLConvert", "NovaSeqXSeries", "Dragen_Germline-2", "a"])
    def test_plain_names_match(self, value):
        assert PLAIN_NAME_RE.fullmatch(value)

    @pytest.mark.parametrize("value", ["", "a b", "a,b", "a]", "a\n", "a.b", "Äpp", "a\x00"])
    def test_other_names_do_not_match(self, value):
        assert not PLAIN_NAME_RE.fullmatch(value)


class TestPlainVersion:
    """A software version: a plain name that may also hold '.'."""

    @pytest.mark.parametrize("value", ["4.3.6", "4.2.7-beta_1"])
    def test_plain_versions_match(self, value):
        assert PLAIN_VERSION_RE.fullmatch(value)

    @pytest.mark.parametrize("value", ["", "4.3 6", "4,3", "4.3.6\n"])
    def test_other_versions_do_not_match(self, value):
        assert not PLAIN_VERSION_RE.fullmatch(value)


class TestHiddenCharacters:
    """Control characters and the Unicode line/paragraph separators."""

    @pytest.mark.parametrize("char", [
        "\x00", "\t", "\n", "\r", "\x0b", "\x0c", "\x1f", "\x7f", "\x85", "\x9b",
        "\u2028", "\u2029",
    ])
    def test_finds_each_hidden_character(self, char):
        assert hidden_characters(f"a{char}b") == [char]

    def test_lists_each_character_once_in_order_of_first_appearance(self):
        assert hidden_characters("\t a \x00 b \t") == ["\t", "\x00"]

    @pytest.mark.parametrize("text", [
        "", "Plain text 1-2_3", "Åsa Öberg", "试验", "Проект", "a b", "2 × 150",
    ])
    def test_finds_nothing_in_visible_text(self, text):
        assert hidden_characters(text) == []

    def test_none_counts_as_empty(self):
        assert hidden_characters(None) == []


class TestDescribe:
    """Character codes for messages; a tab is named."""

    def test_codes_with_tab_named(self):
        assert describe(["\x00", "\t", "\u2028"]) == "U+0000, U+0009 (tab), U+2028"


class TestRefuseHiddenCharacters:
    """One place raises the error for text that may not reach the sheet."""

    @pytest.mark.parametrize("char", ["\n", "\r", "\t", "\x00", "\u2028"])
    def test_refuses_every_hidden_character_by_default(self, char):
        with pytest.raises(ValueError, match=f"U\\+{ord(char):04X}"):
            refuse_hidden_characters(f"a{char}b")

    def test_allowed_characters_pass(self):
        refuse_hidden_characters("a\tb\nc\rd", allow="\t\n\r")

    def test_other_characters_still_refused_when_some_are_allowed(self):
        with pytest.raises(ValueError, match="U\\+0000"):
            refuse_hidden_characters("a\tb\x00", allow="\t\n\r")

    def test_message_names_codes_not_the_text(self):
        with pytest.raises(ValueError) as exc:
            refuse_hidden_characters("Patient-Name\x00X")
        assert "Patient-Name" not in str(exc.value)
        assert str(exc.value) == "Hidden character (U+0000) cannot be written to the Sample Sheet"

    def test_visible_text_passes(self):
        refuse_hidden_characters("Åsa Öberg, 2 × 150")


class TestStartsASection:
    """A value that starts with '[' would start a new section when it is
    the first cell on its line."""

    @pytest.mark.parametrize("value", ["[Junk]", "[", " [BCLConvert_Data]"])
    def test_leading_bracket_starts_a_section(self, value):
        assert starts_a_section(value)

    @pytest.mark.parametrize("value", ["", "gzip", "a[b]", "x]", "'[x"])
    def test_other_text_does_not(self, value):
        assert not starts_a_section(value)
