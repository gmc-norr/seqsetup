"""Tests for index kit CSV validators."""

import pytest

from sequencing_run_setup.models.index import (
    Index,
    IndexKit,
    IndexMode,
    IndexPair,
    IndexType,
)
from sequencing_run_setup.services.index_validator import IndexValidator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_pair(name: str, i7_seq: str, i5_seq: str | None = None) -> IndexPair:
    """Create an IndexPair for testing."""
    index1 = Index(name=name, sequence=i7_seq, index_type=IndexType.I7)
    index2 = (
        Index(name=name, sequence=i5_seq, index_type=IndexType.I5)
        if i5_seq
        else None
    )
    return IndexPair(id=f"test_{name}", name=name, index1=index1, index2=index2)


def _make_index(name: str, seq: str, idx_type: IndexType) -> Index:
    return Index(name=name, sequence=seq, index_type=idx_type)


# ---------------------------------------------------------------------------
# Unique Dual mode
# ---------------------------------------------------------------------------


class TestUniqueDualValidation:
    def test_valid_kit(self):
        kit = IndexKit(
            name="UDI Kit",
            index_mode=IndexMode.UNIQUE_DUAL,
            index_pairs=[
                _make_pair("UDP001", "AACCGGTT", "TTGGCCAA"),
                _make_pair("UDP002", "CCGGAATT", "GGCCTTAA"),
            ],
        )
        result = IndexValidator.validate(kit)
        assert result.is_valid
        assert result.errors == []

    def test_empty_pairs(self):
        kit = IndexKit(name="Empty", index_mode=IndexMode.UNIQUE_DUAL, index_pairs=[])
        result = IndexValidator.validate(kit)
        assert not result.is_valid
        assert any("at least one index pair" in e for e in result.errors)

    def test_missing_i5_sequence(self):
        kit = IndexKit(
            name="No i5",
            index_mode=IndexMode.UNIQUE_DUAL,
            index_pairs=[_make_pair("UDP001", "AACCGGTT", None)],
        )
        result = IndexValidator.validate(kit)
        assert not result.is_valid
        assert any("i5" in e and "required" in e for e in result.errors)

    def test_missing_i7_sequence(self):
        pair = IndexPair(
            id="test",
            name="bad",
            index1=Index(name="bad", sequence="", index_type=IndexType.I7),
            index2=Index(name="bad", sequence="AACCGGTT", index_type=IndexType.I5),
        )
        kit = IndexKit(
            name="No i7",
            index_mode=IndexMode.UNIQUE_DUAL,
            index_pairs=[pair],
        )
        result = IndexValidator.validate(kit)
        assert not result.is_valid
        assert any("i7" in e and "required" in e for e in result.errors)

    def test_invalid_dna_characters(self):
        kit = IndexKit(
            name="Bad DNA",
            index_mode=IndexMode.UNIQUE_DUAL,
            index_pairs=[_make_pair("UDP001", "AAXCGGTT", "TTGGCCAA")],
        )
        result = IndexValidator.validate(kit)
        assert not result.is_valid
        assert any("invalid characters" in e for e in result.errors)

    def test_duplicate_pair_names(self):
        kit = IndexKit(
            name="Dups",
            index_mode=IndexMode.UNIQUE_DUAL,
            index_pairs=[
                _make_pair("UDP001", "AACCGGTT", "TTGGCCAA"),
                _make_pair("UDP001", "CCGGAATT", "GGCCTTAA"),
            ],
        )
        result = IndexValidator.validate(kit)
        assert not result.is_valid
        assert any("Duplicate" in e for e in result.errors)

    def test_inconsistent_i7_lengths_warns(self):
        kit = IndexKit(
            name="Mixed",
            index_mode=IndexMode.UNIQUE_DUAL,
            index_pairs=[
                _make_pair("UDP001", "AACCGGTT", "TTGGCCAA"),
                _make_pair("UDP002", "CCGGAA", "GGCCTT"),
            ],
        )
        result = IndexValidator.validate(kit)
        assert result.is_valid  # warnings, not errors
        assert any("inconsistent lengths" in w for w in result.warnings)

    def test_n_allowed_in_sequence(self):
        kit = IndexKit(
            name="With N",
            index_mode=IndexMode.UNIQUE_DUAL,
            index_pairs=[_make_pair("UDP001", "AACCGNTT", "TTGGNCAA")],
        )
        result = IndexValidator.validate(kit)
        assert result.is_valid


# ---------------------------------------------------------------------------
# Combinatorial mode
# ---------------------------------------------------------------------------


class TestCombinatorialValidation:
    def test_valid_kit(self):
        kit = IndexKit(
            name="Combo",
            index_mode=IndexMode.COMBINATORIAL,
            i7_indexes=[
                _make_index("A", "AACCGGTT", IndexType.I7),
                _make_index("B", "CCGGAATT", IndexType.I7),
            ],
            i5_indexes=[
                _make_index("01", "TTGGCCAA", IndexType.I5),
                _make_index("02", "GGCCTTAA", IndexType.I5),
            ],
        )
        result = IndexValidator.validate(kit)
        assert result.is_valid

    def test_missing_i7(self):
        kit = IndexKit(
            name="No i7",
            index_mode=IndexMode.COMBINATORIAL,
            i7_indexes=[],
            i5_indexes=[_make_index("01", "TTGGCCAA", IndexType.I5)],
        )
        result = IndexValidator.validate(kit)
        assert not result.is_valid
        assert any("i7" in e for e in result.errors)

    def test_missing_i5(self):
        kit = IndexKit(
            name="No i5",
            index_mode=IndexMode.COMBINATORIAL,
            i7_indexes=[_make_index("A", "AACCGGTT", IndexType.I7)],
            i5_indexes=[],
        )
        result = IndexValidator.validate(kit)
        assert not result.is_valid
        assert any("i5" in e for e in result.errors)

    def test_invalid_i7_sequence(self):
        kit = IndexKit(
            name="Bad",
            index_mode=IndexMode.COMBINATORIAL,
            i7_indexes=[_make_index("A", "ZZZZGGTT", IndexType.I7)],
            i5_indexes=[_make_index("01", "TTGGCCAA", IndexType.I5)],
        )
        result = IndexValidator.validate(kit)
        assert not result.is_valid
        assert any("invalid characters" in e for e in result.errors)

    def test_invalid_i5_sequence(self):
        kit = IndexKit(
            name="Bad",
            index_mode=IndexMode.COMBINATORIAL,
            i7_indexes=[_make_index("A", "AACCGGTT", IndexType.I7)],
            i5_indexes=[_make_index("01", "12345678", IndexType.I5)],
        )
        result = IndexValidator.validate(kit)
        assert not result.is_valid
        assert any("invalid characters" in e for e in result.errors)

    def test_duplicate_i7_names(self):
        kit = IndexKit(
            name="Dups",
            index_mode=IndexMode.COMBINATORIAL,
            i7_indexes=[
                _make_index("A", "AACCGGTT", IndexType.I7),
                _make_index("A", "CCGGAATT", IndexType.I7),
            ],
            i5_indexes=[_make_index("01", "TTGGCCAA", IndexType.I5)],
        )
        result = IndexValidator.validate(kit)
        assert not result.is_valid
        assert any("Duplicate i7" in e for e in result.errors)

    def test_duplicate_i5_names(self):
        kit = IndexKit(
            name="Dups",
            index_mode=IndexMode.COMBINATORIAL,
            i7_indexes=[_make_index("A", "AACCGGTT", IndexType.I7)],
            i5_indexes=[
                _make_index("01", "TTGGCCAA", IndexType.I5),
                _make_index("01", "GGCCTTAA", IndexType.I5),
            ],
        )
        result = IndexValidator.validate(kit)
        assert not result.is_valid
        assert any("Duplicate i5" in e for e in result.errors)

    def test_inconsistent_i7_lengths_warns(self):
        kit = IndexKit(
            name="Mixed",
            index_mode=IndexMode.COMBINATORIAL,
            i7_indexes=[
                _make_index("A", "AACCGGTT", IndexType.I7),
                _make_index("B", "CCGG", IndexType.I7),
            ],
            i5_indexes=[_make_index("01", "TTGGCCAA", IndexType.I5)],
        )
        result = IndexValidator.validate(kit)
        assert result.is_valid
        assert any("inconsistent lengths" in w for w in result.warnings)


# ---------------------------------------------------------------------------
# Single mode
# ---------------------------------------------------------------------------


class TestSingleValidation:
    def test_valid_kit(self):
        kit = IndexKit(
            name="Single",
            index_mode=IndexMode.SINGLE,
            i7_indexes=[
                _make_index("A", "AACCGGTT", IndexType.I7),
                _make_index("B", "CCGGAATT", IndexType.I7),
            ],
        )
        result = IndexValidator.validate(kit)
        assert result.is_valid

    def test_empty_i7(self):
        kit = IndexKit(name="Empty", index_mode=IndexMode.SINGLE, i7_indexes=[])
        result = IndexValidator.validate(kit)
        assert not result.is_valid
        assert any("at least one i7" in e for e in result.errors)

    def test_invalid_sequence(self):
        kit = IndexKit(
            name="Bad",
            index_mode=IndexMode.SINGLE,
            i7_indexes=[_make_index("A", "HELLO!!!", IndexType.I7)],
        )
        result = IndexValidator.validate(kit)
        assert not result.is_valid
        assert any("invalid characters" in e for e in result.errors)

    def test_duplicate_names(self):
        kit = IndexKit(
            name="Dups",
            index_mode=IndexMode.SINGLE,
            i7_indexes=[
                _make_index("A", "AACCGGTT", IndexType.I7),
                _make_index("A", "CCGGAATT", IndexType.I7),
            ],
        )
        result = IndexValidator.validate(kit)
        assert not result.is_valid
        assert any("Duplicate" in e for e in result.errors)

    def test_i5_present_warns(self):
        kit = IndexKit(
            name="Has i5",
            index_mode=IndexMode.SINGLE,
            i7_indexes=[_make_index("A", "AACCGGTT", IndexType.I7)],
            i5_indexes=[_make_index("01", "TTGGCCAA", IndexType.I5)],
        )
        result = IndexValidator.validate(kit)
        assert result.is_valid
        assert any("i5 indexes" in w for w in result.warnings)


# ---------------------------------------------------------------------------
# Common / metadata validation
# ---------------------------------------------------------------------------


class TestMetadataValidation:
    def test_empty_kit_name(self):
        kit = IndexKit(
            name="",
            index_mode=IndexMode.SINGLE,
            i7_indexes=[_make_index("A", "AACCGGTT", IndexType.I7)],
        )
        result = IndexValidator.validate(kit)
        assert not result.is_valid
        assert any("name is required" in e for e in result.errors)

    def test_invalid_adapter_read1(self):
        kit = IndexKit(
            name="Kit",
            index_mode=IndexMode.SINGLE,
            i7_indexes=[_make_index("A", "AACCGGTT", IndexType.I7)],
            adapter_read1="NOT-DNA!",
        )
        result = IndexValidator.validate(kit)
        assert not result.is_valid
        assert any("AdapterRead1" in e for e in result.errors)

    def test_invalid_adapter_read2(self):
        kit = IndexKit(
            name="Kit",
            index_mode=IndexMode.SINGLE,
            i7_indexes=[_make_index("A", "AACCGGTT", IndexType.I7)],
            adapter_read2="XYZ",
        )
        result = IndexValidator.validate(kit)
        assert not result.is_valid
        assert any("AdapterRead2" in e for e in result.errors)

    def test_valid_adapters(self):
        kit = IndexKit(
            name="Kit",
            index_mode=IndexMode.SINGLE,
            i7_indexes=[_make_index("A", "AACCGGTT", IndexType.I7)],
            adapter_read1="AGATCGGAAGAGCACACGTCTGAACTCCAGTCA",
            adapter_read2="AGATCGGAAGAGCGTCGTGTAGGGAAAGAGTGT",
        )
        result = IndexValidator.validate(kit)
        assert result.is_valid


# ---------------------------------------------------------------------------
# Version validation
# ---------------------------------------------------------------------------


class TestVersionValidation:
    def test_valid_semver_two_part(self):
        kit = IndexKit(
            name="Kit",
            version="1.0",
            index_mode=IndexMode.SINGLE,
            i7_indexes=[_make_index("A", "AACCGGTT", IndexType.I7)],
        )
        result = IndexValidator.validate(kit)
        assert result.is_valid

    def test_valid_semver_three_part(self):
        kit = IndexKit(
            name="Kit",
            version="2.1.3",
            index_mode=IndexMode.SINGLE,
            i7_indexes=[_make_index("A", "AACCGGTT", IndexType.I7)],
        )
        result = IndexValidator.validate(kit)
        assert result.is_valid

    def test_valid_semver_with_pre_release(self):
        kit = IndexKit(
            name="Kit",
            version="1.0.0a1",
            index_mode=IndexMode.SINGLE,
            i7_indexes=[_make_index("A", "AACCGGTT", IndexType.I7)],
        )
        result = IndexValidator.validate(kit)
        assert result.is_valid

    def test_invalid_version_text(self):
        kit = IndexKit(
            name="Kit",
            version="latest",
            index_mode=IndexMode.SINGLE,
            i7_indexes=[_make_index("A", "AACCGGTT", IndexType.I7)],
        )
        result = IndexValidator.validate(kit)
        assert not result.is_valid
        assert any("not a valid semantic version" in e for e in result.errors)

    def test_invalid_version_special_chars(self):
        kit = IndexKit(
            name="Kit",
            version="v1.0-beta!",
            index_mode=IndexMode.SINGLE,
            i7_indexes=[_make_index("A", "AACCGGTT", IndexType.I7)],
        )
        result = IndexValidator.validate(kit)
        assert not result.is_valid
        assert any("not a valid semantic version" in e for e in result.errors)

    def test_empty_version_skips_validation(self):
        kit = IndexKit(
            name="Kit",
            version="",
            index_mode=IndexMode.SINGLE,
            i7_indexes=[_make_index("A", "AACCGGTT", IndexType.I7)],
        )
        result = IndexValidator.validate(kit)
        assert result.is_valid
