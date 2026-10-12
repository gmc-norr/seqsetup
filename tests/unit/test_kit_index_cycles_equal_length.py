"""A kit's default index cycles must be the length of every index in that slot.

The cycles read for an index decide which bases the demultiplexer compares, so
Mark Ready refuses a sample whose index is not as long as the cycles read for
it (spec 2026-10-05 group A3, §4). A kit whose ``default_index1_cycles`` or
``default_index2_cycles`` says otherwise therefore makes every run that uses
it unmarkable, with the complaint on each sample rather than on the kit that
caused it. The check runs where a kit is saved: ``IndexValidator.validate``,
which the upload route and the GitHub sync both run before storing a kit.
"""

from pathlib import Path

import pytest

from seqsetup.models.index import Index, IndexKit, IndexMode, IndexPair, IndexType
from seqsetup.services.index_kit_sync_parser import IndexKitSyncParser
from seqsetup.services.index_validator import IndexValidator


def _pair_kit(**fields) -> IndexKit:
    return IndexKit(
        name="Dual kit", version="1", index_mode=IndexMode.UNIQUE_DUAL,
        index_pairs=[IndexPair(
            id="p1", name="P1",
            index1=Index(name="i7", sequence="ACGTACGTAC", index_type=IndexType.I7),
            index2=Index(name="i5", sequence="TTGGCCAATT", index_type=IndexType.I5),
        )],
        **fields,
    )


def _combo_kit(i7s, i5s, **fields) -> IndexKit:
    return IndexKit(
        name="Combo kit", version="1", index_mode=IndexMode.COMBINATORIAL,
        i7_indexes=[Index(name=f"A{n}", sequence=s, index_type=IndexType.I7)
                    for n, s in enumerate(i7s)],
        i5_indexes=[Index(name=f"B{n}", sequence=s, index_type=IndexType.I5)
                    for n, s in enumerate(i5s)],
        **fields,
    )


def _errors(kit) -> list[str]:
    return IndexValidator.validate(kit).errors


class TestTheCyclesMustBeTheIndexLength:
    def test_i7_cycles_fewer_than_the_index_are_refused(self):
        [error] = _errors(_pair_kit(default_index1_cycles=8))

        assert "Dual kit" in error
        assert "i7" in error
        assert "8" in error
        assert "10" in error

    def test_i7_cycles_more_than_the_index_are_refused(self):
        [error] = _errors(_pair_kit(default_index1_cycles=12))

        assert "12" in error and "10" in error

    def test_i5_cycles_that_differ_are_refused(self):
        [error] = _errors(_pair_kit(default_index2_cycles=8))

        assert "i5" in error

    def test_both_slots_are_reported(self):
        errors = _errors(_pair_kit(default_index1_cycles=8, default_index2_cycles=12))

        assert len(errors) == 2

    def test_the_index_length_is_accepted(self):
        assert _errors(_pair_kit(default_index1_cycles=10, default_index2_cycles=10)) == []

    def test_no_cycles_at_all_is_accepted(self):
        assert _errors(_pair_kit()) == []

    def test_indexes_of_two_lengths_name_both(self):
        kit = _combo_kit(["ACGTACGT", "ACGTACGTAC"], ["TTGGCCAATT"],
                         default_index1_cycles=8, default_index2_cycles=10)
        [error] = _errors(kit)

        assert "8" in error and "10" in error

    def test_a_slot_with_no_indexes_is_not_checked(self):
        """A single-index kit carrying an i5 number has no i5 to disagree
        with, and no sample takes an i5 from it."""
        kit = IndexKit(
            name="Single kit", version="1", index_mode=IndexMode.SINGLE,
            i7_indexes=[Index(name="A", sequence="ACGTAC", index_type=IndexType.I7)],
            default_index1_cycles=6, default_index2_cycles=8,
        )

        assert _errors(kit) == []


class TestTheSavePaths:
    """Both paths that store a kit run IndexValidator.validate first: the
    upload route (routes/indexes.py: upload_index_kit) and the GitHub sync
    (services/github_sync.py: _fetch_index_kits)."""

    SYNC_YAML = """
name: Synced kit
version: "1"
index_mode: combinatorial
default_index1_cycles: {i1}
default_index2_cycles: {i2}
i7_indexes:
  - name: A
    sequence: ACGTACGTAC
i5_indexes:
  - name: B
    sequence: TTGGCCAATT
"""

    def test_a_synced_kit_with_wrong_cycles_is_not_valid(self):
        kit = IndexKitSyncParser.parse(self.SYNC_YAML.format(i1=12, i2=8), "synced.yaml")

        assert IndexValidator.validate(kit).is_valid is False

    def test_a_synced_kit_with_the_index_length_is_valid(self):
        kit = IndexKitSyncParser.parse(self.SYNC_YAML.format(i1=10, i2=10), "synced.yaml")

        assert IndexValidator.validate(kit).is_valid is True


SHIPPED_KITS = sorted(
    (Path(__file__).resolve().parents[2] / "config" / "indexes").glob("*.yaml"), key=str)


class TestTheShippedKits:
    def test_there_are_shipped_kits_to_check(self):
        assert len(SHIPPED_KITS) == 7

    @pytest.mark.parametrize("path", SHIPPED_KITS, ids=lambda p: p.name)
    def test_every_shipped_kit_passes(self, path):
        kit = IndexKitSyncParser.parse(path.read_text(), path.name)

        assert kit is not None, f"{path.name} did not parse"
        assert IndexValidator.validate(kit).errors == []
