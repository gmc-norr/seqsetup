"""An index kit's fingerprint changes when anything that can reach a sample
or the sheet changes, and only then (index mix-up audit #6, 2026-10-14; the
user's choice "Drop + sync").

A kit could change under the same name and version -- a sync rewrote it, or
two files gave it -- and a drop from a page loaded before took the new
sequences, which the chip never showed. The fingerprint lets a drop prove
the page's kit is the stored one, and a sync refuse a changed kit that kept
its name and version.
"""

import copy
import pathlib

import pytest

from seqsetup.models.index import Index, IndexKit, IndexMode, IndexPair, IndexType
from seqsetup.services.index_kit_sync_parser import IndexKitSyncParser

KITS = sorted(pathlib.Path(__file__).parents[2].joinpath("config", "indexes").glob("*.yaml"))


def _kit(**changes):
    kit = IndexKit(
        name="Kit", version="1.0", description="d", comments="c",
        index_mode=IndexMode.UNIQUE_DUAL,
        index_pairs=[
            IndexPair(id="Kit_P1", name="P1", well_position="A01",
                      index1=Index("D701", "ATTACTCG", IndexType.I7),
                      index2=Index("D501", "TATAGCCT", IndexType.I5)),
            IndexPair(id="Kit_P2", name="P2", well_position="B01",
                      index1=Index("D702", "TCCGGAGA", IndexType.I7),
                      index2=Index("D502", "ATAGAGGC", IndexType.I5)),
        ],
        adapter_read1="CTGTCTCTTATACACATCT", default_index1_cycles=8,
        default_read1_override="Y*", created_by="admin", source="github",
    )
    for name, value in changes.items():
        setattr(kit, name, value)
    return kit


class TestTheSameKitHasTheSameFingerprint:
    """Stored, loaded and parsed again, a kit keeps its fingerprint."""

    @pytest.mark.parametrize("path", KITS, ids=[p.name for p in KITS])
    def test_a_shipped_kit_stored_and_loaded(self, path):
        kit = IndexKitSyncParser.parse(path.read_text(), path.name)
        again = IndexKitSyncParser.parse(path.read_text(), path.name)
        loaded = IndexKit.from_dict(kit.to_dict())
        assert kit.fingerprint() == again.fingerprint() == loaded.fingerprint()

    def test_it_is_a_sha256_in_hex(self):
        assert len(_kit().fingerprint()) == 64
        int(_kit().fingerprint(), 16)

    @pytest.mark.parametrize("field, value", [
        ("description", "other"), ("comments", "other"), ("created_by", "someone"),
        ("source", "user"),
    ])
    def test_what_never_reaches_a_sample_does_not_count(self, field, value):
        assert _kit(**{field: value}).fingerprint() == _kit().fingerprint()


def _changed(change):
    kit = _kit()
    change(kit)
    return kit


class TestAnyChangeThatCanReachASampleCounts:
    """Each of these changes the fingerprint."""

    @pytest.mark.parametrize("change", [
        lambda k: setattr(k, "name", "Other"),
        lambda k: setattr(k, "version", "2.0"),
        lambda k: setattr(k, "index_mode", IndexMode.COMBINATORIAL),
        lambda k: setattr(k, "is_fixed_layout", True),
        lambda k: setattr(k, "adapter_read1", "AGATCGGAAGAGC"),
        lambda k: setattr(k, "adapter_read2", "AGATCGGAAGAGC"),
        lambda k: setattr(k, "default_index1_cycles", 10),
        lambda k: setattr(k, "default_index2_cycles", 8),
        lambda k: setattr(k, "default_read1_override", "N2Y*"),
        lambda k: setattr(k, "default_read2_override", "U8Y*"),
        lambda k: k.index_pairs.reverse(),
        lambda k: k.index_pairs.pop(),
        lambda k: setattr(k.index_pairs[0], "id", "Kit_X"),
        lambda k: setattr(k.index_pairs[0], "name", "X"),
        lambda k: setattr(k.index_pairs[0], "well_position", "C01"),
        lambda k: setattr(k.index_pairs[0].index1, "sequence", "ATTACTCA"),
        lambda k: setattr(k.index_pairs[0].index1, "name", "D799"),
        lambda k: setattr(k.index_pairs[0].index2, "sequence", "TATAGCCA"),
        lambda k: setattr(k.index_pairs[1], "index2", None),
        lambda k: k.i7_indexes.append(Index("N701", "TAAGGCGA", IndexType.I7)),
        lambda k: k.i5_indexes.append(Index("N501", "TAGATCGC", IndexType.I5)),
    ], ids=["name", "version", "mode", "fixed layout", "adapter 1", "adapter 2",
            "i7 cycles", "i5 cycles", "read 1 override", "read 2 override", "pair order",
            "pair removed", "pair id", "pair name", "pair well", "i7 sequence", "i7 name",
            "i5 sequence", "i5 removed", "i7 list", "i5 list"])
    def test_it_changes(self, change):
        assert _changed(change).fingerprint() != _kit().fingerprint()

    def test_a_deep_copy_does_not(self):
        assert copy.deepcopy(_kit()).fingerprint() == _kit().fingerprint()
