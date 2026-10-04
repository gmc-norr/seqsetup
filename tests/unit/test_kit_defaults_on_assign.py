"""Assigning from a kit gives the sample that kit's own index cycles and
read patterns, never the last kit's (review DI-09; spec 2026-10-03 group
A1, §2, rule 1)."""

import pytest

from seqsetup.models.index import Index, IndexKit, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.routes.samples import _apply_kit_defaults

I7 = Index(name="i7", sequence="ACGTACGTAC", index_type=IndexType.I7)
I5 = Index(name="i5", sequence="TTGGCCAATT", index_type=IndexType.I5)

FULL = IndexKit(
    name="Full", default_index1_cycles=6, default_index2_cycles=7,
    default_read1_override="N2Y*", default_read2_override="N3Y*",
)
# No defaults; an empty read override text counts as none.
EMPTY = IndexKit(name="Empty", default_read1_override="")


def _old(**indexes) -> Sample:
    """A sample holding ``indexes`` and another kit's four settings, all
    different from FULL's, so "set to None" and "left alone" differ."""
    return Sample(
        sample_id="S1", index1_cycles=8, index2_cycles=8,
        read1_override_pattern="U8Y*", read2_override_pattern="U8Y*", **indexes,
    )


def _settings(sample):
    return (sample.index1_cycles, sample.index2_cycles,
            sample.read1_override_pattern, sample.read2_override_pattern)


class TestAssignTakesTheKitsOwnSettings:
    """What was just assigned takes the kit's values, None where the kit has
    none; a setting of an index still on the sample is left alone."""

    def test_pair_from_a_kit_with_all_four(self):
        sample = _old(index_pair=IndexPair(id="p", name="p", index1=I7, index2=I5))
        _apply_kit_defaults(sample, FULL, "pair")
        assert _settings(sample) == (6, 7, "N2Y*", "N3Y*")

    def test_pair_from_a_kit_with_none(self):
        sample = _old(index_pair=IndexPair(id="p", name="p", index1=I7, index2=I5))
        _apply_kit_defaults(sample, EMPTY, "pair")
        assert _settings(sample) == (None, None, None, None)

    def test_i7_from_a_kit_with_all_four_leaves_the_i5_cycles(self):
        sample = _old(index1=I7, index2=I5)
        _apply_kit_defaults(sample, FULL, "i7")
        assert _settings(sample) == (6, 8, "N2Y*", "N3Y*")

    def test_i7_from_a_kit_with_none_leaves_the_i5_cycles(self):
        sample = _old(index1=I7, index2=I5)
        _apply_kit_defaults(sample, EMPTY, "i7")
        assert _settings(sample) == (None, 8, None, None)

    def test_i5_from_a_kit_with_all_four_leaves_the_i7_cycles(self):
        sample = _old(index1=I7, index2=I5)
        _apply_kit_defaults(sample, FULL, "i5")
        assert _settings(sample) == (8, 7, "N2Y*", "N3Y*")

    def test_i5_from_a_kit_with_none_leaves_the_i7_cycles(self):
        sample = _old(index1=I7, index2=I5)
        _apply_kit_defaults(sample, EMPTY, "i5")
        assert _settings(sample) == (8, None, None, None)

    def test_a_pair_without_an_i5_gets_no_i5_cycles(self):
        sample = _old(index_pair=IndexPair(id="p", name="p", index1=I7))
        _apply_kit_defaults(sample, FULL, "pair")
        assert _settings(sample) == (6, None, "N2Y*", "N3Y*")

    def test_an_unknown_slot_is_refused(self):
        sample = _old(index1=I7)
        with pytest.raises(ValueError, match="slot"):
            _apply_kit_defaults(sample, FULL, "both")
        assert _settings(sample) == (8, 8, "U8Y*", "U8Y*")
