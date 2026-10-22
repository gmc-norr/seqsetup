"""An index, a pair's slots and a sample's slots are checked on every
assignment and on load, not only at construction.

CLAUDE.md, Data integrity: "Models are **self-validating on every
assignment, not just construction**, for any non-trivial invariant they
declare ... ``__post_init__`` alone is insufficient." ``Index`` declared the
DNA rule and ``IndexPair`` the i7/i5 slot rule in ``__post_init__`` only, and
``Sample`` kept its slot rule in ``assign_index1`` / ``assign_index2`` rather
than in ``__setattr__``: a later assignment put any text in an index, or an
i5 where the Sample Sheet writes the i7 (review LIFECYCLE-3 / TH-3). Nothing
in ``src/`` writes those attributes directly today -- this is the backstop,
not a known wrong sheet.

``Sample.override_cycles`` was held to ``^[YIUN0-9;,]*$``, and ``$`` matches
before a trailing line break, which would then be written into the sheet;
the project's rule is ``\\Z`` (``VALID_DNA_RE`` in ``models/index.py`` says so
of itself). A stored value that breaks the rule now makes the run unreadable,
as a stored over-long sample text does, instead of being dropped to None with
a log line nobody reads.
"""

import pytest

from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample


def _i7(sequence="ATTACTCG") -> Index:
    return Index(name="i7-01", sequence=sequence, index_type=IndexType.I7)


def _i5(sequence="TATAGCCT") -> Index:
    return Index(name="i5-01", sequence=sequence, index_type=IndexType.I5)


def _pair() -> IndexPair:
    return IndexPair(id="p", name="UDP0001", index1=_i7(), index2=_i5())


class TestAnIndexSequence:

    def test_it_is_checked_at_construction(self):
        with pytest.raises(ValueError):
            Index(name="x", sequence="ACGTX", index_type=IndexType.I7)

    # "ACGT\n" is not here: a trailing newline is stripped, at construction
    # and now on assignment too (a YAML literal-block scalar appends one).
    @pytest.mark.parametrize("written", ["ACGTX", "not dna", "ACGT ACGT", "ACGT\tACGT"])
    def test_it_is_checked_on_assignment(self, written):
        index = _i7()

        with pytest.raises(ValueError):
            index.sequence = written

        assert index.sequence == "ATTACTCG"

    def test_it_is_uppercased_and_stripped_on_assignment_as_at_construction(self):
        index = _i7()

        index.sequence = " acgtn \n"

        assert index.sequence == "ACGTN"

    def test_it_is_checked_on_load(self):
        with pytest.raises(ValueError):
            Index.from_dict({"name": "x", "sequence": "ACGTX", "index_type": "i7"})

    @pytest.mark.parametrize("written", [None, 12345678, b"ACGTACGT", ["ACGT"]])
    def test_anything_but_text_is_refused(self, written):
        """A stored ``null`` or number used to open the run and then fail as a
        bare 500 inside Mark Ready, naming no sample."""
        with pytest.raises(ValueError):
            Index(name="x", sequence=written, index_type=IndexType.I7)

        with pytest.raises(ValueError):
            Index.from_dict({"name": "x", "sequence": written, "index_type": "i7"})

    def test_a_good_sequence_is_still_taken(self):
        index = _i7()

        index.sequence = "GGGGCCCC"

        assert index.sequence == "GGGGCCCC"


class TestAPairsSlots:

    def test_an_i5_in_the_i7_slot_is_refused_at_construction(self):
        with pytest.raises(ValueError):
            IndexPair(id="p", name="p", index1=_i5(), index2=_i5())

    def test_an_i5_assigned_into_the_i7_slot_is_refused(self):
        pair = _pair()

        with pytest.raises(ValueError):
            pair.index1 = _i5()

        assert pair.index1.index_type is IndexType.I7

    def test_an_i7_assigned_into_the_i5_slot_is_refused(self):
        pair = _pair()

        with pytest.raises(ValueError):
            pair.index2 = _i7()

        assert pair.index2.index_type is IndexType.I5

    def test_the_i5_slot_may_be_emptied(self):
        pair = _pair()

        pair.index2 = None

        assert pair.index2 is None

    def test_a_stored_pair_with_the_slots_swapped_is_refused_on_load(self):
        stored = _pair().to_dict()
        stored["index1"], stored["index2"] = stored["index2"], stored["index1"]

        with pytest.raises(ValueError):
            IndexPair.from_dict(stored)


class TestASamplesSlots:

    def test_an_i5_assigned_into_the_i7_slot_is_refused(self):
        sample = Sample(sample_id="S1")

        with pytest.raises(ValueError):
            sample.index1 = _i5()

        assert sample.index1 is None

    def test_an_i7_assigned_into_the_i5_slot_is_refused(self):
        sample = Sample(sample_id="S1")

        with pytest.raises(ValueError):
            sample.index2 = _i7()

        assert sample.index2 is None

    def test_the_right_way_round_is_taken(self):
        sample = Sample(sample_id="S1")

        sample.index1 = _i7()
        sample.index2 = _i5()

        assert sample.index1_sequence == "ATTACTCG" and sample.index2_sequence == "TATAGCCT"

    def test_a_pair_in_the_pair_slot_must_be_a_pair(self):
        sample = Sample(sample_id="S1")

        with pytest.raises(ValueError):
            sample.index_pair = _i7()

    def test_a_stored_sample_with_an_i5_in_its_i7_slot_is_refused_on_load(self):
        stored = Sample(sample_id="S1", index1=_i7()).to_dict()
        stored["index1"]["index_type"] = "i5"

        with pytest.raises(ValueError):
            Sample.from_dict(stored)


class TestAnOverrideCycles:

    @pytest.mark.parametrize("written", ["Y151;I8;I8;Y151\n", "Y151;I8;I8;Y151\r\n",
                                         "Y151;I8;I8;Y151\r"])
    def test_a_line_break_at_the_end_is_refused(self, written):
        sample = Sample(sample_id="S1")

        with pytest.raises(ValueError):
            sample.override_cycles = written

        assert sample.override_cycles is None

    def test_a_stored_value_that_breaks_the_rule_makes_the_run_unreadable(self):
        """Never dropped: a sheet written from a run whose stored value was
        quietly replaced by None is a sheet nobody asked for."""
        stored = Sample(sample_id="S1").to_dict()
        stored["override_cycles"] = "Y151;I8;I8;Y151\n"

        with pytest.raises(ValueError):
            Sample.from_dict(stored)

    def test_a_good_value_is_still_taken(self):
        sample = Sample(sample_id="S1")

        sample.override_cycles = "y151;i8;i8;y151"

        assert sample.override_cycles == "Y151;I8;I8;Y151"


class TestNoRouteWritesSuchAValueToday:
    """Searched: no file in src/ assigns to .sequence, .index1, .index2 or
    .index_pair outside the models themselves, so this change refuses nothing
    the app does -- it is the hard rule's backstop."""

    def test_no_file_in_src_assigns_an_index_slot(self):
        import re
        from pathlib import Path

        root = Path(__file__).resolve().parents[2] / "src" / "seqsetup"
        pattern = re.compile(r"\.(sequence|index1|index2|index_pair)\s*=[^=]")
        offenders = []
        for path in root.rglob("*.py"):
            if path.name in ("index.py", "sample.py") and path.parent.name == "models":
                continue
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if pattern.search(line):
                    offenders.append(f"{path.relative_to(root)}:{number}: {line.strip()}")

        assert offenders == [], offenders
