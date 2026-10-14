"""Long sample text is refused, never cut (outside review of 7f858e0,
finding 5; spec 2026-10-14 long sample text).

A sample ID, name, project, test or worksheet ID over 256 characters was
cut to 256 with no word: two IDs alike in their first 256 characters became
one, and a cut ID no longer matched the LIMS. Now the model refuses it, on
construction, on assignment and on load, and each parser refuses the whole
paste or worklist, naming its rows.
"""

import pytest

from seqsetup.models.sample import Sample
from seqsetup.services.sample_api import parse_api_samples
from seqsetup.services.sample_parser import parse_pasted_samples

FIVE = ["sample_id", "sample_name", "project", "test_id", "worksheet_id"]
LONG, FULL = "A" * 257, "A" * 256
TOO_LONG = "longer than 256 characters"


class TestTheModelRefuses:

    @pytest.mark.parametrize("field", FIVE)
    def test_on_construction(self, field):
        with pytest.raises(ValueError, match=TOO_LONG):
            Sample(**{field: LONG})

    @pytest.mark.parametrize("field", FIVE)
    def test_on_assignment_and_keeps_the_old_value(self, field):
        sample = Sample(sample_id="S1")
        before = getattr(sample, field)
        with pytest.raises(ValueError, match=TOO_LONG):
            setattr(sample, field, LONG)
        assert getattr(sample, field) == before

    @pytest.mark.parametrize("field", FIVE)
    def test_on_load(self, field):
        stored = Sample(sample_id="S1").to_dict()
        stored[field] = LONG
        with pytest.raises(ValueError, match=TOO_LONG):
            Sample.from_dict(stored)

    @pytest.mark.parametrize("field", FIVE)
    def test_256_is_kept_whole(self, field):
        assert getattr(Sample(**{field: FULL}), field) == FULL

    def test_the_message_names_the_field_and_the_length(self):
        with pytest.raises(ValueError, match=r"The sample ID is longer than 256 characters \(257\)"):
            Sample(sample_id=LONG)

    def test_the_kit_name_keeps_its_cut(self):
        """Not one of the five: it is on no sheet (spec, "The rule")."""
        assert Sample(index_kit_name="K" * 300).index_kit_name == "K" * 256


class TestAPasteIsRefusedWhole:

    def test_a_long_sample_id(self):
        with pytest.raises(ValueError, match=(
                r"Row\(s\) 3: the sample_id is longer than 256 characters\. "
                r"SeqSetup does not shorten it; shorten it in the source\.")):
            parse_pasted_samples(f"P1\tWGS\nP2\tWGS\n{LONG}\tWGS\n")

    def test_a_long_test(self):
        with pytest.raises(ValueError, match=r"Row\(s\) 1: the test is longer than 256 characters"):
            parse_pasted_samples(f"P1\t{LONG}\nP2\tWGS\n")

    def test_two_ids_alike_in_their_first_256_are_not_merged(self):
        with pytest.raises(ValueError, match=r"Row\(s\) 1, 2: the sample_id is longer"):
            parse_pasted_samples(f"{FULL}X\tWGS\n{FULL}Y\tWGS\n")

    def test_256_is_read_whole(self):
        [sample] = parse_pasted_samples(f"{FULL}\t{FULL}\n")
        assert (sample.sample_id, sample.test_id) == (FULL, FULL)

    def test_a_long_cell_nobody_reads_is_no_reason_to_refuse(self):
        header = "sample_id\ttest_id\tcomment\n"
        [sample] = parse_pasted_samples(header + f"P1\tWGS\t{'x' * 3000}\n")
        assert sample.sample_id == "P1"


class TestAWorklistIsRefusedWhole:

    @pytest.mark.parametrize("field, label", [
        ("sample_id", "the sample_id"), ("test_id", "the test"), ("worksheet_id", "the worksheet ID")])
    def test_a_long_field(self, field, label):
        rows = [{"sample_id": "P1"}, {"sample_id": "P2"}]
        rows[1][field] = LONG
        with pytest.raises(ValueError, match=(
                rf"LIMS row\(s\) 2: {label} is longer than 256 characters\. SeqSetup does not "
                rf"shorten it\. Fix the upstream record\(s\) before retrying\.")):
            parse_api_samples(rows)

    def test_256_is_read_whole(self):
        [row] = parse_api_samples([{"sample_id": FULL, "test_id": FULL, "worksheet_id": FULL}])
        assert (row["sample_id"], row["test_id"], row["worksheet_id"]) == (FULL, FULL, FULL)
