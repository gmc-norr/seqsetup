"""A sample ID made only of zeros is refused.

A LIMS may use 0 for an empty well, and JSON sends it as the number 0, so a
worklist row for a well with nothing in it looks like a sample called "0".
Accepting it names a patient sample 0 in the Sample Sheet, or hides a real
sample behind a duplicate ID. The rule lives on the model, on construction
and on later assignment, so paste, LIMS import and manual entry all refuse
it; the two worklist parsers refuse the whole import, naming the rows, as
they do for a row with no sample ID at all.
"""

import pytest

from seqsetup.models.sample import Sample
from seqsetup.services.sample_api import parse_api_samples
from seqsetup.services.sample_parser import parse_pasted_samples

ZERO_ONLY = ["0", "00", "000", "0" * 10, "0" * 256]
# IDs that contain a zero but are not only zeros; these must behave as before.
ORDINARY_IDS = ["0A", "A0", "100", "0-0", "0.0", "S01", "10", "0 0"]


class TestTheModelRefusesIt:
    @pytest.mark.parametrize("value", ZERO_ONLY)
    def test_it_cannot_be_constructed(self, value):
        with pytest.raises(ValueError, match="only of zeros"):
            Sample(sample_id=value)

    @pytest.mark.parametrize("value", ZERO_ONLY)
    def test_it_cannot_be_assigned_to_a_sample_that_already_exists(self, value):
        sample = Sample(sample_id="S1")

        with pytest.raises(ValueError, match="only of zeros"):
            sample.sample_id = value

        assert sample.sample_id == "S1"

    def test_the_message_says_a_lims_may_use_zero_for_an_empty_well(self):
        with pytest.raises(ValueError, match="empty well"):
            Sample(sample_id="0")

    @pytest.mark.parametrize("value", ORDINARY_IDS)
    def test_an_id_that_merely_contains_a_zero_is_kept(self, value):
        assert Sample(sample_id=value).sample_id == value

    def test_a_stored_sample_with_a_zero_id_is_refused_on_load(self):
        with pytest.raises(ValueError, match="only of zeros"):
            Sample.from_dict({"id": "s1", "sample_id": "0"})


class TestThePasteParserRefusesTheWholePaste:
    def test_it_names_the_row_and_adds_nothing(self):
        with pytest.raises(ValueError, match="only of zeros") as excinfo:
            parse_pasted_samples("sample_id,test_id\n0,WGS\nA1,WGS\n")

        assert "2" in str(excinfo.value)

    def test_it_names_every_offending_row(self):
        with pytest.raises(ValueError) as excinfo:
            parse_pasted_samples("sample_id,test_id\n0,WGS\nA1,WGS\n00,WGS\n")

        assert "2, 4" in str(excinfo.value)

    def test_an_ordinary_id_still_parses(self):
        assert [s.sample_id for s in parse_pasted_samples("sample_id\n100\n0A\n")] == ["100", "0A"]


class TestTheLimsParserRefusesTheWholeWorklist:
    def test_the_json_number_zero_is_refused(self):
        with pytest.raises(ValueError, match="only of zeros") as excinfo:
            parse_api_samples([{"sample_id": 0, "test_id": "WGS"},
                               {"sample_id": "A1", "test_id": "WGS"}])

        assert "1" in str(excinfo.value)

    def test_the_text_zero_is_refused(self):
        with pytest.raises(ValueError, match="only of zeros"):
            parse_api_samples([{"sample_id": "00", "test_id": "WGS"}])

    def test_it_names_every_offending_row(self):
        with pytest.raises(ValueError) as excinfo:
            parse_api_samples([{"sample_id": "0"}, {"sample_id": "A1"}, {"sample_id": "000"}])

        assert "1, 3" in str(excinfo.value)

    def test_an_ordinary_id_still_parses(self):
        rows = parse_api_samples([{"sample_id": "100"}, {"sample_id": "0A"}])
        assert [row["sample_id"] for row in rows] == ["100", "0A"]
