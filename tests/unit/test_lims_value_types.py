"""Every field SeqSetup reads from a LIMS row is text or a whole number, or
the import is refused: str() would read JSON 1.10 as "1.1", true as "True"
and a list as "['a']" (spec 2026-10-10 later list slice 1, §1)."""

import pytest

from seqsetup.models.sample import ZERO_SAMPLE_ID_RULE
from seqsetup.models.sample_api_config import SampleApiConfig
from seqsetup.services.sample_api import parse_api_samples

FIELDS = [
    ("sample_id", "sample_id", "a sample ID"),
    ("worksheet_id", "worksheet_id", "a worksheet ID"),
    ("index1_sequence", "index_i7", "an i7 sequence"),
    ("index2_sequence", "index_i5", "an i5 sequence"),
    ("index_pair_name", "index_pair_name", "an index name"),
    ("index1_name", "i7_name", "an i7 name"),
    ("index2_name", "i5_name", "an i5 name"),
]
DECIMAL = ("that is a number with a decimal point ({}), which JSON may have changed (1.10 is "
           'read as 1.1). Send it as text, for example "1.10".')
NOT_TEXT = "that is not text or a whole number ({})."


def _row(name, value):
    return {name: value} if name == "sample_id" else {"sample_id": "S1", name: value}


def _refused(rows, config=None):
    with pytest.raises(ValueError) as exc:
        parse_api_samples(rows, config)
    return str(exc.value)


@pytest.mark.parametrize("field,name,label", FIELDS, ids=[f[0] for f in FIELDS])
class TestEachFieldIsCheckedByItsType:

    def test_a_decimal_number_is_refused(self, field, name, label):
        assert _refused([_row(name, 1.10)]) == f"LIMS row 1 has {label} " + DECIMAL.format("1.1")

    def test_true_is_refused(self, field, name, label):
        assert _refused([_row(name, True)]) == f"LIMS row 1 has {label} " + NOT_TEXT.format("true")

    def test_a_list_is_refused(self, field, name, label):
        assert _refused([_row(name, ["a", "b"])]) == (
            f"LIMS row 1 has {label} " + NOT_TEXT.format('["a", "b"]'))

    def test_an_object_is_refused(self, field, name, label):
        assert _refused([_row(name, {"a": 1})]) == (
            f"LIMS row 1 has {label} " + NOT_TEXT.format('{"a": 1}'))

    def test_the_row_is_named(self, field, name, label):
        rows = [{"sample_id": "S0"}, _row(name, 2.5)]
        assert _refused(rows).startswith(f"LIMS row 2 has {label} that is a number")


class TestTextAndWholeNumbersPass:

    def test_text_is_read_as_today(self):
        [row] = parse_api_samples([{"sample_id": " S1 ", "worksheet_id": "W1", "i7_name": "D701"}])
        assert (row["sample_id"], row["worksheet_id"], row["index1_name"]) == ("S1", "W1", "D701")

    @pytest.mark.parametrize("name,field", [("i7_name", "index1_name"), ("i5_name", "index2_name"),
                                            ("worksheet_id", "worksheet_id")])
    def test_a_whole_number_keeps_its_digits(self, name, field):
        assert parse_api_samples([{"sample_id": "S1", name: 7}])[0][field] == "7"

    @pytest.mark.parametrize("name,field", [("i7_name", "index1_name"), ("index_pair_name",
                                                                       "index_pair_name")])
    def test_zero_is_zero_not_empty(self, name, field):
        assert parse_api_samples([{"sample_id": "S1", name: 0}])[0][field] == "0"

    def test_a_sample_id_of_zero_is_read_as_zero_then_refused(self):
        # Read as the text "0", not lost as empty: the refusal names the row
        # as a sample ID of only zeros, not as a row with no sample ID (an
        # empty well a LIMS calls 0).
        assert _refused([{"sample_id": 0}]) == (
            f"LIMS row(s) 1: {ZERO_SAMPLE_ID_RULE}. "
            f"Fix the upstream record(s) before retrying.")

    def test_null_gives_way_to_the_next_name(self):
        [row] = parse_api_samples([{"sample_id": None, "sampleid": "S1"}])
        assert row["sample_id"] == "S1"

    def test_a_long_value_is_shortened_in_the_message(self):
        assert _refused([{"sample_id": "S1", "i7_name": ["x" * 50]}]) == (
            "LIMS row 1 has an i7 name " + NOT_TEXT.format('["' + "x" * 38 + "…"))


class TestAnAdminsMappings:

    def test_a_mapped_sample_field_is_checked(self):
        config = SampleApiConfig(field_mappings={"worksheet_id": "WsNo"})
        assert _refused([{"sample_id": "S1", "WsNo": 1.5}], config) == (
            "LIMS row 1 has a worksheet ID " + DECIMAL.format("1.5"))

    def test_a_worksheet_field_is_not_checked(self):
        """investigator and updated_at name worksheet fields, which a sample
        row does not use (review of 91fbe8e)."""
        config = SampleApiConfig(field_mappings={"investigator": "Inv", "updated_at": "Updated"})
        rows = parse_api_samples([{"sample_id": "S1", "Inv": {"name": "x"}, "Updated": 1.5}],
                                 config)
        assert [r["sample_id"] for r in rows] == ["S1"]


class TestTheTestKeepsItsOwnCheck:
    """The test and its version keep their messages (spec 2026-10-07 group A4)."""

    def test_a_decimal_test_has_todays_message(self):
        assert _refused([{"sample_id": "S1", "test_id": 1.10}]) == (
            "Sample 'S1' has a test " + DECIMAL.format("1.1"))

    def test_a_list_test_is_refused(self):
        assert _refused([{"sample_id": "S1", "test_id": ["WGS"]}]) == (
            "Sample 'S1' has a test " + NOT_TEXT.format('["WGS"]'))

    @pytest.mark.parametrize("row", [{"sample_id": "S1"}, {"sample_id": "S1", "test_id": None}],
                             ids=["absent", "null"])
    def test_a_row_without_a_test_is_read_as_today(self, row):
        assert parse_api_samples([row]) == [{"sample_id": "S1", "test_version": ""}]

    def test_a_version_without_a_test_keeps_its_message(self):
        assert _refused([{"sample_id": "S1", "test_version": "1"}]) == (
            "Sample 'S1' has a test version but no test.")
