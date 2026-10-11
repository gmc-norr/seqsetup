"""The worksheet list's IDs: an ID that is not text or a whole number, or that
comes under two spellings of one name, leaves that worksheet out of the list
with a warning; the other worksheets are listed as today (spec 2026-10-10
later list slice 2, §3). The LIMS reply goes through the real _api_get."""

import pytest

from seqsetup.models.sample_api_config import SampleApiConfig
from seqsetup.services.sample_api import fetch_worklists

from .test_sample_api import lims_wire  # noqa: F401 - a fixture

CONFIG = SampleApiConfig(base_url="https://lims.example.org/api", enabled=True)
MAPPED = SampleApiConfig(base_url="https://lims.example.org/api", enabled=True,
                         field_mappings={"worksheet_id": "AL"})

DECIMAL = ('A worksheet in the LIMS list has an ID that is a number with a decimal point (25.1), '
           'which JSON may have changed (1.10 is read as 1.1). Send it as text, for example '
           '"1.10". It is left out of the list.')


def _not_text(shown):
    return (f"A worksheet in the LIMS list has an ID that is not text or a whole number "
            f"({shown}). It is left out of the list.")


def _two(a, b):
    return (f"A worksheet in the LIMS list has the names {a!r} and {b!r}, which SeqSetup reads "
            f"as one name. Send only one of them. It is left out of the list.")


def _listed(wire, body, config=CONFIG):
    wire.body = body
    ok, message, worksheets, left_out = fetch_worklists(config)
    return ok, message, [w["id"] for w in worksheets], left_out


class TestAnIdOfTheWrongTypeIsLeftOut:
    """str() would read JSON 25.10 as "25.1" and true as "True", and the
    import would then fetch that other ID."""

    def test_a_decimal_number(self, lims_wire):
        assert _listed(lims_wire, b'[{"id": "W1"}, {"id": 25.10}]') == (
            True, "Found 1 worksheets", ["W1"], [DECIMAL])

    @pytest.mark.parametrize("raw, shown", [
        (b"true", "true"), (b"false", "false"), (b'["a"]', '["a"]'), (b'{"a": 1}', '{"a": 1}'),
    ])
    def test_not_text_or_a_whole_number(self, lims_wire, raw, shown):
        body = b'[{"id": "W1"}, {"id": ' + raw + b'}]'
        assert _listed(lims_wire, body) == (True, "Found 1 worksheets", ["W1"], [_not_text(shown)])


class TestTextAndWholeNumbersAreListedAsToday:

    def test_text_and_whole_numbers(self, lims_wire):
        assert _listed(lims_wire, b'[{"id": "25.10"}, {"id": 7}, {"id": 0}, {"id": " W2 "}]') == (
            True, "Found 4 worksheets", ["25.10", "7", "0", "W2"], [])

    def test_a_worksheet_without_an_id_is_not_listed_as_today(self, lims_wire):
        assert _listed(lims_wire, b'[{"id": "W1"}, {"name": "no id"}, {"id": null}]') == (
            True, "Found 1 worksheets", ["W1"], [])


class TestTheIdFallback:
    """The ID is the worksheet ID field, or id when that is absent, null or
    blank; the one read is the one checked."""

    def test_id_is_read_when_the_worksheet_id_is_absent(self, lims_wire):
        assert _listed(lims_wire, b'[{"name": "n", "id": 25.10}]') == (
            False, "No valid worksheets found in API response", [], [DECIMAL])

    def test_id_is_read_when_the_worksheet_id_is_null_or_blank(self, lims_wire):
        body = b'[{"worksheet_id": null, "id": "W1"}, {"worksheet_id": " ", "id": true}]'
        assert _listed(lims_wire, body) == (True, "Found 1 worksheets", ["W1"], [_not_text("true")])

    def test_the_worksheet_id_wins_over_id(self, lims_wire):
        assert _listed(lims_wire, b'[{"worksheet_id": "W1", "id": 2.5}]') == (
            True, "Found 1 worksheets", ["W1"], [])


class TestAnAdminsWorksheetIdField:

    def test_the_mapped_field_is_the_one_checked(self, lims_wire):
        assert _listed(lims_wire, b'[{"AL": 25.10, "id": "W1"}, {"AL": "W2"}]', MAPPED) == (
            True, "Found 1 worksheets", ["W2"], [DECIMAL])


class TestTwoSpellingsOfAnIdName:
    """Lower-cased, the last spelling won, with no warning. Both values pass
    a type check, and slice 1's check catches only the same name twice."""

    def test_worksheet_id_in_two_spellings(self, lims_wire):
        body = b'[{"Worksheet_ID": "W_A", "WORKSHEET_ID": "W_B"}, {"id": "W1"}]'
        assert _listed(lims_wire, body) == (
            True, "Found 1 worksheets", ["W1"], [_two("Worksheet_ID", "WORKSHEET_ID")])

    def test_a_mapped_name_in_two_spellings(self, lims_wire):
        body = b'[{"Al": "W_A", "al": "W_B"}, {"AL": "W1"}]'
        assert _listed(lims_wire, body, MAPPED) == (
            True, "Found 1 worksheets", ["W1"], [_two("Al", "al")])

    def test_id_in_two_spellings(self, lims_wire):
        assert _listed(lims_wire, b'[{"Id": "W_A", "ID": "W_B"}]') == (
            False, "No valid worksheets found in API response", [], [_two("Id", "ID")])

    def test_id_in_two_spellings_is_refused_also_when_the_worksheet_id_is_read(self, lims_wire):
        body = b'[{"worksheet_id": "W1", "Id": "a", "ID": "b"}]'
        assert _listed(lims_wire, body) == (
            False, "No valid worksheets found in API response", [], [_two("Id", "ID")])

    def test_other_names_may_come_in_two_spellings(self, lims_wire):
        body = b'[{"id": "W1", "Name": "a", "NAME": "b"}]'
        assert _listed(lims_wire, body)[2] == ["W1"]


class TestEveryWorksheetLeftOut:

    def test_not_a_success_and_every_warning(self, lims_wire):
        assert _listed(lims_wire, b'[{"id": 1.5}, {"id": true}]') == (
            False, "No valid worksheets found in API response", [],
            ['A worksheet in the LIMS list has an ID that is a number with a decimal point (1.5), '
             'which JSON may have changed (1.10 is read as 1.1). Send it as text, for example '
             '"1.10". It is left out of the list.', _not_text("true")])
