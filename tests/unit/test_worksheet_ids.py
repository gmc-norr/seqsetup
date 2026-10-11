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
        assert _listed(lims_wire, b'[{"id": "25.10"}, {"id": 7}, {"id": 0}, {"id": "W-2_a.b~c"}]') == (
            True, "Found 4 worksheets", ["25.10", "7", "0", "W-2_a.b~c"], [])

    def test_a_worksheet_without_an_id_is_not_listed_as_today(self, lims_wire):
        assert _listed(lims_wire, b'[{"id": "W1"}, {"name": "no id"}, {"id": null}]') == (
            True, "Found 1 worksheets", ["W1"], [])


def _cannot(shown):
    return (f"A worksheet in the LIMS list has the ID {shown}, which SeqSetup cannot ask the "
            f"LIMS for as it was sent: an ID is at most 128 letters, digits, '.', '_', '-' or "
            f"'~', with no spaces. It is left out of the list.")


def _same(count, shown):
    return (f"{count} worksheets in the LIMS list have the ID {shown}, and SeqSetup cannot "
            f"tell which one the LIMS means. They are left out of the list.")


class TestAnIdSeqSetupWouldChangeIsLeftOut:
    """The list showed " W2 " as W2 and the import fetched W2: two worksheets
    whose IDs differ only in spaces gave two W2 options that fetched one of
    them (build review of later list slice 2, E-3). The ID is used as sent,
    or the worksheet is left out."""

    def test_spaces_around_the_id(self, lims_wire):
        body = b'[{"id": "W1"}, {"id": " W2 "}, {"id": "W2 "}]'
        assert _listed(lims_wire, body) == (
            True, "Found 1 worksheets", ["W1"], [_cannot("' W2 '"), _cannot("'W2 '")])

    def test_the_review_case_lists_only_the_id_sent_as_it_is(self, lims_wire):
        body = (b'[{"id": "W2 ", "investigator": "Smith"}, {"id": " W2 ", "investigator": "Jones"},'
                b' {"id": "W2", "investigator": "Brown"}]')
        lims_wire.body = body
        ok, _message, worksheets, left_out = fetch_worklists(CONFIG)
        assert [(w["id"], w["investigator"]) for w in worksheets] == [("W2", "Brown")]
        assert left_out == [_cannot("'W2 '"), _cannot("' W2 '")]

    @pytest.mark.parametrize("raw, shown", [
        (b'"WS 12"', "'WS 12'"), (b'"WS/12"', "'WS/12'"), (b'"WS?12"', "'WS?12'"),
        (b'"W\\u00e5"', "'Wå'"), (b'"W2\\n"', "'W2\\n'"),
    ])
    def test_a_character_the_lims_cannot_be_asked_for(self, lims_wire, raw, shown):
        assert _listed(lims_wire, b'[{"id": "W1"}, {"id": ' + raw + b'}]') == (
            True, "Found 1 worksheets", ["W1"], [_cannot(shown)])

    def test_a_long_id(self, lims_wire):
        body = b'[{"id": "' + b"W" * 128 + b'"}, {"id": "' + b"X" * 129 + b'"}]'
        assert _listed(lims_wire, body) == (
            True, "Found 1 worksheets", ["W" * 128], [_cannot("'" + "X" * 40 + "…'")])

    def test_the_mapped_field_is_checked_too(self, lims_wire):
        assert _listed(lims_wire, b'[{"AL": "W2 "}, {"AL": "W3"}]', MAPPED) == (
            True, "Found 1 worksheets", ["W3"], [_cannot("'W2 '")])


class TestTwoWorksheetsWithOneId:
    """Each would be an option that fetches the same worksheet, under another
    worksheet's label."""

    def test_both_are_left_out(self, lims_wire):
        body = (b'[{"id": "W2", "investigator": "Smith"}, {"id": "W1"},'
                b' {"id": "W2", "investigator": "Brown"}]')
        assert _listed(lims_wire, body) == (True, "Found 1 worksheets", ["W1"], [_same(2, "'W2'")])

    def test_text_and_a_number_with_the_same_digits(self, lims_wire):
        assert _listed(lims_wire, b'[{"id": "7"}, {"id": 7}, {"id": "7"}]') == (
            False, "No valid worksheets found in API response", [], [_same(3, "'7'")])


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

    def test_a_long_name_is_shortened_in_the_message(self, lims_wire):
        long = "A" + "l" * 60
        config = SampleApiConfig(base_url="https://lims.example.org/api", enabled=True,
                                 field_mappings={"worksheet_id": long})
        body = ('[{"%s": "W_A", "%s": "W_B"}]' % (long, long.upper())).encode()
        assert _listed(lims_wire, body, config)[3] == [
            _two(long[:40] + "…", long.upper()[:40] + "…")]

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


class TestAnEntryThatIsNotAWorksheet:
    """An entry that is not a JSON object was dropped with no warning (build
    review of later list slice 2, M1-5)."""

    def test_it_is_left_out_with_a_warning(self, lims_wire):
        body = b'[{"id": "W1"}, "25.10", 7, null, ["W2"]]'
        assert _listed(lims_wire, body) == (True, "Found 1 worksheets", ["W1"], [
            f"An entry in the LIMS list is not a worksheet ({shown}). It is left out of the list."
            for shown in ('"25.10"', "7", "null", '["W2"]')])


class TestTheListIsSortedWhateverTheDates:
    """A created value that is not text stopped the sort, and the whole list
    failed with "Unexpected error" (build review of later list slice 2, M1-4)."""

    def test_a_number_and_text(self, lims_wire):
        body = b'[{"id": "W1", "created": 5}, {"id": "W2", "updated_at": "2026-01-01"}]'
        assert _listed(lims_wire, body) == (True, "Found 2 worksheets", ["W1", "W2"], [])


class TestTheConnectionCheckCountsAsTheListShows:
    """The admin's check counted the reply's entries, and could say 3
    worksheets where a run lists 1 (build review of later list slice 2, MB-6)."""

    def test_entries_not_listed_are_named(self, lims_wire):
        from seqsetup.services.sample_api import check_connection
        lims_wire.body = b'[{"id": "W1"}, {"id": 2.5}, "x", {"name": "no id"}]'
        assert check_connection(CONFIG) == (
            True, "Connection successful (1 worksheets found; 3 other entries in the reply are "
                  "not listed)")

    def test_every_entry_listed(self, lims_wire):
        from seqsetup.services.sample_api import check_connection
        lims_wire.body = b'[[{"id": "W1"}, {"id": "W2"}], {"page": 1}]'
        assert check_connection(CONFIG) == (True, "Connection successful (2 worksheets found)")
