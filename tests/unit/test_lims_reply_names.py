"""A LIMS reply's names: one name twice in one object, or two names that
differ only in capitals, is refused, never resolved; SeqSetup's own
worksheet_id is added only when no spelling of it is there (spec 2026-10-10
later list slice 1, §1)."""

from unittest.mock import patch

import pytest

from seqsetup.models.sample_api_config import SampleApiConfig
from seqsetup.services import sample_api as sample_api_module
from seqsetup.services.sample_api import (
    SampleApiError,
    check_connection,
    fetch_worklist_samples,
    parse_api_samples,
)

from .test_sample_api import _get, lims_wire  # noqa: F401 - lims_wire is a fixture

CONFIG = SampleApiConfig(base_url="https://lims.example.org/api", enabled=True)


def _twice(name):
    return (f"The LIMS reply has the name {name!r} twice in one object. SeqSetup cannot tell "
            f"which value is right, so the reply was not used.")


class TestALimsReplyWithANameTwice:
    """json.loads keeps the last of a repeated name, so a patient's row could
    disappear before SeqSetup sees it."""

    def test_the_old_format_with_a_sample_twice_is_refused(self, lims_wire):
        lims_wire.body = b'{"AL": "W1", "samples": {"S1": "WGS", "S2": "WGS", "S1": "WES"}}'
        with pytest.raises(SampleApiError) as exc:
            _get()
        assert str(exc.value) == _twice("S1")

    def test_a_report_with_a_name_twice_is_refused(self, lims_wire):
        lims_wire.body = b'[{"SampleID": "P1", "TestID": "WGS", "SampleID": "P2"}]'
        with pytest.raises(SampleApiError) as exc:
            _get()
        assert str(exc.value) == _twice("SampleID")

    def test_a_name_twice_deeper_down_is_refused(self, lims_wire):
        lims_wire.body = b'{"data": [{"x": {"a": 1, "a": 2}}]}'
        with pytest.raises(SampleApiError) as exc:
            _get()
        assert str(exc.value) == _twice("a")

    def test_a_long_name_is_shortened_in_the_message(self, lims_wire):
        name = "N" * 60
        lims_wire.body = ('{"%s": 1, "%s": 2}' % (name, name)).encode()
        with pytest.raises(SampleApiError) as exc:
            _get()
        assert str(exc.value) == _twice("N" * 40 + "…")

    def test_the_same_name_in_two_objects_is_read(self, lims_wire):
        lims_wire.body = b'[{"SampleID": "P1"}, {"SampleID": "P2"}]'
        assert _get() == [{"SampleID": "P1"}, {"SampleID": "P2"}]

    def test_the_worklist_import_shows_the_message(self, lims_wire):
        lims_wire.body = b'{"samples": {"S1": "WGS", "S1": "WES"}}'
        assert fetch_worklist_samples(CONFIG, "W1") == (False, _twice("S1"), [])

    def test_the_connection_check_shows_the_message(self, lims_wire):
        lims_wire.body = b'{"status": "ok", "status": "down"}'
        ok, message = check_connection(CONFIG)
        assert not ok
        assert _twice("status") in message


def _parse_error(rows, config=None):
    with pytest.raises(ValueError) as exc:
        parse_api_samples(rows, config)
    return str(exc.value)


class TestTwoNamesThatDifferOnlyInCapitals:
    """SeqSetup reads a row's names without their capitals, so one of the two
    values would be lost."""

    def test_sampleid_in_two_spellings_is_refused(self):
        assert _parse_error([{"SampleID": "P1", "sampleid": "P2"}]) == (
            "LIMS row 1 has the names 'SampleID' and 'sampleid', which SeqSetup reads as one "
            "name. Send only one of them.")

    def test_the_row_is_named(self):
        message = _parse_error([{"SampleID": "P1"}, {"TestID": "WGS", "SampleID": "P2",
                                                     "TESTID": "WES"}])
        assert message == ("LIMS row 2 has the names 'TestID' and 'TESTID', which SeqSetup "
                           "reads as one name. Send only one of them.")

    def test_a_name_seqsetup_does_not_read_may_come_twice(self):
        rows = parse_api_samples([{"SampleID": "P1", "Comment": "a", "comment": "b"}])
        assert [r["sample_id"] for r in rows] == ["P1"]

    def test_an_admins_mapped_name_is_checked(self):
        config = SampleApiConfig(field_mappings={"worksheet_id": "WsNo"})
        assert _parse_error([{"sample_id": "S1", "WsNo": "W1", "wsno": "W2"}], config) == (
            "LIMS row 1 has the names 'WsNo' and 'wsno', which SeqSetup reads as one name. "
            "Send only one of them.")

    def test_a_worksheet_field_an_admin_maps_is_not_checked(self):
        """investigator, updated_at and samples name worksheet fields, which a
        sample row does not use (review of 91fbe8e)."""
        config = SampleApiConfig(field_mappings={"investigator": "Inv", "updated_at": "Updated"})
        rows = parse_api_samples([{"sample_id": "S1", "Inv": "a", "inv": "b",
                                   "Updated": "x", "UPDATED": "y"}], config)
        assert [r["sample_id"] for r in rows] == ["S1"]

    def test_one_spelling_of_each_name_is_read_as_today(self):
        rows = parse_api_samples([{"SampleID": "P1", "TestID": "WGS", "WorksheetID": "W1"}])
        assert rows == [{"sample_id": "P1", "test_id": "WGS", "worksheet_id": "W1",
                         "test_version": ""}]


def _fetched(rows):
    with patch.object(sample_api_module, "_api_get", lambda url, key="": rows):
        ok, message, samples = fetch_worklist_samples(CONFIG, "W1")
    assert ok, message
    return samples


class TestTheFetcherAddsTheWorksheetOnlyWhenItIsMissing:
    """The capitals check must see only names the LIMS sent."""

    @pytest.mark.parametrize("name", ["Worksheet_ID", "WORKSHEET_ID", "worksheet_id"])
    def test_a_row_with_the_worksheet_keeps_its_own(self, name):
        samples = _fetched([{"sample_id": "S1", name: "W9"}])
        assert samples == [{"sample_id": "S1", name: "W9"}]
        assert parse_api_samples(samples)[0]["worksheet_id"] == "W9"

    def test_a_row_with_igenes_worksheetid_gets_it_added_as_today(self):
        samples = _fetched([{"SampleID": "S1", "WorksheetID": "W9"}])
        assert samples == [{"SampleID": "S1", "WorksheetID": "W9", "worksheet_id": "W1"}]
        assert parse_api_samples(samples)[0]["worksheet_id"] == "W1"

    def test_a_row_without_one_gets_it_added(self):
        assert _fetched([{"sample_id": "S1"}]) == [{"sample_id": "S1", "worksheet_id": "W1"}]
