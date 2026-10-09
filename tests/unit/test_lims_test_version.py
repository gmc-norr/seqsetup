"""A LIMS sample's test version (spec 2026-10-07 group A4, §2): checked by
its JSON type before anything turns it into text, never cut, and a bad one
refuses the whole worklist."""

import json

import pytest

from seqsetup.models.sample import TEST_VERSION_RULE
from seqsetup.models.sample_api_config import SampleApiConfig
from seqsetup.services.sample_api import parse_api_samples


def _version(raw_json: str, config=None) -> str:
    """The version parse_api_samples reads from one sample of test WGS
    written as JSON."""
    (sample,) = parse_api_samples(
        json.loads(f'[{{"sample_id": "S1", "test_id": "WGS", {raw_json}}}]'), config)
    return sample["test_version"]


def _refused(raw_json: str) -> str:
    with pytest.raises(ValueError) as caught:
        _version(raw_json)
    return str(caught.value)


class TestByJsonType:
    def test_text_is_kept(self):
        assert _version('"test_version": "1.10"') == "1.10"

    def test_text_is_stripped(self):
        assert _version('"test_version": " 1.2 "') == "1.2"

    @pytest.mark.parametrize("raw,text", [("2", "2"), ("0", "0"), ("10", "10")])
    def test_a_whole_number_keeps_its_digits(self, raw, text):
        # Measured on e65c60d: 0 was read as "" (no version).
        assert _version(f'"test_version": {raw}') == text

    def test_null_is_no_version(self):
        assert _version('"test_version": null') == ""

    def test_absent_is_no_version(self):
        (sample,) = parse_api_samples([{"sample_id": "S1"}])
        assert sample["test_version"] == ""

    def test_a_version_without_a_test_is_refused(self):
        # A test and its version are set together (spec §2, decision 6).
        with pytest.raises(ValueError) as caught:
            parse_api_samples([{"sample_id": "S1", "test_version": "1"}])
        assert str(caught.value) == "Sample 'S1' has a test version but no test."

    def test_no_test_and_no_version_is_kept(self):
        (sample,) = parse_api_samples([{"sample_id": "S1", "test_version": None}])
        assert (sample.get("test_id", ""), sample["test_version"]) == ("", "")

    def test_a_decimal_number_is_refused(self):
        # JSON has already read 1.10 as 1.1 (measured on e65c60d: "1.1").
        assert _refused('"test_version": 1.10') == (
            "Sample 'S1' has a test version that is a number with a decimal point (1.1), which "
            "JSON may have changed (1.10 is read as 1.1). Send it as text, for example \"1.10\".")

    @pytest.mark.parametrize("raw,shown", [("true", "true"), ("false", "false"),
                                           ('["1"]', '["1"]'), ('{"v": 1}', '{"v": 1}')])
    def test_other_types_are_refused(self, raw, shown):
        assert _refused(f'"test_version": {raw}') == (
            f"Sample 'S1' has a test version that is not text or a whole number ({shown}).")

    @pytest.mark.parametrize("raw,shown", [
        ('"v1"', "'v1'"), ("-1", "'-1'"), ("1234567890", "'1234567890'"),
        ('"1.x"', "'1.x'"),
    ])
    def test_a_value_that_breaks_the_rule_is_refused(self, raw, shown):
        assert _refused(f'"test_version": {raw}') == (
            f"Sample 'S1' has a test version that is not right ({shown}). {TEST_VERSION_RULE}.")

    def test_a_long_text_is_refused_not_cut(self):
        # Every other LIMS field is cut at 256; cut, this one would pass.
        text = "1" + "0" * 300 + "v"
        assert _refused(f'"test_version": "{text}"') == (
            f"Sample 'S1' has a test version that is not right ('{text[:40]}…'). "
            f"{TEST_VERSION_RULE}.")


class TestTheFieldName:
    def test_the_other_name(self):
        assert _version('"TestVersion": "1"') == "1"

    def test_a_mapped_name(self):
        config = SampleApiConfig(field_mappings={"test_version": "AssayVersion"})
        assert _version('"AssayVersion": "2.1"', config) == "2.1"

    def test_a_null_mapped_field_is_passed_over(self):
        # As for every field: a null name gives way to the next one.
        config = SampleApiConfig(field_mappings={"test_version": "AssayVersion"})
        assert _version('"AssayVersion": null, "test_version": "2"', config) == "2"

    def test_a_mapped_name_is_checked_by_type_too(self):
        # Before group A4 a mapped field was copied as text, so 1.10 became "1.1".
        config = SampleApiConfig(field_mappings={"test_version": "AssayVersion"})
        with pytest.raises(ValueError, match="a number with a decimal point"):
            _version('"AssayVersion": 1.10', config)

    def test_version_alone_is_not_read(self):
        assert _version('"version": "1"') == ""

    def test_the_igene_worklist_has_none(self):
        # fetch_worklist_samples turns {sample_id: test_id} into these rows.
        (sample,) = parse_api_samples([{"sample_id": "S1", "test_id": "WGS", "worksheet_id": "AL1"}])
        assert (sample["test_id"], sample["test_version"]) == ("WGS", "")


class TestTheSampleIdAndTheTestByJsonType:
    """A sample ID or a test sent as a number with a decimal point, or as
    true or false, refuses the whole worklist; text and whole numbers are
    read as before (spec §2, decision 12)."""

    def _refused(self, raw_json: str, config=None) -> str:
        with pytest.raises(ValueError) as caught:
            parse_api_samples(json.loads(raw_json), config)
        return str(caught.value)

    def test_a_decimal_sample_id(self):
        # Measured on e65c60d: 23.10 was read as "23.1".
        assert self._refused('[{"sample_id": "S1"}, {"sample_id": "S2"}, {"sample_id": 23.10}]') == (
            "LIMS row 3 has a sample ID that is a number with a decimal point (23.1), which JSON "
            'may have changed (1.10 is read as 1.1). Send it as text, for example "1.10".')

    @pytest.mark.parametrize("raw", ["true", "false"])
    def test_a_true_or_false_sample_id(self, raw):
        # Measured on e65c60d: true was read as "True", false as a missing sample ID.
        assert self._refused(f'[{{"sample_id": {raw}}}]') == (
            f"LIMS row 1 has a sample ID that is not text or a whole number ({raw}).")

    def test_a_decimal_test(self):
        # Measured on e65c60d: 1.10 was read as "1.1".
        assert self._refused('[{"sample_id": "S1", "test_id": 1.10}]') == (
            "Sample 'S1' has a test that is a number with a decimal point (1.1), which JSON may "
            'have changed (1.10 is read as 1.1). Send it as text, for example "1.10".')

    @pytest.mark.parametrize("raw", ["true", "false"])
    def test_a_true_or_false_test(self, raw):
        assert self._refused(f'[{{"sample_id": "S1", "test_id": {raw}}}]') == (
            f"Sample 'S1' has a test that is not text or a whole number ({raw}).")

    def test_a_mapped_name_is_checked_too(self):
        config = SampleApiConfig(field_mappings={"sample_id": "LabNo", "test_id": "Assay_Code"})
        assert self._refused('[{"LabNo": 2.5}]', config).startswith(
            "LIMS row 1 has a sample ID that is a number with a decimal point (2.5)")
        assert self._refused('[{"LabNo": "S1", "Assay_Code": 2.5}]', config).startswith(
            "Sample 'S1' has a test that is a number with a decimal point (2.5)")

    def test_a_null_name_gives_way_to_the_next(self):
        assert self._refused('[{"sample_id": null, "id": true}]') == (
            "LIMS row 1 has a sample ID that is not text or a whole number (true).")

    def _igene(self, monkeypatch, body: str) -> list[dict]:
        """The rows fetch_worklist_samples makes of iGene's {sample_id: test_id}."""
        from seqsetup.services import sample_api
        monkeypatch.setattr(sample_api, "_api_get", lambda url, api_key="": json.loads(body))
        ok, message, rows = sample_api.fetch_worklist_samples(
            SampleApiConfig(enabled=True, base_url="https://lims.example.org"), "AL1")
        assert ok, message
        return rows

    @pytest.mark.parametrize("raw,shown", [
        ("false", "not text or a whole number (false)"),
        ("true", "not text or a whole number (true)"),
        ("0.0", "a number with a decimal point (0.0)"),
        ("1.10", "a number with a decimal point (1.1)"),
    ])
    def test_the_igene_form_checks_the_test_too(self, monkeypatch, raw, shown):
        # Plan review of 8b17009: there false and 0.0 became no test.
        rows = self._igene(monkeypatch, f'{{"samples": {{"S1": {raw}}}}}')
        with pytest.raises(ValueError) as caught:
            parse_api_samples(rows)
        assert str(caught.value).startswith(f"Sample 'S1' has a test that is {shown}")

    def test_the_igene_form_reads_text_and_no_test_as_before(self, monkeypatch):
        rows = self._igene(monkeypatch, '{"samples": {"S1": "WGS", "S2": null, "S3": ""}}')
        assert [(s["sample_id"], s["test_id"]) for s in parse_api_samples(rows)] == [
            ("S1", "WGS"), ("S2", ""), ("S3", "")]

    def test_whole_numbers_and_text_are_read_as_before(self):
        (first, second) = parse_api_samples(json.loads(
            '[{"sample_id": 12345, "test_id": 7}, {"sample_id": " S2 ", "test_id": "WGS"}]'))
        assert [(s["sample_id"], s["test_id"]) for s in (first, second)] == [
            ("12345", "7"), ("S2", "WGS")]
