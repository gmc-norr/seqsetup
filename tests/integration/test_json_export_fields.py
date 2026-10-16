"""The JSON export carries a sample's test, worksheet, index kit and
mismatch numbers (outside review of f490536, finding F7; design note
docs/design/2026-10-16-json-export-fields-design.md).

Measured by the verifier: a sample whose i7 mismatch is 2 produces
BarcodeMismatchesIndex1,2 in the Sample Sheet while the JSON stated only
the run-level 1 under bclconvert_settings, so two exports of one run
disagreed about a number and a reader could not tell which was right. The
sample's test, test version, worksheet and index kit were missing too, and
the run's test_versions_used and i5_workflow.
"""

import json
from pathlib import Path

from seqsetup.models.sequencing_run import RunStatus
from seqsetup.services.json_exporter import JSONExporter

from .conftest import hold_edit_lock
from .test_group_a3 import ORIGIN, profiles  # noqa: F401  (the fixture)
from .test_group_a4 import _a3_draft

OLD_KEYS = {"id", "sample_id", "sample_name", "project", "lanes", "index1", "index2",
            "samplesheet_index2", "override_cycles", "samplesheet_override_cycles",
            "analyses", "description", "metadata"}
NEW_SAMPLE_KEYS = {"test_id", "test_version", "worksheet_id", "index_kit_name",
                   "barcode_mismatches_index1", "barcode_mismatches_index2",
                   "samplesheet_barcode_mismatches_index1",
                   "samplesheet_barcode_mismatches_index2"}


def _draft(ctx, run_id, **fields):
    _a3_draft(ctx, run_id, "1.0.0")
    if fields:
        run = ctx.run_repo.get_by_id(run_id)
        for key, value in fields.items():
            setattr(run.samples[0], key, value)
        ctx.run_repo.save(run)
        hold_edit_lock(ctx, run_id)
    return run_id


def _ready_json(ctx, client, run_id):
    from .conftest import mark_ready
    resp = mark_ready(client, run_id, ORIGIN)
    assert resp.status_code == 200, resp.text[:400]
    run = ctx.run_repo.get_by_id(run_id)
    assert run.status == RunStatus.READY, resp.text[:400]
    return json.loads(run.generated_json), run


class TestASampleCarriesItsTestAndWorksheet:

    def test_the_test_the_version_the_worksheet_and_the_kit_are_there(
            self, logged_in_client, profiles):  # noqa: F811
        run_id = _draft(profiles, "json-fields", worksheet_id="WS-77",
                        index_kit_name="JsonKit")

        data, _run = _ready_json(profiles, logged_in_client, run_id)
        sample = data["samples"][0]

        assert sample["test_id"] == "A3T"
        assert sample["test_version"] == "1.0.0"
        assert sample["worksheet_id"] == "WS-77"
        assert sample["index_kit_name"] == "JsonKit"

    def test_every_new_key_is_present(self, logged_in_client, profiles):  # noqa: F811
        run_id = _draft(profiles, "json-new-keys")

        data, _run = _ready_json(profiles, logged_in_client, run_id)

        assert NEW_SAMPLE_KEYS <= set(data["samples"][0]), (
            NEW_SAMPLE_KEYS - set(data["samples"][0]))

    def test_no_old_key_is_lost_or_renamed(self, logged_in_client, profiles):  # noqa: F811
        run_id = _draft(profiles, "json-old-keys")

        data, _run = _ready_json(profiles, logged_in_client, run_id)

        assert OLD_KEYS <= set(data["samples"][0]), OLD_KEYS - set(data["samples"][0])


class TestTheMismatchNumbersAgreeWithTheSheet:

    def test_a_samples_own_number_is_exported(self, logged_in_client, profiles):  # noqa: F811
        run_id = _draft(profiles, "json-mm-own", barcode_mismatches_index1=2,
                        barcode_mismatches_index2=0)

        data, _run = _ready_json(profiles, logged_in_client, run_id)
        sample = data["samples"][0]

        assert sample["barcode_mismatches_index1"] == 2
        assert sample["barcode_mismatches_index2"] == 0

    def test_the_number_the_sheet_writes_is_exported_too(
            self, logged_in_client, profiles):  # noqa: F811
        """Read from the sheet plan, the one place that resolves it -- not
        derived again in the exporter. The measured defect: the sheet said 2
        and the JSON said only the run-level 1."""
        run_id = _draft(profiles, "json-mm-sheet", barcode_mismatches_index1=2)

        data, run = _ready_json(profiles, logged_in_client, run_id)
        sample = data["samples"][0]

        assert sample["samplesheet_barcode_mismatches_index1"] == 2, (
            "the JSON does not say what the sheet carries")
        assert data["bclconvert_settings"]["barcode_mismatches_index1"] == 1, (
            "the run default is still 1, which is what used to be the only number")
        assert "BarcodeMismatchesIndex1" in run.generated_samplesheet_v2

    def test_the_sheet_number_is_there_even_with_no_override_of_its_own(
            self, logged_in_client, profiles):  # noqa: F811
        run_id = _draft(profiles, "json-mm-default")

        data, _run = _ready_json(profiles, logged_in_client, run_id)
        sample = data["samples"][0]

        assert sample["samplesheet_barcode_mismatches_index1"] is not None
        assert sample["samplesheet_barcode_mismatches_index2"] is not None


class TestTheRunCarriesItsVersionsAndDirection:

    def test_the_test_versions_the_checks_passed_are_exported(
            self, logged_in_client, profiles):  # noqa: F811
        """The JSON is written before run.test_versions_used is set, so the
        versions have to be passed in."""
        run_id = _draft(profiles, "json-versions")

        data, run = _ready_json(profiles, logged_in_client, run_id)

        assert data["test_versions_used"], "the run passed a test version but JSON has none"
        assert data["test_versions_used"] == run.test_versions_used

    def test_the_i5_workflow_is_exported(self, logged_in_client, profiles):  # noqa: F811
        run_id = _draft(profiles, "json-i5")

        data, _run = _ready_json(profiles, logged_in_client, run_id)

        assert data["i5_workflow"] == "Standard", data.get("i5_workflow")


class TestTheLiveFallbackForOlderRuns:
    """Runs made before pre-generation existed are exported live, with no
    sheet plan: the two samplesheet_* mismatch keys are null, not missing --
    the shape samplesheet_index2 already has when SeqSetup cannot say what
    the sheet would write."""

    def test_the_sheet_numbers_are_present_and_null(self, profiles):  # noqa: F811
        run_id = _draft(profiles, "json-live")
        run = profiles.run_repo.get_by_id(run_id)

        sample = json.loads(JSONExporter.export(run))["samples"][0]

        assert sample["samplesheet_barcode_mismatches_index1"] is None
        assert sample["samplesheet_barcode_mismatches_index2"] is None
        assert sample["test_id"] == "A3T", "the sample's own fields are there either way"
        assert sample["barcode_mismatches_index1"] == 1

    def test_the_run_keys_are_present_too(self, profiles):  # noqa: F811
        run_id = _draft(profiles, "json-live-run")
        run = profiles.run_repo.get_by_id(run_id)

        data = json.loads(JSONExporter.export(run))

        assert data["test_versions_used"] == [], "a Draft has passed no versions yet"
        assert data["i5_workflow"] == "Standard"


class TestTheReadmeNoLongerOverstatesIt:

    def test_it_does_not_call_the_json_complete(self):
        text = (Path(__file__).resolve().parents[2] / "README.md").read_text()
        line = [l for l in text.splitlines() if l.startswith("| JSON Metadata")]
        assert line, "the README's export table no longer has a JSON Metadata row"
        assert "Complete run and sample data" not in line[0], line[0]


class TestASampleWithoutAnIndexSaysNothingAboutItsNumber:
    """A fresh review proved the JSON stated a NUMBER where the sheet writes
    ``na``: the v2 writer puts the index-presence guard first, while the
    sheet plan stores a number for every sample. An i7-only sample's
    BarcodeMismatchesIndex2 cell is ``na``, and the JSON said 1 -- or 2,
    where the operator had typed 2 for an index the sample does not have.
    ``samplesheet_index2`` is already null for such a sample; these two keys
    now follow it."""

    def _i7_only(self, ctx, run_id):
        from seqsetup.models.index import Index, IndexType
        _a3_draft(ctx, run_id, "1.0.0")
        run = ctx.run_repo.get_by_id(run_id)
        sample = run.samples[0]
        kept = sample.index1_sequence
        sample.index_pair = None
        sample.assign_index1(Index(name="i7", sequence=kept, index_type=IndexType.I7))
        ctx.run_repo.save(run)
        hold_edit_lock(ctx, run_id)
        return run

    def test_the_i5_number_is_null_when_the_sample_has_no_i5(self, profiles):  # noqa: F811
        run = self._i7_only(profiles, "json-no-i5")

        sample = json.loads(JSONExporter.export(
            run, sheet_mismatches={(run.samples[0].id, 1): 1,
                                   (run.samples[0].id, 2): 1}))["samples"][0]

        assert sample["index2"] is None, "this sample is supposed to have no i5"
        assert sample["samplesheet_index2"] is None
        assert sample["samplesheet_barcode_mismatches_index2"] is None, (
            "the sheet writes na for an index the sample does not have")

    def test_a_number_typed_for_an_index_it_does_not_have_is_not_published(
            self, profiles):  # noqa: F811
        run = self._i7_only(profiles, "json-no-i5-typed")
        run.samples[0].barcode_mismatches_index2 = 2
        profiles.run_repo.save(run)
        hold_edit_lock(profiles, run.id)

        sample = json.loads(JSONExporter.export(
            run, sheet_mismatches={(run.samples[0].id, 2): 2}))["samples"][0]

        assert sample["barcode_mismatches_index2"] == 2, "the sample's own value is still shown"
        assert sample["samplesheet_barcode_mismatches_index2"] is None, (
            "the sheet writes na, so the JSON must not publish 2 as the sheet's number")

    def test_control_the_i7_number_is_still_published(self, profiles):  # noqa: F811
        run = self._i7_only(profiles, "json-no-i5-control")

        sample = json.loads(JSONExporter.export(
            run, sheet_mismatches={(run.samples[0].id, 1): 2}))["samples"][0]

        assert sample["samplesheet_barcode_mismatches_index1"] == 2


class TestTheSheetsNumberComesFromTheProfilesDefault:
    """The case the whole design rests on, driven through Mark Ready: the
    sample overrides nothing, so the sheet's cell is the application
    profile's Data default -- a number only the sheet plan knows."""

    def test_the_json_states_the_profiles_number_not_the_run_default(
            self, logged_in_client, profiles):  # noqa: F811
        from .test_group_a3 import _bcl_profile
        # Replace the fixture's profile: a second one of the same name and
        # version is a different thing entirely (the sync refuses it).
        profiles.app_profile_repo.delete_all()
        profiles.app_profile_repo.save(_bcl_profile(mismatch_default=2))
        from seqsetup.services.validation import clear_validation_cache
        clear_validation_cache()
        run_id = _draft(profiles, "json-profile-default")
        run = profiles.run_repo.get_by_id(run_id)
        run.samples[0].barcode_mismatches_index1 = None
        profiles.run_repo.save(run)
        hold_edit_lock(profiles, run_id)

        data, stored = _ready_json(profiles, logged_in_client, run_id)
        sample = data["samples"][0]

        assert sample["barcode_mismatches_index1"] is None, "the sample overrides nothing"
        assert sample["samplesheet_barcode_mismatches_index1"] == 2, (
            "the JSON does not state the profile's number, which is what the sheet writes")
        assert data["bclconvert_settings"]["barcode_mismatches_index1"] == 1, (
            "the run default is 1: that is the number the JSON used to give")
        row = [l for l in stored.generated_samplesheet_v2.splitlines()
               if l.startswith("A3T") or ",2," in l]
        assert any("2" in l for l in row), row[:3]
