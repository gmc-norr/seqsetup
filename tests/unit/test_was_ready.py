"""A run remembers that it was Ready once (spec 2026-09-28 group 2a, F16).

The flag decides who may delete an emptied draft and whether a copy is
kept. The model keeps it, so no route can forget it or clear it."""

from seqsetup.models.sequencing_run import RunStatus, SequencingRun
from seqsetup.services.json_exporter import JSONExporter
from seqsetup.services.run_diff import diff_run
from seqsetup.services.samplesheet_v2_exporter import SampleSheetV2Exporter


class TestWasReadyFlag:
    """Set by the model when the status becomes Ready or Archived; never cleared."""

    def test_new_run_was_never_ready(self):
        assert SequencingRun().was_ready is False

    def test_becoming_ready_sets_it(self):
        run = SequencingRun()
        run.status = RunStatus.READY
        assert run.was_ready is True

    def test_becoming_archived_sets_it(self):
        run = SequencingRun()
        run.status = RunStatus.ARCHIVED
        assert run.was_ready is True

    def test_back_to_draft_keeps_it(self):
        run = SequencingRun()
        run.status = RunStatus.READY
        run.status = RunStatus.DRAFT
        assert run.was_ready is True

    def test_cannot_be_cleared(self):
        run = SequencingRun()
        run.status = RunStatus.READY
        run.status = RunStatus.DRAFT
        run.was_ready = False
        assert run.was_ready is True

    def test_built_ready_is_true(self):
        assert SequencingRun(status=RunStatus.READY).was_ready is True

    def test_built_archived_with_false_is_still_true(self):
        assert SequencingRun(status=RunStatus.ARCHIVED, was_ready=False).was_ready is True

    def test_draft_can_be_built_as_once_ready(self):
        assert SequencingRun(status=RunStatus.DRAFT, was_ready=True).was_ready is True

    def test_stored_ready_or_archived_without_the_key_loads_true(self):
        for status in ("ready", "archived"):
            doc = SequencingRun().to_dict()
            doc.pop("was_ready", None)
            doc["status"] = status
            assert SequencingRun.from_dict(doc).was_ready is True, status

    def test_stored_draft_without_the_key_loads_false(self):
        doc = SequencingRun().to_dict()
        doc.pop("was_ready", None)
        assert SequencingRun.from_dict(doc).was_ready is False

    def test_round_trip(self):
        run = SequencingRun()
        run.status = RunStatus.READY
        run.status = RunStatus.DRAFT
        again = SequencingRun.from_dict(run.to_dict())
        assert (again.status, again.was_ready) == (RunStatus.DRAFT, True)


class TestWasReadyIsNotAHistoryLine:
    """The history already records the status change that sets the flag."""

    def test_ready_save_records_the_status_only(self):
        run = SequencingRun()
        before = run.to_dict()
        run.status = RunStatus.READY
        field_changes, _samples = diff_run(before, run.to_dict())
        assert [c["field"] for c in field_changes] == ["status"]


class TestExportsDoNotCarryTheFlag:
    """No export reads the flag: the bytes are the same either way."""

    def test_sheet_and_json_are_the_same_bytes(self, sample_run):
        never = SequencingRun.from_dict(sample_run.to_dict())
        doc = sample_run.to_dict()
        doc["was_ready"] = True
        once = SequencingRun.from_dict(doc)
        assert (never.was_ready, once.was_ready) == (False, True)
        assert SampleSheetV2Exporter.export(once) == SampleSheetV2Exporter.export(never)
        assert JSONExporter.export(once) == JSONExporter.export(never)
