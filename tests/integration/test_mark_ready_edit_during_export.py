"""Mark Ready refuses when the run was edited or deleted while its exports
were being generated.

``update_status`` writes the sheets and the report from the run it loaded,
then reads the run again before it saves. A run deleted in between is
refused ("was deleted while its exports were being generated"); a run whose
export inputs changed in between (``_export_input_fingerprint``) is refused
with the audit reason ``concurrent_edit_during_export``, so stale sheets are
never stored on a newer run. Neither branch had a test (only the fingerprint
helper, for one field, in tests/unit/test_run_i5_workflow.py); this file
closes that gap ("Risk 5").

The other person's change is made through the repository, as their own
save would make it, from inside the export step.
"""

from ..sheet_through_profiles import sheet as sheet_through_profiles

import html

import pytest

from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun
from seqsetup.services.samplesheet_v2_exporter import SampleSheetV2Exporter

from .conftest import hold_edit_lock, mark_ready, nothing_stored, stored_export, seed_profiles

ORIGIN = {"Origin": "http://testserver"}
OTHER_USER = "other-user"
EDITED_MESSAGE = (
    "This run was edited by another user (or session) while its exports were being generated."
)
DELETED_MESSAGE = "was deleted while its exports were being generated."


def _pair(i7: str, i5: str, name: str) -> IndexPair:
    return IndexPair(
        id=name, name=name,
        index1=Index(name=f"{name}-i7", sequence=i7, index_type=IndexType.I7),
        index2=Index(name=f"{name}-i5", sequence=i5, index_type=IndexType.I5),
    )


def _draft(ctx, run_id: str) -> SequencingRun:
    """A two-sample Draft that passes the checks with no profiles (the
    hardcoded BCLConvert path), its edit lock held by the logged-in admin."""
    seed_profiles(ctx)
    run = SequencingRun(
        id=run_id, run_name="Edited mid-export",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8),
    )
    run.add_sample(Sample(test_id="WGS", test_version="1", sample_id="S1", index_pair=_pair("ATTACTCG", "TATAGCCT", "p1"), lanes=[1]))
    run.add_sample(Sample(test_id="WGS", test_version="1", sample_id="S2", index_pair=_pair("TCCGGAGA", "ATAGAGGC", "p2"), lanes=[1]))
    ctx.run_repo.save(run)
    hold_edit_lock(ctx, run.id)
    return run


def _sheet(ctx, run: SequencingRun) -> str:
    return sheet_through_profiles(run, instrument_config=ctx.instrument_config)


def _change_i7(run):
    run.samples[0].assign_index(_pair("GGACTCCT", "TATAGCCT", "p9"))


def _add_sample(run):
    run.add_sample(Sample(test_id="WGS", test_version="1", sample_id="S3", index_pair=_pair("TAGGCATG", "CCTATCCT", "p3"), lanes=[1]))


def _change_lanes(run):
    run.samples[0].lanes = [1, 2]


def _rename_run(run):
    run.run_name = "Renamed by another user"


def _change_read1_cycles(run):
    run.run_cycles = RunCycles(101, 151, 8, 8)


EDITS = {
    "i7-changed": _change_i7,
    "sample-added": _add_sample,
    "lanes-changed": _change_lanes,
    "run-name-changed": _rename_run,
    "read1-cycles-changed": _change_read1_cycles,
}


def _kept(run) -> dict:
    """What each edit wrote, read back from the stored run."""
    return {
        "i7-changed": run.samples[0].index1_sequence,
        "sample-added": [s.sample_id for s in run.samples],
        "lanes-changed": run.samples[0].lanes,
        "run-name-changed": run.run_name,
        "read1-cycles-changed": run.run_cycles.read1_cycles if run.run_cycles else None,
    }


EXPECTED_KEPT = {
    "i7-changed": "GGACTCCT",
    "sample-added": ["S1", "S2", "S3"],
    "lanes-changed": [1, 2],
    "run-name-changed": "Renamed by another user",
    "read1-cycles-changed": 101,
}


def _another_user_saves(ctx, run_id: str, edit) -> None:
    """Load the stored run, change it and save it, as another user's save
    through any edit route would."""
    theirs = ctx.run_repo.get_by_id(run_id)
    if edit is not None:
        edit(theirs)
    theirs.touch(updated_by=OTHER_USER)
    ctx.run_repo.save(theirs)


def _after_the_exports(monkeypatch, action) -> dict:
    """Run ``action`` once, right after ``_pregenerate_exports`` has made
    every export and before Mark Ready reads the run again."""
    from seqsetup.routes import runs
    original = runs._pregenerate_exports
    calls = {"n": 0}

    def exports_then_action(*args, **kwargs):
        made = original(*args, **kwargs)
        calls["n"] += 1
        if calls["n"] == 1:
            action()
        return made

    monkeypatch.setattr(runs, "_pregenerate_exports", exports_then_action)
    return calls


def _assert_no_exports(ctx, stored: SequencingRun) -> None:
    assert stored.status == RunStatus.DRAFT
    assert nothing_stored(ctx, stored)
    assert stored.sheet_targets == {}
    assert stored.test_versions_used == []


def _denied_reasons(ctx, run_id: str) -> list:
    return [
        (e.outcome, e.details.get("reason"))
        for e in ctx.audit_event_repo.search(limit=100, event_prefix="run.status.denied")
        if e.target == run_id
    ]


def _made_ready(ctx, run_id: str) -> list:
    return [
        e for e in ctx.audit_event_repo.search(limit=100, event_prefix="run.status.changed")
        if e.target == run_id and e.details.get("to_status") == "ready"
    ]


class TestAnEditDuringTheExportsIsRefused:
    """Each kind of edit that changes the Sample Sheet, saved by someone else
    while Mark Ready writes the exports, refuses Mark Ready: the run stays a
    Draft with no exports, the other person's edit is kept, and the refusal
    is audited."""

    @pytest.mark.parametrize("kind", list(EDITS))
    def test_an_edit_saved_during_the_exports_refuses_mark_ready(
            self, logged_in_client, fresh_app, monkeypatch, kind):
        _app, ctx, _db = fresh_app
        run = _draft(ctx, f"edit-{kind}")
        sheet_before = _sheet(ctx, run)
        calls = _after_the_exports(monkeypatch, lambda: _another_user_saves(ctx, run.id, EDITS[kind]))

        resp = mark_ready(logged_in_client, run.id, ORIGIN)

        assert calls["n"] == 1, "the exports were never generated"
        assert resp.status_code == 409, html.unescape(resp.text)[:400]
        assert EDITED_MESSAGE in html.unescape(resp.text)
        stored = ctx.run_repo.get_by_id(run.id)
        _assert_no_exports(ctx, stored)
        assert _kept(stored)[kind] == EXPECTED_KEPT[kind], "the other user's edit was lost"
        assert stored.updated_by == OTHER_USER
        # The edit does change the sheet: storing the exports made before
        # it would have stored a sheet that is not this run's.
        assert _sheet(ctx, stored) != sheet_before
        assert _denied_reasons(ctx, run.id).count(("denied", "concurrent_edit_during_export")) == 1
        assert _made_ready(ctx, run.id) == []

    def test_an_edit_saved_while_the_sheet_is_written_refuses_mark_ready(
            self, logged_in_client, fresh_app, monkeypatch):
        """The edit lands inside the v2 writer, before the other exports."""
        _app, ctx, _db = fresh_app
        run = _draft(ctx, "edit-inside-writer")
        original = SampleSheetV2Exporter.export.__func__
        calls = {"n": 0}

        def write_then_edit(cls, *args, **kwargs):
            sheet = original(cls, *args, **kwargs)
            calls["n"] += 1
            if calls["n"] == 1:
                _another_user_saves(ctx, run.id, _change_i7)
            return sheet

        monkeypatch.setattr(SampleSheetV2Exporter, "export", classmethod(write_then_edit))

        resp = mark_ready(logged_in_client, run.id, ORIGIN)

        assert calls["n"] == 1
        assert resp.status_code == 409, html.unescape(resp.text)[:400]
        assert EDITED_MESSAGE in html.unescape(resp.text)
        stored = ctx.run_repo.get_by_id(run.id)
        _assert_no_exports(ctx, stored)
        assert stored.samples[0].index1_sequence == "GGACTCCT"
        assert _denied_reasons(ctx, run.id).count(("denied", "concurrent_edit_during_export")) == 1
        assert _made_ready(ctx, run.id) == []


class TestARunDeletedDuringTheExportsIsRefused:
    """The run's document is gone when Mark Ready reads it again."""

    def test_a_run_deleted_during_the_exports_is_refused_and_not_stored(
            self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        run = _draft(ctx, "deleted-mid-export")
        calls = _after_the_exports(
            monkeypatch, lambda: ctx.run_repo.collection.delete_one({"_id": run.id}))

        resp = mark_ready(logged_in_client, run.id, ORIGIN)

        assert calls["n"] == 1, "the exports were never generated"
        assert resp.status_code == 409, html.unescape(resp.text)[:400]
        assert DELETED_MESSAGE in html.unescape(resp.text)
        assert ctx.run_repo.collection.find_one({"_id": run.id}) is None
        assert ctx.run_repo.get_by_id(run.id) is None
        assert _made_ready(ctx, run.id) == []


class TestControls:
    """The same Mark Ready goes through when nothing that reaches the sheet
    changed, so the refusals above come from the edit."""

    def test_mark_ready_with_no_change_during_the_exports_succeeds(
            self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        run = _draft(ctx, "no-edit-mid-export")
        calls = _after_the_exports(monkeypatch, lambda: None)

        resp = mark_ready(logged_in_client, run.id, ORIGIN)

        assert calls["n"] == 1
        assert resp.status_code == 200, html.unescape(resp.text)[:400]
        stored = ctx.run_repo.get_by_id(run.id)
        assert stored.status == RunStatus.READY
        assert stored_export(ctx, stored, "samplesheet_v2") == _sheet(ctx, run)
        assert stored_export(ctx, stored, "json")
        assert stored_export(ctx, stored, "validation_json")
        assert stored_export(ctx, stored, "validation_pdf")
        assert "concurrent_edit_during_export" not in [r for _o, r in _denied_reasons(ctx, run.id)]
        assert len(_made_ready(ctx, run.id)) == 1

    def test_a_save_that_changes_nothing_in_the_sheet_is_adopted(
            self, logged_in_client, fresh_app, monkeypatch):
        """Only the version moved (a touch): the exports still match the
        run, so Mark Ready saves them onto the newer version."""
        _app, ctx, _db = fresh_app
        run = _draft(ctx, "touch-mid-export")
        moved = {}

        def touch_only():
            before = ctx.run_repo.get_by_id(run.id).updated_at
            _another_user_saves(ctx, run.id, None)
            moved["version"] = ctx.run_repo.get_by_id(run.id).updated_at != before

        calls = _after_the_exports(monkeypatch, touch_only)

        resp = mark_ready(logged_in_client, run.id, ORIGIN)

        assert calls["n"] == 1
        assert moved == {"version": True}, "the other user's save did not move the version"
        assert resp.status_code == 200, html.unescape(resp.text)[:400]
        stored = ctx.run_repo.get_by_id(run.id)
        assert stored.status == RunStatus.READY
        assert stored_export(ctx, stored, "samplesheet_v2") == _sheet(ctx, run)
        assert "concurrent_edit_during_export" not in [r for _o, r in _denied_reasons(ctx, run.id)]
