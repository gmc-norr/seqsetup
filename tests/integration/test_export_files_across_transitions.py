"""The files a run points at, across every transition it can make.

READY -> DRAFT -> READY writes new files and the old ones stay; READY ->
ARCHIVED keeps serving, also from a fresh app instance; a deleted run's kept
copy names files that are still there
(docs/design/2026-10-16-export-files-own-records-design.md, "What proves it"
5 and 6).
"""

from seqsetup.models.sequencing_run import EXPORT_KINDS, RunStatus
from seqsetup.services.run_exports import read_export
from seqsetup.services.samplesheet_v1_exporter import SampleSheetV1Exporter

from .conftest import mark_ready, nothing_stored, stored_export
from .test_export_files_own_records import BOTH_SHEETS, ORIGIN, records, seed_run


HX = {"Origin": "http://testserver", "HX-Request": "true"}


def _edit_again(client, ctx, run_id):
    """Back to Draft, and the lock the status route granted."""
    assert client.post(f"/runs/{run_id}/status/draft", headers=ORIGIN).status_code == 200
    assert ctx.run_repo.get_by_id(run_id).status == RunStatus.DRAFT


class TestBackToDraftAndReadyAgain:

    def test_the_second_ready_names_new_files_and_the_old_ones_stay(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = seed_run(ctx, "re-promoted")
        assert mark_ready(logged_in_client, run_id, ORIGIN).status_code == 200
        first = dict(ctx.run_repo.get_by_id(run_id).exports)

        _edit_again(logged_in_client, ctx, run_id)
        assert mark_ready(logged_in_client, run_id, ORIGIN).status_code == 200

        second = ctx.run_repo.get_by_id(run_id).exports
        assert set(second) == set(EXPORT_KINDS)
        for kind in EXPORT_KINDS:
            assert second[kind]["id"] != first[kind]["id"], kind
            assert ctx.run_export_repo.get(first[kind]["id"]) is not None, (
                f"the first Ready's {kind} was removed")

    def test_back_to_draft_leaves_the_run_naming_nothing(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = seed_run(ctx, "back-to-draft")
        assert mark_ready(logged_in_client, run_id, ORIGIN).status_code == 200

        _edit_again(logged_in_client, ctx, run_id)

        assert nothing_stored(ctx, run_id)
        assert len(records(ctx, run_id)) == len(EXPORT_KINDS), "the files were removed"

    def test_a_v1_sheet_withheld_the_second_time_is_not_served(
            self, logged_in_client, fresh_app, monkeypatch):
        """Ready with a v1 sheet, back to Draft, changed so v1 is withheld,
        Ready again: no v1 sheet, and not the one from the first Ready."""
        _app, ctx, _db = fresh_app
        run_id = seed_run(ctx, "v1-then-withheld")
        assert mark_ready(logged_in_client, run_id, ORIGIN).status_code == 200
        assert stored_export(ctx, run_id, "samplesheet_v1"), "the run had no v1 sheet to lose"

        _edit_again(logged_in_client, ctx, run_id)
        monkeypatch.setattr(SampleSheetV1Exporter, "withheld", classmethod(
            lambda cls, run, mismatches=None:
            ("S1 has OverrideCycles a v1 sheet cannot hold", ["S1"])))
        assert mark_ready(logged_in_client, run_id, ORIGIN).status_code == 200

        stored = ctx.run_repo.get_by_id(run_id)
        assert "samplesheet_v1" not in stored.exports
        assert stored.samplesheet_v1_withheld
        resp = logged_in_client.get(f"/runs/{run_id}/export/samplesheet-v1")
        assert resp.status_code == 409, resp.text[:200]
        assert "OLD" not in resp.text


class TestTheReadyManifestNamesExactlyWhatWasJustWritten:
    """The manifest is assigned whole, never merged into one already there.

    A Draft should never carry a manifest -- Return to Draft empties it --
    but a hand-edited document or a future path that forgot to could leave
    one, and then a merge would let a Ready run name a file from before the
    edit cycle beside the new ones. The lab would be served the index the
    operator had just replaced.
    """

    def test_a_draft_that_carries_a_stale_manifest_does_not_keep_it(
            self, logged_in_client, fresh_app, monkeypatch):
        from .conftest import seed_stored_exports
        _app, ctx, _db = fresh_app
        run_id = seed_run(ctx, "stale-manifest")
        stale = seed_stored_exports(ctx, run_id, samplesheet_v1="[Header]\nSTALE-V1\n")
        run = ctx.run_repo.get_by_id(run_id)
        run.exports = stale
        ctx.run_repo.save(run)
        # ... and this Mark Ready writes no v1 sheet of its own.
        monkeypatch.setattr(SampleSheetV1Exporter, "withheld", classmethod(
            lambda cls, run, mismatches=None: ("S1 cannot have one", ["S1"])))

        assert mark_ready(logged_in_client, run_id, ORIGIN).status_code == 200

        stored = ctx.run_repo.get_by_id(run_id)
        assert "samplesheet_v1" not in stored.exports, (
            "the Ready run kept a file from before the edit cycle")
        assert stored.exports["samplesheet_v2"]["id"] != stale.get("samplesheet_v1", {}).get("id")
        resp = logged_in_client.get(f"/runs/{run_id}/export/samplesheet-v1")
        assert resp.status_code == 409 and "STALE-V1" not in resp.text


class TestArchived:

    def test_an_archived_run_still_serves_every_file(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = seed_run(ctx, "to-archive")
        assert mark_ready(logged_in_client, run_id, ORIGIN).status_code == 200
        before = {kind: stored_export(ctx, run_id, kind) for kind in EXPORT_KINDS}

        assert logged_in_client.post(f"/runs/{run_id}/status/archived",
                                     headers=ORIGIN).status_code == 200

        stored = ctx.run_repo.get_by_id(run_id)
        assert stored.status == RunStatus.ARCHIVED
        for kind in EXPORT_KINDS:
            assert stored_export(ctx, stored, kind) == before[kind], kind

    def test_a_fresh_app_instance_serves_the_same_bytes(self, logged_in_client, fresh_app):
        """Nothing is cached in the process: a second context over the same
        database reads the same files."""
        from seqsetup.context import AppContext
        _app, ctx, db = fresh_app
        run_id = seed_run(ctx, "fresh-instance")
        assert mark_ready(logged_in_client, run_id, ORIGIN).status_code == 200
        assert logged_in_client.post(f"/runs/{run_id}/status/archived",
                                     headers=ORIGIN).status_code == 200
        before = {kind: stored_export(ctx, run_id, kind) for kind in EXPORT_KINDS}

        from seqsetup.repositories.run_export_repo import RunExportRepository
        from seqsetup.repositories.run_repo import RunRepository
        other = AppContext(run_repo=RunRepository(db), index_kit_repo=ctx.index_kit_repo,
                           test_repo=ctx.test_repo,
                           run_export_repo=RunExportRepository(db))

        run = other.run_repo.get_by_id(run_id)
        for kind in EXPORT_KINDS:
            assert read_export(other, run, kind) == before[kind], kind


class TestADeletedRunsCopy:

    def test_the_copy_names_files_that_are_still_there(self, logged_in_client, fresh_app):
        _app, ctx, db = fresh_app
        run_id = seed_run(ctx, "deleted-with-files")
        assert mark_ready(logged_in_client, run_id, ORIGIN).status_code == 200
        assert logged_in_client.post(f"/runs/{run_id}/status/archived",
                                     headers=ORIGIN).status_code == 200
        before = {kind: stored_export(ctx, run_id, kind) for kind in EXPORT_KINDS}

        assert logged_in_client.delete(f"/runs/{run_id}", headers=HX).status_code == 200

        assert ctx.run_repo.get_by_id(run_id) is None
        (copy,) = list(db["deleted_runs"].find({"run_id": run_id}))
        manifest = copy["run"]["exports"]
        assert set(manifest) == set(EXPORT_KINDS)
        for kind, entry in manifest.items():
            record = ctx.run_export_repo.get(entry["id"])
            assert record is not None, f"the copy's {kind} is gone"
            content = record["content"]
            assert content == before[kind], kind
