"""A stored run whose status this release does not know, or none, is refused
when read, never read as a Draft (design note
docs/design/2026-10-18-unknown-status-design.md).

``SequencingRun.from_dict`` and ``RunListing.from_doc`` turned an unknown
stored ``status`` into DRAFT with a log line, and a missing one into
``"draft"`` by default. So a Ready run whose status was damaged -- a database
edit, or a later release renaming a status -- opened as an editable Draft,
left the API (which serves Ready and Archived only), and the first save wrote
``draft`` over the stored value, losing the record that the run had ever been
Ready.

The fallback was there so an archived clinical run never becomes unreadable;
it bought that by quietly unlocking one. This mirrors the choice made for an
unknown instrument on 2026-10-17 (``stored_platform``,
docs/design/2026-10-17-unknown-platform-design.md): such a document is a
damaged one. It cannot be opened, edited, marked Ready, archived or served
until an administrator repairs it, and the dashboard names it.

The legacy ``"complete"`` -> archived mapping stays: SeqSetup wrote it.
"""

import bson
import pytest

from seqsetup.models.api_token import ApiToken
from seqsetup.models.run_listing import RunListing
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import (InstrumentPlatform, RunCycles, RunStatus,
                                            SequencingRun)

from .conftest import hold_edit_lock

UNKNOWN = "finished"


def _run(ctx, run_id, status=RunStatus.DRAFT):
    run = SequencingRun(id=run_id, run_name=run_id,
                        instrument_platform=InstrumentPlatform.NOVASEQ_X,
                        flowcell_type="10B", run_cycles=RunCycles(151, 151, 10, 10),
                        status=status)
    run.add_sample(Sample(id=f"{run_id}-s1", sample_id="PAT-1", lanes=[1]))
    ctx.run_repo.save(run)
    hold_edit_lock(ctx, run_id)
    return run


def _name_status(db, doc_id, status):
    if status is None:
        db["runs"].update_one({"_id": doc_id}, {"$unset": {"status": ""}})
    else:
        db["runs"].update_one({"_id": doc_id}, {"$set": {"status": status}})


def _raw(db, doc_id):
    return bson.encode(db["runs"].find_one({"_id": doc_id}))


def _bearer(ctx):
    plaintext = ApiToken.generate_token()
    token_hash, prefix = ApiToken.hash_token(plaintext)
    ctx.api_token_repo.save(ApiToken(name="status", token_hash=token_hash,
                                     token_prefix=prefix))
    return {"Authorization": f"Bearer {plaintext}"}


class TestEveryReaderRefusesIt:

    @pytest.mark.parametrize("status", [UNKNOWN, None, "", "Ready", "DRAFT", 0])
    def test_a_run(self, fresh_app, status):
        _app, ctx, db = fresh_app
        _run(ctx, "odd")
        _name_status(db, "odd", status)

        with pytest.raises(ValueError) as refused:
            SequencingRun.from_dict(db["runs"].find_one({"_id": "odd"}))

        assert "odd" in str(refused.value)
        assert "status this release does not know" in str(refused.value)
        assert repr(status) in str(refused.value)

    @pytest.mark.parametrize("status", [UNKNOWN, None, "Ready"])
    def test_a_listing_row(self, fresh_app, status):
        _app, ctx, db = fresh_app
        _run(ctx, "odd")
        _name_status(db, "odd", status)

        with pytest.raises(ValueError, match="status this release does not know"):
            RunListing.from_doc(db["runs"].find_one({"_id": "odd"}))

    @pytest.mark.parametrize("status", ["draft", "ready", "archived"])
    def test_a_known_status_still_reads(self, fresh_app, status):
        _app, ctx, db = fresh_app
        _run(ctx, "fine")
        _name_status(db, "fine", status)

        assert ctx.run_repo.get_by_id("fine").status == RunStatus(status)
        assert RunListing.from_doc(db["runs"].find_one({"_id": "fine"})).status == RunStatus(status)

    def test_the_legacy_complete_still_reads_as_archived(self, fresh_app):
        """SeqSetup wrote "complete"; every run it ever wrote stores a status,
        so only a document changed outside SeqSetup lacks one."""
        _app, ctx, db = fresh_app
        _run(ctx, "old", status=RunStatus.ARCHIVED)
        _name_status(db, "old", "complete")

        assert ctx.run_repo.get_by_id("old").status == RunStatus.ARCHIVED
        assert RunListing.from_doc(db["runs"].find_one({"_id": "old"})).status == (
            RunStatus.ARCHIVED)


class TestTheRunIsNamedAndLeftAlone:

    def test_the_dashboard_names_it_and_lists_the_rest(self, logged_in_client, fresh_app):
        _app, ctx, db = fresh_app
        _run(ctx, "good")
        _run(ctx, "odd")
        _name_status(db, "odd", UNKNOWN)
        before = _raw(db, "odd")

        page = logged_in_client.get("/")

        assert page.status_code == 200
        assert 'id="run-item-good"' in page.text
        assert 'id="run-item-odd"' not in page.text
        assert "could not be read" in page.text and "odd" in page.text
        assert _raw(db, "odd") == before

    def test_opening_it_fails_and_writes_nothing(self, logged_in_client, fresh_app):
        _app, ctx, db = fresh_app
        _run(ctx, "odd")
        _name_status(db, "odd", UNKNOWN)
        before = _raw(db, "odd")

        with pytest.raises(ValueError):
            logged_in_client.get("/runs/odd")

        assert _raw(db, "odd") == before

    def test_mark_ready_fails_and_writes_nothing(self, logged_in_client, fresh_app):
        _app, ctx, db = fresh_app
        _run(ctx, "odd")
        _name_status(db, "odd", UNKNOWN)
        before = _raw(db, "odd")

        with pytest.raises(ValueError):
            logged_in_client.post("/runs/odd/status/ready",
                                  headers={"Origin": "http://testserver"})

        assert _raw(db, "odd") == before

    def test_archiving_it_fails_and_keeps_the_stored_status(
            self, logged_in_client, fresh_app):
        """The damaged status was read as Draft, so the first save wrote
        "draft" over it -- the record that the run had been Ready, gone."""
        _app, ctx, db = fresh_app
        _run(ctx, "odd", status=RunStatus.READY)
        _name_status(db, "odd", UNKNOWN)

        with pytest.raises(ValueError):
            logged_in_client.post("/runs/odd/status/archived",
                                  headers={"Origin": "http://testserver"})

        assert db["runs"].find_one({"_id": "odd"})["status"] == UNKNOWN

    def test_editing_it_fails_and_writes_nothing(self, logged_in_client, fresh_app):
        _app, ctx, db = fresh_app
        _run(ctx, "odd")
        _name_status(db, "odd", UNKNOWN)
        before = _raw(db, "odd")

        with pytest.raises(ValueError):
            logged_in_client.post("/runs/odd/samples/odd-s1/settings",
                                  data={"override_cycles": "Y151;I8;I8;Y151",
                                        "target_setting": ""},
                                  headers={"Origin": "http://testserver"})

        assert _raw(db, "odd") == before

    def test_the_api_list_leaves_it_out_without_failing(self, client, fresh_app):
        """Unlike an unknown instrument, an unknown status never reaches a
        reader from the list: ``list_summaries`` queries ``{"status": "ready"}``
        and a damaged value matches neither it nor "archived", so the run is
        outside the set the API is asked for. It was equally absent before
        this change (read as a Draft), the dashboard names it, and every
        per-run endpoint refuses it below."""
        _app, ctx, db = fresh_app
        _run(ctx, "good", status=RunStatus.READY)
        _run(ctx, "odd", status=RunStatus.READY)
        _name_status(db, "odd", UNKNOWN)

        answer = client.get("/api/runs", headers=_bearer(ctx))

        assert answer.status_code == 200
        assert [item["id"] for item in answer.json()["items"]] == ["good"]

    @pytest.mark.parametrize("path", [
        "samplesheet-v2", "samplesheet-v1", "json", "validation-report", "validation-pdf",
    ])
    def test_serving_one_of_its_files_fails(self, client, fresh_app, path):
        """Every per-run endpoint loads the run by id, so the refusal reaches
        the consumer instead of a file from a run read as a Draft."""
        _app, ctx, db = fresh_app
        _run(ctx, "odd", status=RunStatus.READY)
        _name_status(db, "odd", UNKNOWN)

        with pytest.raises(ValueError, match="status this release does not know"):
            client.get(f"/api/runs/odd/{path}", headers=_bearer(ctx))
