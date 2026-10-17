"""A stored run or template naming an instrument this release does not know,
or none, is refused when read, never guessed (design note
docs/design/2026-10-17-unknown-platform-design.md).

Every reader once fell back to NovaSeq X with only a log line: a run made
for another instrument (a database edit, or a later release renaming an
instrument) opened as a NovaSeq X run, could be marked Ready with NovaSeq
X's i5 direction and settings, and any save -- archiving included -- wrote
"NovaSeq X Series" over the stored value. A template started NovaSeq X runs.

The user chose (2026-10-17) to treat such a document as a damaged one: it
cannot be opened, edited, marked Ready or served until an administrator
repairs it, and every list names it rather than dropping it or failing for
everyone.
"""

import bson
import pytest

from seqsetup.models.api_token import ApiToken
from seqsetup.models.run_listing import RunListing
from seqsetup.models.run_template import RunTemplate
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import (InstrumentPlatform, RunCycles, RunStatus,
                                            SequencingRun)

from .conftest import hold_edit_lock

UNKNOWN = "NovaSeq Z Series"


def _run(ctx, run_id, status=RunStatus.DRAFT):
    run = SequencingRun(id=run_id, run_name=run_id, instrument_platform=InstrumentPlatform.NOVASEQ_X,
                        flowcell_type="10B", run_cycles=RunCycles(151, 151, 10, 10), status=status)
    run.add_sample(Sample(id=f"{run_id}-s1", sample_id="PAT-1", lanes=[1]))
    ctx.run_repo.save(run)
    hold_edit_lock(ctx, run_id)
    return run


def _name_platform(db, collection, doc_id, platform):
    if platform is None:
        db[collection].update_one({"_id": doc_id}, {"$unset": {"instrument_platform": ""}})
    else:
        db[collection].update_one({"_id": doc_id}, {"$set": {"instrument_platform": platform}})


def _raw(db, collection, doc_id):
    return bson.encode(db[collection].find_one({"_id": doc_id}))


def _bearer(ctx):
    plaintext = ApiToken.generate_token()
    token_hash, prefix = ApiToken.hash_token(plaintext)
    ctx.api_token_repo.save(ApiToken(name="platform", token_hash=token_hash, token_prefix=prefix))
    return {"Authorization": f"Bearer {plaintext}"}


def _template(ctx, name):
    template = RunTemplate(name=name, created_by="admin-test", updated_by="admin-test",
                           flowcell_type="10B")
    ctx.run_template_repo.save(template)
    return template.id


class TestEveryReaderRefusesIt:

    @pytest.mark.parametrize("platform", [UNKNOWN, None, ""])
    def test_a_run(self, fresh_app, platform):
        _app, ctx, db = fresh_app
        _run(ctx, "odd")
        _name_platform(db, "runs", "odd", platform)

        with pytest.raises(ValueError) as refused:
            SequencingRun.from_dict(db["runs"].find_one({"_id": "odd"}))

        assert "odd" in str(refused.value)
        assert "instrument this release does not know" in str(refused.value)
        assert repr(platform) in str(refused.value)

    @pytest.mark.parametrize("platform", [UNKNOWN, None])
    def test_a_listing_row(self, fresh_app, platform):
        _app, ctx, db = fresh_app
        _run(ctx, "odd")
        _name_platform(db, "runs", "odd", platform)

        with pytest.raises(ValueError, match="instrument this release does not know"):
            RunListing.from_doc(db["runs"].find_one({"_id": "odd"}))

    @pytest.mark.parametrize("platform", [UNKNOWN, None])
    def test_a_template(self, fresh_app, platform):
        _app, ctx, db = fresh_app
        tid = _template(ctx, "Odd")
        _name_platform(db, "run_templates", tid, platform)

        with pytest.raises(ValueError, match="instrument this release does not know"):
            RunTemplate.from_dict(db["run_templates"].find_one({"_id": tid}))

    def test_a_known_platform_still_reads(self, fresh_app):
        _app, ctx, db = fresh_app
        _run(ctx, "fine")
        _template(ctx, "Fine")

        assert ctx.run_repo.get_by_id("fine").instrument_platform == InstrumentPlatform.NOVASEQ_X
        (template,) = ctx.run_template_repo.list_all()
        assert template.instrument_platform == InstrumentPlatform.NOVASEQ_X


class TestTheRunIsNamedAndLeftAlone:

    def test_the_dashboard_names_it_and_lists_the_rest(self, logged_in_client, fresh_app):
        _app, ctx, db = fresh_app
        _run(ctx, "good")
        _run(ctx, "odd")
        _name_platform(db, "runs", "odd", UNKNOWN)
        before = _raw(db, "runs", "odd")

        page = logged_in_client.get("/")

        assert page.status_code == 200
        assert 'id="run-item-good"' in page.text
        assert 'id="run-item-odd"' not in page.text
        assert "could not be read" in page.text and "odd" in page.text
        assert _raw(db, "runs", "odd") == before

    def test_opening_it_fails_and_writes_nothing(self, logged_in_client, fresh_app):
        _app, ctx, db = fresh_app
        _run(ctx, "odd")
        _name_platform(db, "runs", "odd", UNKNOWN)
        before = _raw(db, "runs", "odd")

        with pytest.raises(ValueError):
            logged_in_client.get("/runs/odd")

        assert _raw(db, "runs", "odd") == before

    def test_mark_ready_fails_and_writes_nothing(self, logged_in_client, fresh_app):
        _app, ctx, db = fresh_app
        _run(ctx, "odd")
        _name_platform(db, "runs", "odd", UNKNOWN)
        before = _raw(db, "runs", "odd")

        with pytest.raises(ValueError):
            logged_in_client.post("/runs/odd/status/ready",
                                  headers={"Origin": "http://testserver"})

        assert _raw(db, "runs", "odd") == before

    def test_archiving_a_ready_one_fails_and_keeps_the_stored_name(
            self, logged_in_client, fresh_app):
        """Archiving saves the run: on the fallback it wrote NovaSeq X over
        the stored value."""
        _app, ctx, db = fresh_app
        _run(ctx, "odd", status=RunStatus.READY)
        _name_platform(db, "runs", "odd", UNKNOWN)

        with pytest.raises(ValueError):
            logged_in_client.post("/runs/odd/status/archived",
                                  headers={"Origin": "http://testserver"})

        stored = db["runs"].find_one({"_id": "odd"})
        assert (stored["instrument_platform"], stored["status"]) == (UNKNOWN, "ready")

    def test_the_api_list_fails_rather_than_answer_without_it(self, client, fresh_app):
        """The rule for any run the API cannot read (test_dashboard_unreadable_run):
        an external consumer is never handed a shortened list."""
        _app, ctx, db = fresh_app
        _run(ctx, "good", status=RunStatus.READY)
        _run(ctx, "odd", status=RunStatus.READY)
        _name_platform(db, "runs", "odd", UNKNOWN)

        with pytest.raises(ValueError):
            client.get("/api/runs", headers=_bearer(ctx))


class TestTheTemplateIsNamedAndLeftAlone:

    def test_the_templates_page_names_it_and_lists_the_rest(self, logged_in_client, fresh_app):
        _app, ctx, db = fresh_app
        good = _template(ctx, "Good template")
        odd = _template(ctx, "Odd template")
        _name_platform(db, "run_templates", odd, UNKNOWN)
        before = _raw(db, "run_templates", odd)

        page = logged_in_client.get("/templates")

        assert page.status_code == 200
        assert f'id="template-item-{good}"' in page.text
        assert f'id="template-item-{odd}"' not in page.text
        assert "could not be read" in page.text and odd in page.text
        assert _raw(db, "run_templates", odd) == before

    def test_the_new_run_page_offers_the_rest_and_names_it(self, logged_in_client, fresh_app):
        _app, ctx, db = fresh_app
        good = _template(ctx, "Good template")
        odd = _template(ctx, "Odd template")
        _name_platform(db, "run_templates", odd, UNKNOWN)
        blank = SequencingRun(id="blank", run_name="")
        ctx.run_repo.save(blank)
        hold_edit_lock(ctx, "blank")

        page = logged_in_client.get("/runs/new/step/1?run_id=blank&new=1")

        assert page.status_code == 200
        assert f'<option value="{good}">' in page.text
        assert f'<option value="{odd}">' not in page.text
        assert "could not be read" in page.text and odd in page.text

    def test_starting_a_run_from_it_fails_and_makes_nothing(self, logged_in_client, fresh_app):
        _app, ctx, db = fresh_app
        odd = _template(ctx, "Odd template")
        _name_platform(db, "run_templates", odd, UNKNOWN)
        runs_before = db["runs"].count_documents({})

        with pytest.raises(ValueError):
            logged_in_client.post(f"/runs/new/from-template/{odd}",
                                  headers={"Origin": "http://testserver"})

        assert db["runs"].count_documents({}) == runs_before
