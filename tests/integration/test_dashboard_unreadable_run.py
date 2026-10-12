"""One run document this release cannot read must not take the dashboard
down with it.

The dashboard built every run with no per-document guard, so a single
document whose ``from_dict`` raises — a whole-number field stored as 1.0, a
base no index allows, an analysis type this release does not know, all of
which only a direct database write or an older release produces — made the
page, the tab fragment and the search raise, and the lab could reach no run
at all from the dashboard.

The dashboard now lists every run that loads and names, in a plain line,
each run id it could not read: never silently hidden (CLAUDE.md: never
silently discard data), logged at WARNING for the administrator who has to
repair the document, and nothing in the database is touched.

The archive and delete handlers render the same listing after they have
written, and that is where it matters most: on the old code, archiving a
good Ready run while one unreadable document was stored STORED the new
status and wrote the run.status.changed audit row, then raised while
building the fragment -- so the user saw a 500 and did not know the archive
had happened. The same for a delete, which cannot be undone. Those two are
pinned below.

The JSON API is deliberately NOT changed here: ``/api/runs`` still raises on
such a document rather than handing an external clinical consumer a quietly
shortened list. Changing what the API returns is a separate decision; the
test at the bottom pins today's behaviour so this restructuring cannot move
it by accident.
"""

import copy
import logging

import bson
import pytest

from seqsetup.models.api_token import ApiToken
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import (
    InstrumentPlatform,
    RunCycles,
    RunStatus,
    SequencingRun,
)

GOOD_ID = "good-run"
BAD_ID = "unreadable-run"


def _run(ctx, run_id, name, status=RunStatus.DRAFT, sample_id="PAT-1", with_sample=True):
    run = SequencingRun(
        id=run_id,
        run_name=name,
        instrument_platform=InstrumentPlatform.NOVASEQ_X,
        flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 10, 10),
        status=status,
    )
    if with_sample:
        run.add_sample(Sample(id=f"{run_id}-s1", sample_id=sample_id, lanes=[1]))
    ctx.run_repo.save(run)
    return run


def _make_unreadable(db, run_id):
    """Store a barcode-mismatch count as 1.0 on one sample, the way a direct
    database write or an older release leaves it. Sample.from_dict refuses a
    value that is not a whole number, so the whole run document stops
    loading."""
    doc = db["runs"].find_one({"_id": run_id})
    doc["samples"][0]["barcode_mismatches_index1"] = 1.0
    db["runs"].replace_one({"_id": run_id}, doc)
    with pytest.raises(ValueError):
        SequencingRun.from_dict(db["runs"].find_one({"_id": run_id}))


def _bad_and_good(ctx, db, bad_status=RunStatus.DRAFT):
    _run(ctx, GOOD_ID, "Readable run")
    _run(ctx, BAD_ID, "Broken run", status=bad_status, sample_id="PAT-2")
    _make_unreadable(db, BAD_ID)


def _raw(db):
    return [bson.encode(doc) for doc in db["runs"].find().sort("_id")]


def _raw_one(db, run_id):
    doc = db["runs"].find_one({"_id": run_id})
    return bson.encode(doc) if doc is not None else None


def _seed_api_token(ctx) -> str:
    plaintext = ApiToken.generate_token()
    token_hash, token_prefix = ApiToken.hash_token(plaintext)
    ctx.api_token_repo.save(ApiToken(
        name="unreadable-run-token", token_hash=token_hash,
        token_prefix=token_prefix, created_by="admin-test",
    ))
    return plaintext


class TestDashboardSurvivesAnUnreadableRun:
    """The page, the tab fragment and the search all answer 200, list the
    run that loads, and name the one that does not."""

    def test_the_page_lists_the_good_run_and_names_the_bad_one(
            self, logged_in_client, fresh_app):
        _app, ctx, db = fresh_app
        _bad_and_good(ctx, db)

        response = logged_in_client.get("/")

        assert response.status_code == 200
        assert f'id="run-item-{GOOD_ID}"' in response.text
        assert BAD_ID in response.text

    def test_the_tab_fragment_lists_the_good_run_and_names_the_bad_one(
            self, logged_in_client, fresh_app):
        _app, ctx, db = fresh_app
        _bad_and_good(ctx, db)

        response = logged_in_client.get("/dashboard/tab/draft")

        assert response.status_code == 200
        assert f'id="run-item-{GOOD_ID}"' in response.text
        assert BAD_ID in response.text

    def test_the_search_lists_the_good_run_and_names_the_bad_one(
            self, logged_in_client, fresh_app):
        _app, ctx, db = fresh_app
        _bad_and_good(ctx, db)

        response = logged_in_client.get("/dashboard/search", params={"q": "Readable"})

        assert response.status_code == 200
        assert f'id="run-item-{GOOD_ID}"' in response.text
        assert BAD_ID in response.text

    def test_the_only_run_being_unreadable_still_answers_200(
            self, logged_in_client, fresh_app):
        _app, ctx, db = fresh_app
        _run(ctx, BAD_ID, "Broken run")
        _make_unreadable(db, BAD_ID)

        response = logged_in_client.get("/")

        assert response.status_code == 200
        assert BAD_ID in response.text


class TestUnreadableRunIsRecordedNotHidden:
    """It is named for the user, logged for the administrator, and nothing
    is written."""

    def test_a_warning_names_the_run_id(self, logged_in_client, fresh_app, caplog):
        _app, ctx, db = fresh_app
        _bad_and_good(ctx, db)
        caplog.set_level(logging.WARNING, logger="seqsetup.repositories.run_repo")

        logged_in_client.get("/")

        warnings = [r.getMessage() for r in caplog.records
                    if r.name == "seqsetup.repositories.run_repo"
                    and r.levelno == logging.WARNING]
        assert any(BAD_ID in message for message in warnings), warnings

    def test_the_stored_documents_are_byte_identical_afterwards(
            self, logged_in_client, fresh_app):
        _app, ctx, db = fresh_app
        _bad_and_good(ctx, db)
        before = copy.deepcopy(_raw(db))

        for path, params in (("/", None), ("/dashboard/tab/draft", None),
                             ("/dashboard/search", {"q": "run"})):
            assert logged_in_client.get(path, params=params).status_code == 200

        assert _raw(db) == before

    def test_a_dashboard_with_no_bad_document_says_nothing_about_one(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, GOOD_ID, "Readable run")

        response = logged_in_client.get("/")

        assert response.status_code == 200
        assert f'id="run-item-{GOOD_ID}"' in response.text
        assert "could not be read" not in response.text


class TestThePageNeverSaysBothThings:
    """"No Runs Yet" and "1 run could not be read" cannot both be true.

    With exactly one run stored and that run unreadable, the page showed
    the notice AND a heading saying the lab had no runs at all, with a
    "+ New Run" button under it. A clinical page must not tell the
    operator two contradictory things about what is in the database. The
    empty-state block is now shown only when there is genuinely nothing:
    no readable runs and no unreadable ones.
    """

    def test_one_unreadable_run_is_not_called_no_runs_yet(
            self, logged_in_client, fresh_app):
        _app, ctx, db = fresh_app
        _run(ctx, BAD_ID, "Broken run")
        _make_unreadable(db, BAD_ID)

        response = logged_in_client.get("/")

        assert response.status_code == 200
        assert BAD_ID in response.text
        assert "No Runs Yet" not in response.text

    def test_an_empty_database_still_says_no_runs_yet(self, logged_in_client, fresh_app):
        """The genuinely-empty page is unchanged."""
        _app, _ctx, _db = fresh_app

        response = logged_in_client.get("/")

        assert response.status_code == 200
        assert "No Runs Yet" in response.text
        assert "could not be read" not in response.text


class TestArchiveAndDeleteSurviveAnUnreadableRun:
    """The two handlers that WRITE and then render the listing.

    They are the highest-consequence entry points: both have already
    changed the database by the time the fragment is built. On the old
    code, with one unreadable document stored, the archive stored
    ``status = archived`` and wrote the ``run.status.changed`` audit row and
    then raised, so the lab got a 500 and could not tell whether the run
    had been archived; the delete is worse still, because it cannot be
    undone. Both now answer 200 and name the unreadable run.
    """

    def test_archive_answers_200_and_names_the_unreadable_run(
            self, logged_in_client, fresh_app):
        _app, ctx, db = fresh_app
        _run(ctx, GOOD_ID, "Readable run", status=RunStatus.READY)
        _run(ctx, BAD_ID, "Broken run", sample_id="PAT-2")
        _make_unreadable(db, BAD_ID)
        bad_before = _raw_one(db, BAD_ID)

        response = logged_in_client.post(
            f"/runs/{GOOD_ID}/archive", headers={"Origin": "http://testserver"})

        assert response.status_code == 200
        assert BAD_ID in response.text
        assert ctx.run_repo.get_by_id(GOOD_ID).status == RunStatus.ARCHIVED
        assert _raw_one(db, BAD_ID) == bad_before

    def test_delete_answers_200_and_names_the_unreadable_run(
            self, logged_in_client, fresh_app):
        """An empty draft that was never Ready: deletable by any user."""
        _app, ctx, db = fresh_app
        _run(ctx, GOOD_ID, "Readable run", with_sample=False)
        _run(ctx, BAD_ID, "Broken run", sample_id="PAT-2")
        _make_unreadable(db, BAD_ID)
        bad_before = _raw_one(db, BAD_ID)

        response = logged_in_client.request(
            "DELETE", f"/runs/{GOOD_ID}", headers={"Origin": "http://testserver"})

        assert response.status_code == 200
        assert BAD_ID in response.text
        assert ctx.run_repo.get_by_id(GOOD_ID) is None
        assert _raw_one(db, BAD_ID) == bad_before


class TestTheJsonApiIsUnchanged:
    """``/api/runs`` is left exactly as it was: a document it cannot read
    raises, and no caller is handed a quietly shortened list. Changing that
    would change what an external clinical consumer receives — a separate
    decision, pinned here."""

    def test_api_runs_still_raises_on_an_unreadable_ready_run(self, client, fresh_app):
        _app, ctx, db = fresh_app
        plaintext = _seed_api_token(ctx)
        _bad_and_good(ctx, db, bad_status=RunStatus.READY)

        with pytest.raises(ValueError):
            client.get("/api/runs", headers={"Authorization": f"Bearer {plaintext}"})

    def test_api_runs_still_lists_a_readable_ready_run(self, client, fresh_app):
        _app, ctx, _db = fresh_app
        plaintext = _seed_api_token(ctx)
        _run(ctx, GOOD_ID, "Readable run", status=RunStatus.READY)

        response = client.get("/api/runs", headers={"Authorization": f"Bearer {plaintext}"})

        assert response.status_code == 200
        assert [item["id"] for item in response.json()["items"]] == [GOOD_ID]
