"""Every listing shows what it showed before, and reads only what it shows.

docs/design/2026-10-17-listing-summaries-design.md. The dashboard, its tabs,
its search, /served-runs and GET /api/runs are built from a projection that
leaves the samples out. This file pins that the rows are the same, that the
API's limit happens in the database, that no listing can erase a run, and the
one behaviour change the summary brings.
"""

import re

import bson
import pytest

from seqsetup.api.app import _run_summary
from seqsetup.models.api_token import ApiToken
from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.run_listing import RunListing
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import (
    InstrumentPlatform, RunCycles, RunStatus, SequencingRun,
)

ORIGIN = {"Origin": "http://testserver"}


def _run(ctx, k, status=RunStatus.READY, samples=2, name=None):
    run = SequencingRun(
        id=f"run-{k:03d}", run_name=name or f"Run {k:03d}",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 10, 10), created_by="maker", updated_by="changer")
    for i in range(samples):
        run.add_sample(Sample(
            sample_id=f"PAT{k:03d}-{i:03d}", lanes=[1],
            index_pair=IndexPair(
                id=f"p{i}", name=f"p{i}",
                index1=Index(name=f"i7-{i}", sequence="ACGTACGTAC", index_type=IndexType.I7),
                index2=Index(name=f"i5-{i}", sequence="TGCATGCATG", index_type=IndexType.I5))))
    run.status = status
    ctx.run_repo.save(run)
    return run


@pytest.fixture
def seeded(fresh_app):
    """Runs of every status the dashboard can show, plus the awkward ones."""
    _app, ctx, db = fresh_app
    _run(ctx, 1, RunStatus.DRAFT, samples=0)
    _run(ctx, 2, RunStatus.DRAFT, samples=3)
    _run(ctx, 3, RunStatus.READY, samples=2)
    _run(ctx, 4, RunStatus.READY, samples=5)
    _run(ctx, 5, RunStatus.ARCHIVED, samples=1)
    # A run stored by an older release: status "complete", no was_ready, no
    # sheet_targets, no updated_by.
    legacy = _run(ctx, 6, RunStatus.ARCHIVED, samples=2).to_dict()
    legacy["status"] = "complete"
    for gone in ("was_ready", "sheet_targets", "updated_by", "exports"):
        legacy.pop(gone, None)
    db.runs.replace_one({"_id": legacy["_id"]}, legacy)
    # A run with no samples key at all.
    old_shape = _run(ctx, 7, RunStatus.READY, samples=0).to_dict()
    old_shape.pop("samples")
    db.runs.replace_one({"_id": old_shape["_id"]}, old_shape)
    return fresh_app


def _bearer(ctx):
    plaintext = ApiToken.generate_token()
    token_hash, prefix = ApiToken.hash_token(plaintext)
    ctx.api_token_repo.save(ApiToken(name="listing", token_hash=token_hash, token_prefix=prefix))
    return {"Authorization": f"Bearer {plaintext}"}


def _rows(html):
    """(run id, every cell) per row of a dashboard or served-runs table."""
    rows = {}
    for match in re.finditer(r'id="(?:run-item|served-run)-([^"]+)"(.*?)(?=id="(?:run-item|served-run)-|\Z)',
                             html, re.S):
        text = re.sub(r"<[^>]+>", "|", match.group(2))
        rows[match.group(1)] = [cell.strip() for cell in text.split("|") if cell.strip()]
    return rows


def _order(html):
    return [match.group(1) for match in
            re.finditer(r'id="(?:run-item|served-run)-([^"]+)"', html)]


class TestTheListingsShowTheSameThing:
    """Rows and order, against the whole-run code the listings replaced."""

    def test_the_dashboard_rows_are_the_same(self, seeded, logged_in_client):
        _app, ctx, _db = seeded
        before = {run.id: run for run in ctx.run_repo.list_all_readable()[0]}
        html = logged_in_client.get("/").text
        rows = _rows(html)
        assert set(rows) == {run.id for run in before.values()
                             if run.status == RunStatus.DRAFT}
        for run_id, cells in rows.items():
            run = before[run_id]
            assert run.run_name in cells
            assert run.instrument_platform.value in cells
            assert str(len(run.samples)) in cells
            assert (run.created_by or "—") in cells
            assert (run.updated_by or "—") in cells

    @pytest.mark.parametrize("tab", ["draft", "ready", "archived"])
    def test_each_tab_lists_the_same_runs_in_the_same_order(self, seeded, logged_in_client, tab):
        _app, ctx, _db = seeded
        runs, _ = ctx.run_repo.list_all_readable()
        expected = [run.id for run in
                    sorted((r for r in runs if r.status.value == tab),
                           key=lambda r: r.updated_at, reverse=True)]
        html = logged_in_client.get(f"/dashboard/tab/{tab}").text
        assert _order(html) == expected

    def test_the_tab_counts_are_the_same(self, seeded, logged_in_client):
        _app, ctx, _db = seeded
        runs, _ = ctx.run_repo.list_all_readable()
        html = logged_in_client.get("/").text
        for status in ("draft", "ready", "archived"):
            count = sum(1 for run in runs if run.status.value == status)
            assert re.search(rf"{status.capitalize()}\s*<span[^>]*>\s*{count}\s*</span>", html), status

    def test_the_search_finds_the_same_runs_by_name_and_by_sample(self, seeded, logged_in_client):
        _app, ctx, _db = seeded
        runs, _ = ctx.run_repo.list_all_readable()
        for query in ("Run 00", "PAT004", "PAT004-003", "nothing-matches"):
            expected = sorted(
                (run.id for run in runs
                 if query.lower() in (run.run_name or "").lower()
                 or any(query.lower() in (s.sample_id or "").lower() for s in run.samples)),
                key=lambda run_id: next(r.updated_at for r in runs if r.id == run_id),
                reverse=True)
            html = logged_in_client.get(f"/dashboard/search?q={query}").text
            assert _order(html) == expected, query

    def test_the_search_still_names_the_samples_that_matched(self, seeded, logged_in_client):
        html = logged_in_client.get("/dashboard/search?q=PAT004-003").text
        assert "PAT004-003" in html

    @pytest.mark.parametrize("query", [".*", ".", "PAT00[0-9]", "Run+", "(", "a|b", "^Run"])
    def test_a_query_is_a_plain_substring_not_a_regular_expression(
            self, seeded, logged_in_client, query):
        """The search ran in Python over `q in name`; it runs in the database
        now, and the query must still be taken literally — and never make the
        page fail, whatever punctuation someone types."""
        _app, ctx, _db = seeded
        runs, _ = ctx.run_repo.list_all_readable()
        expected = {run.id for run in runs
                    if query.lower() in (run.run_name or "").lower()
                    or any(query.lower() in (s.sample_id or "").lower()
                           for s in run.samples)}
        response = logged_in_client.get("/dashboard/search", params={"q": query})
        assert response.status_code == 200, query
        assert set(_order(response.text)) == expected, query

    @pytest.mark.parametrize("status", ["ready", "archived"])
    def test_served_runs_lists_the_same_runs_in_the_same_order(self, seeded, logged_in_client, status):
        _app, ctx, _db = seeded
        runs = ctx.run_repo.list_by_status(status)
        runs.sort(key=lambda r: r.updated_at or r.created_at, reverse=True)
        html = logged_in_client.get(f"/served-runs?status={status}").text
        assert _order(html) == [run.id for run in runs]
        rows = _rows(html)
        for run in runs:
            assert str(len(run.samples)) in rows[run.id]
            assert run.instrument_platform.value in rows[run.id]

    @pytest.mark.parametrize("status", ["ready", "archived"])
    def test_the_api_answers_exactly_what_it_answered_before(self, seeded, logged_in_client, status):
        _app, ctx, _db = seeded
        runs = ctx.run_repo.list_by_status(status)
        runs.sort(key=lambda r: r.updated_at or r.created_at, reverse=True)
        expected = {
            "items": [_run_summary(run).model_dump(mode="json") for run in runs],
            "total": len(runs), "limit": 50, "offset": 0,
        }
        got = logged_in_client.get(f"/api/runs?status={status}&limit=50",
                                   headers=_bearer(ctx)).json()
        assert got == expected
        # _run_summary builds both sides above, so the counts and names are
        # also asserted against the runs themselves.
        assert [item["id"] for item in got["items"]] == [run.id for run in runs]
        assert [item["run_name"] for item in got["items"]] == [run.run_name for run in runs]
        assert ([item["sample_count"] for item in got["items"]]
                == [len(run.samples) for run in runs])
        assert any(item["sample_count"] > 0 for item in got["items"]), (
            "the fixture must have a run with samples, or the count proves nothing")

    def test_the_api_pages_as_it_did(self, seeded, logged_in_client):
        _app, ctx, _db = seeded
        runs = ctx.run_repo.list_by_status("ready")
        runs.sort(key=lambda r: r.updated_at or r.created_at, reverse=True)
        headers = _bearer(ctx)
        got = logged_in_client.get("/api/runs?limit=1&offset=1", headers=headers).json()
        assert got["items"] == [_run_summary(runs[1]).model_dump(mode="json")]
        assert got["total"] == len(runs)


class TestTheLimitIsAppliedInTheDatabase:

    def test_one_summary_is_built_for_limit_one(self, fresh_app, logged_in_client, monkeypatch):
        _app, ctx, _db = fresh_app
        for k in range(50):
            _run(ctx, k, RunStatus.READY, samples=1)
        built = []
        original = RunListing.from_doc
        monkeypatch.setattr(RunListing, "from_doc",
                            classmethod(lambda cls, doc: built.append(doc) or original(doc)))
        response = logged_in_client.get("/api/runs?limit=1", headers=_bearer(ctx))
        assert response.status_code == 200
        assert len(response.json()["items"]) == 1
        assert response.json()["total"] == 50
        assert len(built) == 1, f"{len(built)} summaries built for a limit of 1"


class TestNoListingCanErase:

    def _stored(self, db):
        return {doc["_id"]: bson.encode(doc) for doc in db.runs.find()}

    def test_every_listing_leaves_the_documents_byte_for_byte(self, seeded, logged_in_client):
        _app, ctx, db = seeded
        before = self._stored(db)
        headers = _bearer(ctx)
        for url in ("/", "/dashboard/tab/ready", "/dashboard/tab/archived",
                    "/dashboard/search?q=Run", "/served-runs",
                    "/served-runs?status=archived"):
            assert logged_in_client.get(url).status_code == 200, url
        assert logged_in_client.get("/api/runs", headers=headers).status_code == 200
        assert self._stored(db) == before

    def test_a_listing_is_not_a_run_and_cannot_be_saved(self, seeded):
        _app, ctx, _db = seeded
        listing = ctx.run_repo.list_summaries("ready")[0]
        assert not isinstance(listing, SequencingRun)
        with pytest.raises(TypeError):
            ctx.run_repo.save(listing)


class TestWhatTheSummaryCanAndCannotSee:
    """The one behaviour change, and the guarantees that stay."""

    def _break_samples(self, db, run_id):
        """A sample no release can read; the summary never looks at it."""
        db.runs.update_one({"_id": run_id},
                           {"$set": {"samples": [{"sample_id": "S1", "lanes": "not-a-list",
                                                  "index1_sequence": "ZZZZ"}]}})

    def _break_summary_field(self, db, run_id):
        db.runs.update_one({"_id": run_id}, {"$set": {"created_at": "not-a-date"}})

    def test_a_run_whose_samples_do_not_read_is_listed_now(self, seeded, logged_in_client):
        _app, _ctx, db = seeded
        self._break_samples(db, "run-003")
        html = logged_in_client.get("/dashboard/tab/ready").text
        assert "run-003" in _order(html)

    def test_and_opening_it_still_fails(self, seeded, logged_in_client):
        """As it does today: the page builds the whole run, and cannot."""
        _app, _ctx, db = seeded
        self._break_samples(db, "run-003")
        with pytest.raises(Exception):
            logged_in_client.get("/runs/run-003")

    def test_and_the_api_still_lists_it(self, seeded, logged_in_client):
        _app, ctx, db = seeded
        self._break_samples(db, "run-003")
        got = logged_in_client.get("/api/runs", headers=_bearer(ctx)).json()
        assert "run-003" in [item["id"] for item in got["items"]]

    def test_the_search_still_answers_and_names_the_run_it_cannot_read(
            self, seeded, logged_in_client):
        """The results leave it out, as they did when the search ran over
        the readable runs — and the line above them names it."""
        _app, _ctx, db = seeded
        self._break_summary_field(db, "run-003")
        response = logged_in_client.get("/dashboard/search?q=Run")
        assert response.status_code == 200
        assert "run-003" not in _order(response.text)
        assert "run-003" in response.text

    def test_a_run_whose_summary_field_does_not_read_is_named_on_the_dashboard(
            self, seeded, logged_in_client):
        _app, _ctx, db = seeded
        self._break_summary_field(db, "run-003")
        html = logged_in_client.get("/").text
        assert "run-003" in html, "an unreadable run must still be named, never dropped"

    def test_a_run_whose_summary_field_does_not_read_fails_the_api_list_loudly(
            self, seeded, logged_in_client):
        _app, ctx, db = seeded
        headers = _bearer(ctx)
        before = logged_in_client.get("/api/runs", headers=headers).json()
        assert [item["id"] for item in before["items"]] == ["run-007", "run-004", "run-003"]
        self._break_summary_field(db, "run-003")
        with pytest.raises(Exception):
            logged_in_client.get("/api/runs", headers=headers)

    def test_and_the_list_never_comes_back_shorter_instead(self, seeded, logged_in_client):
        """The failure above is the point: two of three runs is not an answer."""
        _app, ctx, db = seeded
        self._break_summary_field(db, "run-003")
        with pytest.raises(Exception):
            ctx.run_repo.list_summaries("ready")


class TestNoRouteLoadsWholeRuns:
    """The whole-run listings stay for whoever needs whole runs — but no
    page or endpoint that only lists runs may reach for one."""

    @pytest.fixture
    def no_whole_runs(self, monkeypatch):
        def refuse(*_args, **_kwargs):
            raise AssertionError("a listing loaded whole runs")
        monkeypatch.setattr("seqsetup.repositories.run_repo.RunRepository.list_by_status", refuse)
        monkeypatch.setattr("seqsetup.repositories.run_repo.RunRepository.list_all_readable", refuse)
        monkeypatch.setattr("seqsetup.repositories.run_repo.RunRepository.list_all", refuse)

    @pytest.mark.parametrize("url", [
        "/", "/dashboard/tab/draft", "/dashboard/tab/ready", "/dashboard/tab/archived",
        "/dashboard/search?q=Run", "/dashboard/search?q=PAT004",
        "/served-runs", "/served-runs?status=archived",
    ])
    def test_the_page_is_built_from_listing_rows(self, seeded, logged_in_client,
                                                 no_whole_runs, url):
        assert logged_in_client.get(url).status_code == 200, url

    def test_the_api_list_is_built_from_listing_rows(self, seeded, logged_in_client,
                                                     no_whole_runs):
        _app, ctx, _db = seeded
        response = logged_in_client.get("/api/runs", headers=_bearer(ctx))
        assert response.status_code == 200
        assert response.json()["total"] == 3
