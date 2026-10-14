"""A worklist import adds only what its preview showed (outside review of
7f858e0, finding 2; the user's choice "Preview first", 2026-10-14).

The import asked the LIMS again and added whatever came back, from a button
next to the worksheet list, so a worksheet changed in the LIMS since the
preview, or another one picked after it, reached the run unseen. Now the
preview carries the import's button and a signature of its plan; the import
builds the plan again and saves only when the signature matches.
"""

import re

from seqsetup.models.sample import Sample
from seqsetup.models.sample_api_config import SampleApiConfig
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, SequencingRun
from seqsetup.services import sample_api as sample_api_module
from .conftest import hold_edit_lock, import_from_preview

ORIGIN = {"Origin": "http://testserver"}
RUN = "bind-run"
BANNER = {"HX-Retarget": "#error-banner", "HX-Reswap": "innerHTML", "HX-Reselect": "unset"}
CHANGED = ("The worksheet or the run changed since the preview. Nothing was added. "
           "Preview again.")
NO_PREVIEW = "Preview the worksheet first, then import it from the preview."


def _run(ctx, sample_ids=()):
    run = SequencingRun(
        id=RUN, run_name="Bind", instrument_platform=InstrumentPlatform.NOVASEQ_X,
        flowcell_type="10B", run_cycles=RunCycles(151, 151, 10, 10),
    )
    for k, sample_id in enumerate(sample_ids, start=1):
        run.add_sample(Sample(id=f"s{k}", sample_id=sample_id, lanes=[1]))
    ctx.run_repo.save(run)
    hold_edit_lock(ctx, run.id)


def _lims(ctx, monkeypatch):
    """The LIMS on, listing W1 and W2, and answering the returned rows for
    any worksheet; a test changes them to change the LIMS. No network."""
    ctx.sample_api_config_repo.save(SampleApiConfig(
        base_url="https://lims.example.org/api", enabled=True))
    rows = [{"sample_id": "P1", "test_id": "WGS", "index_i7": "ACGTACGT"},
            {"sample_id": "P2", "test_id": "WES"}]

    def answer(url, api_key=""):
        if "/worksheets/" in url:
            return [dict(row) for row in rows]
        return [{"id": "W1"}, {"id": "W2"}]

    monkeypatch.setattr(sample_api_module, "_api_get", answer)
    return rows


def _preview(client, worklist_id="W1"):
    return client.get(f"/runs/{RUN}/samples/preview-worklist",
                      params={"worklist_id": worklist_id, "lanes": ["1"]})


def _plan(html):
    found = re.search(r'<input type="hidden" name="plan" value="([^"]*)">', html)
    return found.group(1) if found else None


def _post(client, **form):
    form.setdefault("lanes", "1")  # as the preview's Import button sends it
    return client.post(f"/runs/{RUN}/samples/fetch-worklist", data=form, headers=ORIGIN)


def _ids(ctx):
    return [s.sample_id for s in ctx.run_repo.get_by_id(RUN).samples]


class TestThePreviewCarriesTheImport:

    def test_its_import_button_sends_the_worksheet_and_the_plan(
            self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _run(ctx)
        _lims(ctx, monkeypatch)

        html = _preview(logged_in_client).text

        [form] = re.findall(r"<form[^>]*fetch-worklist[^>]*>", html)
        assert f'hx-post="/runs/{RUN}/samples/fetch-worklist"' in form
        assert 'hx-target="#sample-section"' in form
        assert 'hx-swap="outerHTML"' in form
        assert 'hx-disabled-elt="find button"' in form
        assert '<input type="hidden" name="worklist_id" value="W1">' in html
        assert re.fullmatch(r"[0-9a-f]{64}", _plan(html))
        assert ">Import 2 samples</button>" in html

    def test_one_sample(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _run(ctx)
        _lims(ctx, monkeypatch)[1:] = []

        assert ">Import 1 sample</button>" in _preview(logged_in_client).text

    def test_the_worksheet_list_has_no_import_button(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _run(ctx)
        _lims(ctx, monkeypatch)

        html = logged_in_client.get(f"/runs/{RUN}/samples/worklists").text

        assert 'id="worklist-select"' in html
        assert "fetch-worklist" not in html

    def test_a_refused_worksheet_offers_no_import(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _run(ctx)
        _lims(ctx, monkeypatch)[1]["sample_id"] = "P1"

        html = _preview(logged_in_client).text

        assert "Importing this worksheet would be refused" in html
        assert "fetch-worklist" not in html and _plan(html) is None

    def test_nothing_to_add_offers_no_import(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _run(ctx, ["P1", "P2"])
        _lims(ctx, monkeypatch)

        html = _preview(logged_in_client).text

        assert "0 samples to add" in html
        assert "2 already in this run, will be skipped: P1, P2" in html
        assert "fetch-worklist" not in html and _plan(html) is None


class TestTheImportAddsWhatThePreviewShowed:

    def test_the_previewed_samples_are_added(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _run(ctx)
        _lims(ctx, monkeypatch)

        resp = import_from_preview(logged_in_client, RUN, "W1")

        assert resp.status_code == 200, resp.text[:300]
        assert "Added 2 samples from worklist to lane 1." in resp.text
        assert _ids(ctx) == ["P1", "P2"]


class TestAnImportThatIsNotWhatThePreviewShowedIsRefused:
    """Refused to the banner, and the run stays as it was."""

    def _refused(self, client, ctx, status, text, **form):
        before = ctx.run_repo.get_by_id(RUN).to_dict()
        resp = _post(client, **form)
        assert resp.status_code == status, resp.text[:300]
        assert {name: resp.headers.get(name) for name in BANNER} == BANNER
        assert f'<p class="error-message">{text}</p>' in resp.text
        assert ctx.run_repo.get_by_id(RUN).to_dict() == before

    def test_with_no_preview(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _run(ctx)
        _lims(ctx, monkeypatch)
        self._refused(logged_in_client, ctx, 400, NO_PREVIEW, worklist_id="W1")

    def test_a_sample_changed_in_the_lims(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _run(ctx)
        rows = _lims(ctx, monkeypatch)
        plan = _plan(_preview(logged_in_client).text)
        rows[1]["test_id"] = "WGS"
        self._refused(logged_in_client, ctx, 409, CHANGED, worklist_id="W1", plan=plan)

    def test_an_index_changed_in_the_lims(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _run(ctx)
        rows = _lims(ctx, monkeypatch)
        plan = _plan(_preview(logged_in_client).text)
        rows[0]["index_i7"] = "TTGGCCAA"
        self._refused(logged_in_client, ctx, 409, CHANGED, worklist_id="W1", plan=plan)

    def test_a_sample_added_in_the_lims(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _run(ctx)
        rows = _lims(ctx, monkeypatch)
        plan = _plan(_preview(logged_in_client).text)
        rows.append({"sample_id": "P3", "test_id": "WGS"})
        self._refused(logged_in_client, ctx, 409, CHANGED, worklist_id="W1", plan=plan)

    def test_an_index_name_changed_in_the_lims(self, logged_in_client, fresh_app, monkeypatch):
        """The preview's table shows no index names; the import still holds
        to them (review of 314d640, P3-3)."""
        _app, ctx, _db = fresh_app
        _run(ctx)
        rows = _lims(ctx, monkeypatch)
        plan = _plan(_preview(logged_in_client).text)
        rows[0]["i7_name"] = "D701"
        self._refused(logged_in_client, ctx, 409, CHANGED, worklist_id="W1", plan=plan)

    def test_the_runs_cycles_changed_since(self, logged_in_client, fresh_app, monkeypatch):
        """Each sample's Override Cycles would differ from the preview's plan."""
        _app, ctx, _db = fresh_app
        _run(ctx)
        _lims(ctx, monkeypatch)
        plan = _plan(_preview(logged_in_client).text)
        run = ctx.run_repo.get_by_id(RUN)
        run.run_cycles = RunCycles(101, 101, 10, 10)
        ctx.run_repo.save(run)
        self._refused(logged_in_client, ctx, 409, CHANGED, worklist_id="W1", plan=plan)

    def test_another_worksheet_with_the_same_rows(self, logged_in_client, fresh_app, monkeypatch):
        """Rows that name their own worksheet plan the same samples for W1
        and W2; the import is still held to the worksheet previewed."""
        _app, ctx, _db = fresh_app
        _run(ctx)
        for row in _lims(ctx, monkeypatch):
            row["worksheet_id"] = "W1"
        plan = _plan(_preview(logged_in_client, "W1").text)
        self._refused(logged_in_client, ctx, 409, CHANGED, worklist_id="W2", plan=plan)

    def test_a_sample_added_in_the_lims_that_the_run_already_has(
            self, logged_in_client, fresh_app, monkeypatch):
        """The import would add the same two samples, but skip one the
        preview did not name."""
        _app, ctx, _db = fresh_app
        _run(ctx, ["OLD1"])
        rows = _lims(ctx, monkeypatch)
        plan = _plan(_preview(logged_in_client).text)
        rows.append({"sample_id": "OLD1"})
        self._refused(logged_in_client, ctx, 409, CHANGED, worklist_id="W1", plan=plan)

    def test_another_worksheet_than_the_one_previewed(self, logged_in_client, fresh_app, monkeypatch):
        """W2 answers the same rows: the worksheet each sample is given differs."""
        _app, ctx, _db = fresh_app
        _run(ctx)
        _lims(ctx, monkeypatch)
        plan = _plan(_preview(logged_in_client, "W1").text)
        self._refused(logged_in_client, ctx, 409, CHANGED, worklist_id="W2", plan=plan)

    def test_a_sample_of_the_worksheet_added_to_the_run_since(
            self, logged_in_client, fresh_app, monkeypatch):
        """The import would skip it and add one sample, not the two shown."""
        _app, ctx, _db = fresh_app
        _run(ctx)
        _lims(ctx, monkeypatch)
        plan = _plan(_preview(logged_in_client).text)
        run = ctx.run_repo.get_by_id(RUN)
        run.add_sample(Sample(id="s9", sample_id="P1", lanes=[1]))
        ctx.run_repo.save(run)
        self._refused(logged_in_client, ctx, 409, CHANGED, worklist_id="W1", plan=plan)

    def test_a_plan_no_preview_made(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _run(ctx)
        _lims(ctx, monkeypatch)
        self._refused(logged_in_client, ctx, 409, CHANGED, worklist_id="W1", plan="0" * 64)


class TestAPlanWithNothingToAdd:
    """The preview offers no import then. A request that sends that plan
    anyway adds nothing and says so, as before (review of 314d640, P3-3)."""

    def test_it_says_nothing_was_added(self, logged_in_client, fresh_app, monkeypatch):
        from seqsetup.routes.samples import _worklist_plan_signature
        _app, ctx, _db = fresh_app
        _run(ctx, ["P1", "P2"])
        _lims(ctx, monkeypatch)
        before = ctx.run_repo.get_by_id(RUN).to_dict()

        resp = _post(logged_in_client, worklist_id="W1",
                     plan=_worklist_plan_signature("W1", [], ["P1", "P2"]))

        assert resp.status_code == 200, resp.text[:300]
        assert '<p class="warning-message">No new samples added from worklist.</p>' in resp.text
        assert ctx.run_repo.get_by_id(RUN).to_dict() == before
