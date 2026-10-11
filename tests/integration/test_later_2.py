"""Later list, slice 2: the LIMS import works from the run page, a worksheet
whose ID SeqSetup cannot read for sure is left out of the list, and the
preview shows what the import would add (spec 2026-10-10 later list slice 2)."""

import re

from markupsafe import escape

from seqsetup.models.sample import Sample
from seqsetup.models.sample_api_config import SampleApiConfig
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, SequencingRun
from seqsetup.services import sample_api as sample_api_module

ORIGIN = {"Origin": "http://testserver"}
RUN = "l2-run"


def _run(ctx, sample_ids=()):
    """Save a NovaSeq X draft with one sample per Sample ID given."""
    run = SequencingRun(
        id=RUN, run_name="L2", instrument_platform=InstrumentPlatform.NOVASEQ_X,
        flowcell_type="10B", run_cycles=RunCycles(151, 151, 10, 10),
    )
    for k, sample_id in enumerate(sample_ids, start=1):
        run.add_sample(Sample(id=f"s{k}", sample_id=sample_id, lanes=[1]))
    ctx.run_repo.save(run)


def _lims_on(ctx, mappings=None):
    ctx.sample_api_config_repo.save(SampleApiConfig(
        base_url="https://lims.example.org/api", enabled=True, field_mappings=mappings or {}))


def _worksheet_list(monkeypatch, items):
    """The LIMS's worksheet list, with no network; fetch_worklists runs."""
    monkeypatch.setattr(sample_api_module, "_api_get", lambda url, api_key="": items)


def _options(html):
    return re.findall(r'<option value="([^"]*)"', html)


# --- spec §3: worksheet IDs --------------------------------------------------

LEFT_OUT = ('A worksheet in the LIMS list has an ID that is a number with a decimal point (25.1), '
            'which JSON may have changed (1.10 is read as 1.1). Send it as text, for example '
            '"1.10". It is left out of the list.')
TWO = ("A worksheet in the LIMS list has the names 'Id' and 'ID', which SeqSetup reads as one "
       "name. Send only one of them. It is left out of the list.")


class TestTheWorksheetListShowsWhatIsLeftOut:
    """A worksheet whose ID is not text or a whole number, or comes under two
    spellings, is not in the dropdown, and a warning above it names it."""

    def test_the_others_are_listed_with_the_warnings(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _run(ctx)
        _lims_on(ctx)
        _worksheet_list(monkeypatch, [{"id": "W1"}, {"id": 25.1}, {"Id": "W_A", "ID": "W_B"}])
        resp = logged_in_client.get(f"/runs/{RUN}/samples/worklists")
        assert resp.status_code == 200
        assert _options(resp.text) == ["W1"]
        assert f'<p class="warning-message">{escape(LEFT_OUT)}</p>' in resp.text
        assert f'<p class="warning-message">{escape(TWO)}</p>' in resp.text
        assert resp.text.index(str(escape(LEFT_OUT))) < resp.text.index('id="worklist-select"')

    def test_nothing_left_to_list_shows_the_error_and_the_warnings(
            self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _run(ctx)
        _lims_on(ctx)
        _worksheet_list(monkeypatch, [{"id": 25.1}])
        resp = logged_in_client.get(f"/runs/{RUN}/samples/worklists")
        assert resp.status_code == 200
        assert _options(resp.text) == []
        assert ('<p class="error-message">Failed to load worklists: No valid worksheets found '
                'in API response</p>') in resp.text
        assert f'<p class="warning-message">{escape(LEFT_OUT)}</p>' in resp.text

    def test_a_list_with_nothing_left_out_shows_no_warning(
            self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _run(ctx)
        _lims_on(ctx)
        _worksheet_list(monkeypatch, [{"id": "W1"}, {"id": 7}])
        resp = logged_in_client.get(f"/runs/{RUN}/samples/worklists")
        assert _options(resp.text) == ["W1", "7"]
        assert "warning-message" not in resp.text


# --- spec §1, §2: the button and the page after an import -------------------

BANNER = {"HX-Retarget": "#error-banner", "HX-Reswap": "innerHTML", "HX-Reselect": "unset"}


def _worksheet(monkeypatch, rows):
    """The LIMS's rows for any worksheet, with no network; the real
    fetch_worklist_samples, parse and import run. Records the URLs asked."""
    asked = []

    def answer(url, api_key=""):
        asked.append(url)
        return [dict(row) if isinstance(row, dict) else row for row in rows]

    monkeypatch.setattr(sample_api_module, "_api_get", answer)
    return asked


def _import(client, **form):
    return client.post(f"/runs/{RUN}/samples/fetch-worklist", data=form, headers=ORIGIN)


def _headers(resp):
    return {name: resp.headers.get(name) for name in BANNER}


class TestTheRunPageAsksTheRunsAddress:
    """The run page gave the LIMS box no run_id, so Load Worklists asked
    /runs//samples/worklists, which is a 404."""

    def test_load_worklists_asks_this_run(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)
        _lims_on(ctx)
        resp = logged_in_client.get(f"/runs/{RUN}")
        assert re.findall(r'hx-get="([^"]*/samples/worklists[^"]*)"', resp.text) == [
            f"/runs/{RUN}/samples/worklists"]


class TestTheImportSwapsTheSampleSection:
    """The import answers with the whole #sample-section; swapped in place of
    #sample-table, the section landed inside itself."""

    def test_import_samples_targets_the_section(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _run(ctx)
        _lims_on(ctx)
        _worksheet_list(monkeypatch, [{"id": "W1"}])
        resp = logged_in_client.get(f"/runs/{RUN}/samples/worklists")
        button = re.search(r'<button[^>]*hx-post="[^"]*fetch-worklist[^"]*"[^>]*>', resp.text).group(0)
        assert 'hx-target="#sample-section"' in button
        assert 'hx-swap="outerHTML"' in button


class TestTheImportReadsTheWorksheetFromTheFormBody:
    """The page posts worklist_id in the form body; the route read the query
    string, answered "No worklist selected." and asked the LIMS nothing."""

    def test_a_form_body_post_imports(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _run(ctx)
        _lims_on(ctx)
        asked = _worksheet(monkeypatch, [{"sample_id": "P1", "test_id": ""}])
        resp = _import(logged_in_client, worklist_id="WS1")
        assert resp.status_code == 200, resp.text[:300]
        assert "Added 1 sample from worklist." in resp.text
        assert asked == ["https://lims.example.org/api/worksheets/WS1"]
        assert [s.sample_id for s in ctx.run_repo.get_by_id(RUN).samples] == ["P1"]

    def test_the_query_string_is_not_read(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _run(ctx)
        _lims_on(ctx)
        asked = _worksheet(monkeypatch, [{"sample_id": "P1", "test_id": ""}])
        resp = logged_in_client.post(f"/runs/{RUN}/samples/fetch-worklist",
                                     params={"worklist_id": "WS1"}, headers=ORIGIN)
        assert resp.status_code == 400
        assert '<p class="error-message">No worklist selected.</p>' in resp.text
        assert asked == []


class TestEachRefusalOfTheImportGoesToTheBanner:
    """A refusal answers 400 with today's message, aimed at #error-banner,
    and the run stays as it was. A 200 aimed there could be cleared by
    app.js right after a failed import from the same button."""

    def _refused(self, client, ctx, **form):
        before = ctx.run_repo.get_by_id(RUN).to_dict()
        resp = _import(client, **form)
        assert resp.status_code == 400
        assert _headers(resp) == BANNER
        assert ctx.run_repo.get_by_id(RUN).to_dict() == before
        return resp.text

    def test_the_sample_api_not_enabled(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, ["OLD1"])
        ctx.sample_api_config_repo.save(SampleApiConfig(base_url="https://lims.example.org/api"))
        text = self._refused(logged_in_client, ctx, worklist_id="WS1")
        assert ('<p class="error-message">Sample API is not enabled or base URL is not '
                'configured.</p>') in text

    def test_no_worksheet_picked(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, ["OLD1"])
        _lims_on(ctx)
        assert '<p class="error-message">No worklist selected.</p>' in self._refused(
            logged_in_client, ctx)

    def test_the_fetch_failed(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _run(ctx, ["OLD1"])
        _lims_on(ctx)

        def fail(url, api_key=""):
            raise sample_api_module.SampleApiError("The LIMS did not answer")

        monkeypatch.setattr(sample_api_module, "_api_get", fail)
        assert ('<p class="error-message">Failed to fetch worklist samples: The LIMS did not '
                'answer</p>') in self._refused(logged_in_client, ctx, worklist_id="WS1")

    def test_the_rows_refused(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _run(ctx, ["OLD1"])
        _lims_on(ctx)
        _worksheet(monkeypatch, [{"sample_id": "P1"}, {"sample_id": "P1"}])
        assert ('<p class="error-message">Worklist import rejected: these sample IDs appear more '
                'than once in the worklist: P1. Nothing was added.</p>') in self._refused(
            logged_in_client, ctx, worklist_id="WS1")

    def test_no_valid_samples(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _run(ctx, ["OLD1"])
        _lims_on(ctx)
        _worksheet(monkeypatch, [{"sample_id": "P1"}])
        monkeypatch.setattr(sample_api_module, "parse_api_samples", lambda rows, config: [])
        assert ('<p class="warning-message">No valid samples found in worklist.</p>'
                in self._refused(logged_in_client, ctx, worklist_id="WS1"))

    def test_the_runs_sample_maximum(self, logged_in_client, fresh_app, monkeypatch):
        from seqsetup.models import sequencing_run as sequencing_run_module
        _app, ctx, _db = fresh_app
        _run(ctx, ["OLD1"])
        _lims_on(ctx)
        _worksheet(monkeypatch, [{"sample_id": "P1"}])
        monkeypatch.setattr(sequencing_run_module, "MAX_SAMPLES_PER_RUN", 1)
        assert ('<p class="error-message">Worklist import rejected: a run accepts a maximum of 1 '
                'samples (run already has 1).</p>') in self._refused(
            logged_in_client, ctx, worklist_id="WS1")

    def test_every_sample_already_in_the_run_answers_as_today(
            self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _run(ctx, ["OLD1"])
        _lims_on(ctx)
        _worksheet(monkeypatch, [{"sample_id": "OLD1"}])
        resp = _import(logged_in_client, worklist_id="WS1")
        assert resp.status_code == 200
        assert _headers(resp) == {name: None for name in BANNER}
        assert 'id="sample-section"' in resp.text
        assert '<p class="warning-message">No new samples added from worklist.</p>' in resp.text
