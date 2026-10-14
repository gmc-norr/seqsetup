"""Later list, slice 2: the LIMS import works from the run page, a worksheet
whose ID SeqSetup cannot read for sure is left out of the list, and the
preview shows what the import would add (spec 2026-10-10 later list slice 2)."""

import re

import pytest
from markupsafe import escape

from seqsetup.models.sample import Sample
from seqsetup.models.sample_api_config import SampleApiConfig
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, SequencingRun
from seqsetup.services import sample_api as sample_api_module
from .conftest import hold_edit_lock, import_from_preview

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
    hold_edit_lock(ctx, run.id)


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

    def test_at_most_ten_warnings(self, logged_in_client, fresh_app, monkeypatch):
        """300 bad IDs gave 300 warnings above the list (build review of later
        list slice 2, M1-1, MB-2)."""
        _app, ctx, _db = fresh_app
        _run(ctx)
        _lims_on(ctx)
        _worksheet_list(monkeypatch, [{"id": "W1"}] + [{"id": k + 0.5} for k in range(12)])
        resp = logged_in_client.get(f"/runs/{RUN}/samples/worklists")
        assert _options(resp.text) == ["W1"]
        assert resp.text.count('<p class="warning-message">') == 11
        assert "(9.5)" in resp.text and "(10.5)" not in resp.text
        assert ('<p class="warning-message">2 more warnings about the LIMS list are not '
                'shown.</p>') in resp.text

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
    """Import as the page does: from the preview, with the plan it shows
    (outside review of 7f858e0, finding 2). With no worksheet picked there
    is no preview."""
    if form.get("worklist_id"):
        return import_from_preview(client, RUN, form["worklist_id"])
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

    def test_the_previews_import_targets_the_section(self, logged_in_client, fresh_app, monkeypatch):
        """The import is the preview's button now (outside review of 7f858e0,
        finding 2)."""
        _app, ctx, _db = fresh_app
        _run(ctx)
        _lims_on(ctx)
        _worksheet(monkeypatch, [{"sample_id": "P1"}])
        resp = _preview(logged_in_client)
        form = re.search(r'<form[^>]*hx-post="[^"]*fetch-worklist[^"]*"[^>]*>', resp.text).group(0)
        assert 'hx-target="#sample-section"' in form
        assert 'hx-swap="outerHTML"' in form


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
        # Asked by the preview, then again by the import, which compares.
        assert asked == ["https://lims.example.org/api/worksheets/WS1"] * 2
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

    def test_every_sample_already_in_the_run(self, logged_in_client, fresh_app, monkeypatch):
        """The preview offers no import then, so there is no plan to send
        (outside review of 7f858e0, finding 2)."""
        _app, ctx, _db = fresh_app
        _run(ctx, ["OLD1"])
        _lims_on(ctx)
        _worksheet(monkeypatch, [{"sample_id": "OLD1"}])
        assert ('<p class="error-message">Preview the worksheet first, then import it from the '
                'preview.</p>') in self._refused(logged_in_client, ctx, worklist_id="WS1")


# --- spec §4: the preview is the import's plan -------------------------------

def _preview(client, worklist_id="WS1"):
    return client.get(f"/runs/{RUN}/samples/preview-worklist",
                      params={"worklist_id": worklist_id, "lanes": ["1"]})


def _cells(html):
    return [re.findall(r"<td>(.*?)</td>", row) for row in re.findall(r"<tr>(.*?)</tr>", html, re.S)
            if "<td>" in row]


GOOD_ROWS = [
    {"Sample": "P1", "Test": "WGS", "test_version": "1", "index_i7": "ACGTACGT",
     "index_i5": "TTGGCCAA"},
    {"sample_id": "P2", "test_id": "WES", "test_version": "2.1"},
    {"sample_id": "OLD1", "test_id": "WGS", "test_version": "1"},
]


class TestThePreviewShowsWhatTheImportWouldAdd:
    """The preview showed the rows as the LIMS sent them, by two names only,
    20 at most, with no version, and a worksheet the import refuses looked
    like any other. Now it shows the import's own plan."""

    def test_a_good_worksheet(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _run(ctx, ["OLD1"])
        _lims_on(ctx)
        _worksheet(monkeypatch, GOOD_ROWS)
        resp = _preview(logged_in_client)
        assert resp.status_code == 200
        assert "<h4>Worksheet WS1: 2 samples to add to lane 1</h4>" in resp.text
        assert _cells(resp.text) == [["P1", "WGS", "1", "ACGTACGT", "TTGGCCAA"],
                                     ["P2", "WES", "2.1", "-", "-"]]
        assert ('<p class="warning-message">1 already in this run, will be skipped: OLD1</p>'
                in resp.text)

    def test_the_import_adds_what_the_preview_showed(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _run(ctx, ["OLD1"])
        _lims_on(ctx)
        _worksheet(monkeypatch, GOOD_ROWS)
        shown = _cells(_preview(logged_in_client).text)
        assert _import(logged_in_client, worklist_id="WS1").status_code == 200
        added = [[s.sample_id, s.test_id or "-", s.test_version or "-", s.index1_sequence or "-",
                  s.index2_sequence or "-"] for s in ctx.run_repo.get_by_id(RUN).samples[1:]]
        assert added == shown

    def test_one_sample(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _run(ctx)
        _lims_on(ctx)
        _worksheet(monkeypatch, [{"sample_id": "P1"}])
        resp = _preview(logged_in_client)
        assert "<h4>Worksheet WS1: 1 sample to add to lane 1</h4>" in resp.text
        assert "already in this run" not in resp.text

    def test_every_row_is_shown(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _run(ctx)
        _lims_on(ctx)
        _worksheet(monkeypatch, [{"sample_id": f"P{k}"} for k in range(25)])
        resp = _preview(logged_in_client)
        assert [row[0] for row in _cells(resp.text)] == [f"P{k}" for k in range(25)]
        assert "more samples" not in resp.text

    def test_an_admins_test_version_field_is_read(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _run(ctx)
        _lims_on(ctx, {"test_version": "TV"})
        _worksheet(monkeypatch, [{"sample_id": "P1", "test_id": "WGS", "TV": "1.2"}])
        assert _cells(_preview(logged_in_client).text) == [["P1", "WGS", "1.2", "-", "-"]]

    def test_a_refused_worksheet_shows_the_imports_refusal(
            self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _run(ctx)
        _lims_on(ctx)
        _worksheet(monkeypatch, [{"sample_id": "P1"}, {"sample_id": "P1"}])
        refusal = ("these sample IDs appear more than once in the worklist: P1. "
                   "Nothing was added.")
        resp = _preview(logged_in_client)
        assert resp.status_code == 200
        assert (f'<p class="error-message">Importing this worksheet would be refused: {refusal}</p>'
                in resp.text)
        assert "<table" not in resp.text
        assert (f'<p class="error-message">Worklist import rejected: {refusal}</p>'
                in _import(logged_in_client, worklist_id="WS1").text)

    def test_the_runs_sample_maximum(self, logged_in_client, fresh_app, monkeypatch):
        from seqsetup.models import sequencing_run as sequencing_run_module
        _app, ctx, _db = fresh_app
        _run(ctx, ["OLD1"])
        _lims_on(ctx)
        _worksheet(monkeypatch, [{"sample_id": "P1"}])
        monkeypatch.setattr(sequencing_run_module, "MAX_SAMPLES_PER_RUN", 1)
        assert ('<p class="error-message">Importing this worksheet would be refused: a run accepts '
                'a maximum of 1 samples (run already has 1).</p>') in _preview(logged_in_client).text

    def test_the_preview_of_a_ready_run_is_refused(self, logged_in_client, fresh_app, monkeypatch):
        from seqsetup.models.sequencing_run import RunStatus
        _app, ctx, _db = fresh_app
        _run(ctx)
        run = ctx.run_repo.get_by_id(RUN)
        run.status = RunStatus.READY
        ctx.run_repo.save(run)
        hold_edit_lock(ctx, run.id)
        _lims_on(ctx)
        asked = _worksheet(monkeypatch, [{"sample_id": "P1"}])
        assert _preview(logged_in_client).status_code == 403
        assert asked == []


class TestThePlanGivesARowThePickedWorksheet:
    """A row whose worksheet ID is null has none after parsing; the import
    gives it the worksheet that was picked, and so does the plan."""

    def test_null_in_either_spelling(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _run(ctx)
        _lims_on(ctx)
        _worksheet(monkeypatch, [{"sample_id": "P1", "worksheet_id": None},
                                 {"sample_id": "P2", "Worksheet_ID": None},
                                 {"sample_id": "P3", "worksheet_id": "W7"}])
        assert _import(logged_in_client, worklist_id="WS9").status_code == 200
        assert {s.sample_id: s.worksheet_id for s in ctx.run_repo.get_by_id(RUN).samples} == {
            "P1": "WS9", "P2": "WS9", "P3": "W7"}

    def test_blank_in_either_spelling(self, logged_in_client, fresh_app, monkeypatch):
        """A blank kept the blank, so the row named no worksheet (build review
        of slice 2, E-2); spec §4 says absent, null or blank."""
        _app, ctx, _db = fresh_app
        _run(ctx)
        _lims_on(ctx)
        _worksheet(monkeypatch, [{"sample_id": "P1", "worksheet_id": ""},
                                 {"sample_id": "P2", "Worksheet_ID": "  "},
                                 {"sample_id": "P3", "worksheet_id": "W7"}])
        assert _import(logged_in_client, worklist_id="WS9").status_code == 200
        assert {s.sample_id: s.worksheet_id for s in ctx.run_repo.get_by_id(RUN).samples} == {
            "P1": "WS9", "P2": "WS9", "P3": "W7"}

    @pytest.mark.parametrize("name", ["worklist_id", "worksheetid", "worksheet", "AL"])
    def test_a_row_with_its_own_under_another_name_keeps_it(
            self, logged_in_client, fresh_app, monkeypatch, name):
        """The picked worksheet hid it (Astra's review of later list slice 2)."""
        _app, ctx, _db = fresh_app
        _run(ctx)
        _lims_on(ctx)
        _worksheet(monkeypatch, [{"sample_id": "PATIENT", name: "ORIGINAL"}])
        assert _import(logged_in_client, worklist_id="WS1").status_code == 200
        assert [(s.sample_id, s.worksheet_id) for s in ctx.run_repo.get_by_id(RUN).samples] == [
            ("PATIENT", "ORIGINAL")]

    def test_the_plan_itself(self, fresh_app):
        from seqsetup.routes.samples import _plan_worklist_import
        _app, ctx, _db = fresh_app
        _run(ctx)
        rows = [{"sample_id": "P1", "worksheet_id": None}, {"sample_id": "P2", "worksheet_id": "W7"}]
        config = SampleApiConfig(base_url="https://lims.example.org/api", enabled=True)
        new, skipped = _plan_worklist_import(ctx.run_repo.get_by_id(RUN), rows, config, "WS9", [1])
        assert [(s.sample_id, s.worksheet_id) for s in new] == [("P1", "WS9"), ("P2", "W7")]
        assert skipped == []


class TestAnIndexNameWithoutItsSequence:
    """A row with an i7 or i5 name and no sequence for it was added with no
    index and no message (build review of later list slice 2, M2-6): the
    whole worksheet is refused, as for a row without a sample ID."""

    ROWS = [
        ([{"sample_id": "P1", "i7_name": "D701"}],
         "Sample 'P1' has an i7 name ('D701') but no i7 sequence."),
        ([{"sample_id": "P1", "index_i7": "ACGTACGT", "i5_name": "D501"}],
         "Sample 'P1' has an i5 name ('D501') but no i5 sequence."),
        ([{"sample_id": "P1", "index_i7": "ACGTACGT", "index_i5": "", "i5_name": "D501"}],
         "Sample 'P1' has an i5 name ('D501') but no i5 sequence."),
        ([{"sample_id": "P1", "index_pair_name": "UDP0001"}],
         "Sample 'P1' has an index pair name ('UDP0001') but no index sequence."),
        ([{"sample_id": "P1", "kit_name": "Kit A"}],
         "Sample 'P1' has an index pair name ('Kit A') but no index sequence."),
    ]

    @pytest.mark.parametrize("rows, text", ROWS)
    def test_the_import_is_refused(self, logged_in_client, fresh_app, monkeypatch, rows, text):
        _app, ctx, _db = fresh_app
        _run(ctx, ["OLD1"])
        _lims_on(ctx)
        _worksheet(monkeypatch, rows)
        before = ctx.run_repo.get_by_id(RUN).to_dict()
        resp = _import(logged_in_client, worklist_id="WS1")
        assert resp.status_code == 400
        assert _headers(resp) == BANNER
        assert f'<p class="error-message">Worklist import rejected: {escape(text)}</p>' in resp.text
        assert ctx.run_repo.get_by_id(RUN).to_dict() == before

    @pytest.mark.parametrize("rows, text", ROWS[:1])
    def test_the_preview_shows_the_refusal(self, logged_in_client, fresh_app, monkeypatch, rows, text):
        _app, ctx, _db = fresh_app
        _run(ctx)
        _lims_on(ctx)
        _worksheet(monkeypatch, rows)
        resp = _preview(logged_in_client)
        assert (f'<p class="error-message">Importing this worksheet would be refused: '
                f'{escape(text)}</p>') in resp.text

    def test_a_name_with_its_sequence_is_imported(self, logged_in_client, fresh_app, monkeypatch):
        """A pair name with only an i7 is a single-index sample, as before."""
        _app, ctx, _db = fresh_app
        _run(ctx)
        _lims_on(ctx)
        _worksheet(monkeypatch, [
            {"sample_id": "P1", "index_i7": "ACGTACGT", "i7_name": "D701"},
            {"sample_id": "P2", "kit_name": "Kit A", "index_i7": "TTGGCCAA"}])
        assert _import(logged_in_client, worklist_id="WS1").status_code == 200
        stored = {s.sample_id: s for s in ctx.run_repo.get_by_id(RUN).samples}
        assert (stored["P1"].index1_name, stored["P1"].index1_sequence) == ("D701", "ACGTACGT")
        assert (stored["P2"].index_kit_name, stored["P2"].index1_sequence) == ("Kit A", "TTGGCCAA")


class TestTheWorksheetListNeedsADraft:
    """Load Worklists asked the LIMS for any run ID, a Ready run's or none
    (build review of later list slice 2, M3-3, MB-1); the preview and the
    import take a draft only, and so does the list now."""

    def _asked(self, monkeypatch):
        asked = []

        def answer(url, api_key=""):
            asked.append(url)
            return [{"id": "W1"}]

        monkeypatch.setattr(sample_api_module, "_api_get", answer)
        return asked

    def test_a_ready_run(self, logged_in_client, fresh_app, monkeypatch):
        from seqsetup.models.sequencing_run import RunStatus
        _app, ctx, _db = fresh_app
        _run(ctx)
        run = ctx.run_repo.get_by_id(RUN)
        run.status = RunStatus.READY
        ctx.run_repo.save(run)
        hold_edit_lock(ctx, run.id)
        _lims_on(ctx)
        asked = self._asked(monkeypatch)
        assert logged_in_client.get(f"/runs/{RUN}/samples/worklists").status_code == 403
        assert asked == []

    def test_no_such_run(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _lims_on(ctx)
        asked = self._asked(monkeypatch)
        assert logged_in_client.get("/runs/no-such-run/samples/worklists").status_code == 404
        assert asked == []

    def test_a_draft_is_listed(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _run(ctx)
        _lims_on(ctx)
        self._asked(monkeypatch)
        resp = logged_in_client.get(f"/runs/{RUN}/samples/worklists")
        assert resp.status_code == 200
        assert _options(resp.text) == ["W1"]


class TestTheLimsRoutesAreSafeToUse:
    """Three findings of the build review of later list slice 2."""

    def test_the_import_button_is_off_while_it_works(self, logged_in_client, fresh_app, monkeypatch):
        """Two quick clicks sent two imports; the paste's Add has this (M2-4)."""
        _app, ctx, _db = fresh_app
        _run(ctx)
        _lims_on(ctx)
        _worksheet(monkeypatch, [{"sample_id": "P1"}])
        resp = _preview(logged_in_client)
        [form] = re.findall(r"<form[^>]*samples/fetch-worklist[^>]*>", resp.text)
        assert 'hx-disabled-elt="find button"' in form

    def test_the_lims_routes_run_in_the_thread_pool(self):
        """An async def import made its LIMS call, up to 30 s, on the server's
        event loop, which served no other request meanwhile (M3-5)."""
        import inspect
        from seqsetup.routes import samples
        assert [inspect.iscoroutinefunction(f) for f in (
            samples.list_worklists, samples.preview_worklist, samples.import_worklist_samples)] == [
            False, False, False]

    def test_the_preview_changes_nothing(self, logged_in_client, fresh_app, monkeypatch):
        """Nothing tested it (M3-4)."""
        _app, ctx, _db = fresh_app
        _run(ctx, ["OLD1"])
        _lims_on(ctx)
        _worksheet(monkeypatch, [{"sample_id": "OLD1"}, {"sample_id": "P1", "index_i7": "ACGTACGT"}])
        before = ctx.run_repo.get_by_id(RUN).to_dict()
        resp = _preview(logged_in_client)
        assert "1 sample to add" in resp.text and "1 already in this run" in resp.text
        assert ctx.run_repo.get_by_id(RUN).to_dict() == before


class TestTheAdminSeesTheConnectionCount:
    """The save tested the connection but showed its message only on a
    failure, so the count of worksheets a run would list never showed
    (review of the fixes after the build of later list slice 2)."""

    def test_the_count_is_shown_after_a_save(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _worksheet_list(monkeypatch, [{"id": "W1"}, {"id": 2.5}, "x"])
        resp = logged_in_client.post("/admin/settings/sample-api", data={
            "base_url": "https://lims.example.org/api", "enabled": "on"}, headers=ORIGIN)
        assert resp.status_code == 200
        assert ("LIMS integration configuration saved. Connection successful (1 worksheets "
                "found; 2 other entries in the reply are not listed)") in resp.text
        assert ctx.sample_api_config_repo.get().enabled is True

    def test_a_save_that_is_not_enabled_tests_nothing(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        asked = _worksheet(monkeypatch, [])
        resp = logged_in_client.post("/admin/settings/sample-api", data={
            "base_url": "https://lims.example.org/api"}, headers=ORIGIN)
        assert ">LIMS integration configuration saved</div>" in resp.text
        assert asked == []
