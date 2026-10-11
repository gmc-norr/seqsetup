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
