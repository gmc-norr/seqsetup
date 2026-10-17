"""A sample ID made only of zeros is refused through the real routes.

A LIMS may use 0 for an empty well, so a worklist row for an empty well
arrives as the JSON number 0 and looks like a sample called "0". Paste,
LIMS import and manual entry each refuse it and save nothing.
"""

import pytest

from seqsetup.models.sample import Sample
from seqsetup.models.sample_api_config import SampleApiConfig
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, SequencingRun
from seqsetup.services import sample_api as sample_api_module
from .conftest import hold_edit_lock

ORIGIN = {"Origin": "http://testserver"}
RUN = "zero-id-run"


def _run(ctx, sample_ids=()):
    run = SequencingRun(
        id=RUN, run_name="Zero ID", instrument_platform=InstrumentPlatform.NOVASEQ_X,
        flowcell_type="10B", run_cycles=RunCycles(151, 151, 8, 8),
    )
    for k, sample_id in enumerate(sample_ids, start=1):
        run.add_sample(Sample(id=f"s{k}", sample_id=sample_id, lanes=[1]))
    ctx.run_repo.save(run)
    hold_edit_lock(ctx, run.id)


def _stored(ctx):
    return ctx.run_repo.get_by_id(RUN)


class TestManualEntry:
    @pytest.mark.parametrize("value", ["0", "00"])
    def test_adding_a_sample_called_zero_is_400(self, logged_in_client, fresh_app, value):
        _app, ctx, _db = fresh_app
        _run(ctx)
        before = _stored(ctx).to_dict()

        resp = logged_in_client.post(
            f"/runs/{RUN}/samples", data={"sample_id": value}, headers=ORIGIN)

        assert resp.status_code == 400, resp.text[:300]
        assert "only of zeros" in resp.text
        assert _stored(ctx).to_dict() == before


class TestPaste:
    def test_the_whole_paste_is_refused_and_the_banner_names_the_row(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)

        resp = logged_in_client.post(
            f"/runs/{RUN}/samples/bulk",
            data={"paste_data": "sample_id\nPAT1\n0\n", "lanes": "1"},
            headers=ORIGIN,
        )

        assert resp.status_code == 200, resp.text[:300]
        assert "only of zeros" in resp.text
        assert _stored(ctx).samples == []

    def test_the_preview_refuses_it_too(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)

        resp = logged_in_client.post(
            f"/runs/{RUN}/samples/preview",
            data={"paste_data": "sample_id\nPAT1\n0\n", "lanes": "1"},
            headers=ORIGIN,
        )

        assert resp.status_code == 200, resp.text[:300]
        assert "only of zeros" in resp.text
        assert _stored(ctx).samples == []


class TestWorklistImport:
    def _lims(self, ctx, monkeypatch, rows):
        ctx.sample_api_config_repo.save(
            SampleApiConfig(base_url="https://lims.example.org/api", enabled=True))
        monkeypatch.setattr(
            sample_api_module, "fetch_worklist_samples",
            lambda config, worklist_id: (True, f"Fetched {len(rows)} samples", rows),
        )

    def test_a_row_with_the_number_zero_refuses_the_whole_worklist(
            self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _run(ctx)
        self._lims(ctx, monkeypatch, [
            {"sample_id": "PAT1", "test_id": "WGS"},
            {"sample_id": 0, "test_id": "WGS"},
        ])

        resp = logged_in_client.post(
            f"/runs/{RUN}/samples/fetch-worklist", data={"worklist_id": "WS1", "lanes": "1"},
            headers=ORIGIN)

        assert resp.status_code == 400, resp.text[:300]
        assert "only of zeros" in resp.text
        assert _stored(ctx).samples == []
