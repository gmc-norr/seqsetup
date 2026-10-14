"""Long sample text is refused through the real routes, never cut (outside
review of 7f858e0, finding 5; spec 2026-10-14 long sample text).

Each way in answers with a message naming what is too long, and the run
stays as it was.
"""

import json

import pytest

from seqsetup.models.sample import Sample
from seqsetup.models.sample_api_config import SampleApiConfig
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, SequencingRun
from seqsetup.services import sample_api as sample_api_module
from .conftest import hold_edit_lock, import_from_preview

ORIGIN = {"Origin": "http://testserver"}
RUN = "long-text-run"
LONG, FULL = "A" * 257, "A" * 256


def _run(ctx, sample_ids=()):
    run = SequencingRun(
        id=RUN, run_name="Long text", instrument_platform=InstrumentPlatform.NOVASEQ_X,
        flowcell_type="10B", run_cycles=RunCycles(151, 151, 10, 10),
    )
    for k, sample_id in enumerate(sample_ids, start=1):
        run.add_sample(Sample(id=f"s{k}", sample_id=sample_id, lanes=[1]))
    ctx.run_repo.save(run)
    hold_edit_lock(ctx, run.id)


def _stored(ctx):
    return ctx.run_repo.get_by_id(RUN).to_dict()


LABELS = {"sample_id": "sample ID", "sample_name": "sample name", "project": "project",
          "test_id": "test"}


class TestAddingOneSample:

    @pytest.mark.parametrize("field", ["sample_id", "sample_name", "project", "test_id"])
    def test_a_long_value_is_400(self, logged_in_client, fresh_app, field):
        _app, ctx, _db = fresh_app
        _run(ctx)
        before = _stored(ctx)
        data = {"sample_id": "P1", field: LONG}

        resp = logged_in_client.post(f"/runs/{RUN}/samples", data=data, headers=ORIGIN)

        assert resp.status_code == 400, resp.text[:300]
        assert resp.text == f"The {LABELS[field]} is longer than 256 characters. Nothing was saved."
        assert _stored(ctx) == before

    def test_256_is_kept_whole(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)

        resp = logged_in_client.post(f"/runs/{RUN}/samples", data={"sample_id": f"  {FULL}  "},
                                     headers=ORIGIN)

        assert resp.status_code == 200, resp.text[:300]
        assert [s["sample_id"] for s in _stored(ctx)["samples"]] == [FULL]


class TestRenamingASample:

    @pytest.mark.parametrize("field", ["sample_id", "sample_name", "project"])
    def test_a_long_value_is_400(self, logged_in_client, fresh_app, field):
        _app, ctx, _db = fresh_app
        _run(ctx, ["PAT1"])
        before = _stored(ctx)

        resp = logged_in_client.post(f"/runs/{RUN}/samples/s1", data={field: LONG}, headers=ORIGIN)

        assert resp.status_code == 400, resp.text[:300]
        assert resp.text == f"The {LABELS[field]} is longer than 256 characters. Nothing was saved."
        assert _stored(ctx) == before


class TestSettingATestOnSelectedSamples:

    def test_a_long_test_is_400(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, ["PAT1"])
        before = _stored(ctx)

        resp = logged_in_client.post(f"/runs/{RUN}/samples/set-test-id",
                                     data={"sample_ids": json.dumps(["s1"]), "test_id": LONG},
                                     headers=ORIGIN)

        assert resp.status_code == 400, resp.text[:300]
        assert resp.text == "The test is longer than 256 characters. Nothing was saved."
        assert _stored(ctx) == before


class TestAPaste:

    @pytest.mark.parametrize("path", ["bulk", "preview"])
    def test_a_long_default_test_is_400(self, logged_in_client, fresh_app, path):
        _app, ctx, _db = fresh_app
        _run(ctx)
        before = _stored(ctx)

        resp = logged_in_client.post(
            f"/runs/{RUN}/samples/{path}",
            data={"paste_data": "sample_id\nPAT1\n", "lanes": "1", "default_test_id": LONG},
            headers=ORIGIN)

        assert resp.status_code == 400, resp.text[:300]
        assert resp.text == "The test is longer than 256 characters. Nothing was saved."
        assert _stored(ctx) == before

    @pytest.mark.parametrize("path", ["bulk", "preview"])
    def test_a_long_sample_id_refuses_the_whole_paste(self, logged_in_client, fresh_app, path):
        _app, ctx, _db = fresh_app
        _run(ctx)

        resp = logged_in_client.post(
            f"/runs/{RUN}/samples/{path}",
            data={"paste_data": f"sample_id\nPAT1\n{LONG}\n", "lanes": "1"}, headers=ORIGIN)

        assert resp.status_code == 200, resp.text[:300]
        assert "Row(s) 3: the sample_id is longer than 256 characters." in resp.text
        assert _stored(ctx)["samples"] == []


class TestAWorklist:

    def _lims(self, ctx, monkeypatch, rows):
        ctx.sample_api_config_repo.save(
            SampleApiConfig(base_url="https://lims.example.org/api", enabled=True))
        monkeypatch.setattr(sample_api_module, "_api_get", lambda url, api_key="": rows)

    def test_the_preview_shows_the_refusal(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _run(ctx)
        self._lims(ctx, monkeypatch, [{"sample_id": "P1"}, {"sample_id": "P2", "worksheet_id": LONG}])

        resp = logged_in_client.get(f"/runs/{RUN}/samples/preview-worklist",
                                    params={"worklist_id": "WS1"})

        assert ("Importing this worksheet would be refused: LIMS row(s) 2: the worksheet ID is "
                "longer than 256 characters.") in resp.text

    def test_the_import_is_refused(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _run(ctx)
        self._lims(ctx, monkeypatch, [{"sample_id": LONG}])
        before = _stored(ctx)

        resp = import_from_preview(logged_in_client, RUN, "WS1")

        assert resp.status_code == 400, resp.text[:300]
        assert ("Worklist import rejected: LIMS row(s) 1: the sample_id is longer than 256 "
                "characters.") in resp.text
        assert _stored(ctx) == before


class TestARunHoldingALongValue:
    """Only a run saved before the cuts (2026-05-25) can hold one. By the
    user's choice it is not cut on load: the dashboard names it as a run it
    could not read."""

    def test_the_dashboard_names_it(self, logged_in_client, fresh_app):
        _app, ctx, db = fresh_app
        _run(ctx, ["PAT1"])
        doc = db["runs"].find_one({"_id": RUN})
        doc["samples"][0]["sample_id"] = LONG
        db["runs"].replace_one({"_id": RUN}, doc)

        resp = logged_in_client.get("/")

        assert resp.status_code == 200
        assert f"could not be read and is not listed: {RUN}." in resp.text
