"""A worklist ID made only of dots is refused before the LIMS is asked.

``worklist_samples_url`` built ``{base}/worksheets/..`` -- ``quote`` leaves a
dot alone -- and SeqSetup sent it with the LIMS api-key, so any server or
proxy that normalises dot segments answered for ``{base}/`` instead. The
JSON that came back was shown in the preview, or imported as this run's
samples. Any signed-in standard user could ask for it through the run page
(security review 2026-10).

The refusal is ``validate_worklist_id``'s, so every caller gets it; these
tests prove it where a person reaches it, and that nothing is asked of the
LIMS at all.
"""

import pytest

from seqsetup.models.sample import Sample
from seqsetup.models.sample_api_config import SampleApiConfig
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, SequencingRun
from seqsetup.services import sample_api as sample_api_module

ORIGIN = {"Origin": "http://testserver"}
RUN = "dots-run"
DOT_ONLY = [".", "..", "..."]


def _run(ctx, sample_ids=()):
    run = SequencingRun(
        id=RUN, run_name="Dots", instrument_platform=InstrumentPlatform.NOVASEQ_X,
        flowcell_type="10B", run_cycles=RunCycles(151, 151, 10, 10),
    )
    for k, sample_id in enumerate(sample_ids, start=1):
        run.add_sample(Sample(id=f"s{k}", sample_id=sample_id, lanes=[1]))
    ctx.run_repo.save(run)


def _lims_on(ctx):
    ctx.sample_api_config_repo.save(SampleApiConfig(
        base_url="https://lims.example.org/api", enabled=True))


def _lims_asked(monkeypatch, rows=({"sample_id": "P1", "test_id": ""},)):
    """Record every URL asked of the LIMS; no network. Returns the list."""
    asked = []

    def answer(url, api_key=""):
        asked.append(url)
        return [dict(row) for row in rows]

    monkeypatch.setattr(sample_api_module, "_api_get", answer)
    return asked


@pytest.fixture
def lims_run(logged_in_client, fresh_app, monkeypatch):
    _app, ctx, _db = fresh_app
    _run(ctx)
    _lims_on(ctx)
    return logged_in_client, ctx, _lims_asked(monkeypatch)


def _preview(client, worklist_id):
    return client.get(f"/runs/{RUN}/samples/preview-worklist",
                      params={"worklist_id": worklist_id})


def _import(client, worklist_id):
    return client.post(f"/runs/{RUN}/samples/fetch-worklist",
                       data={"worklist_id": worklist_id}, headers=ORIGIN)


class TestThePreviewRefusesIt:
    @pytest.mark.parametrize("worklist_id", DOT_ONLY)
    def test_the_lims_is_not_asked_and_the_refusal_is_shown(self, lims_run, worklist_id):
        client, _ctx, asked = lims_run

        refused = _preview(client, worklist_id)

        assert asked == []
        assert "only of dots" in refused.text
        assert "Failed to fetch worksheet samples" in refused.text

    def test_a_bad_id_of_another_kind_is_answered_the_same_way(self, lims_run):
        """Control on the shape: a slash in the ID has always been refused
        here, and the dot-only rule did not move that refusal."""
        client, _ctx, asked = lims_run

        refused = _preview(client, "WS/1")

        assert asked == []
        assert "Failed to fetch worksheet samples" in refused.text

    def test_an_ordinary_id_still_previews(self, lims_run):
        client, _ctx, asked = lims_run

        shown = _preview(client, "1.2")

        assert asked == ["https://lims.example.org/api/worksheets/1.2"]
        assert "P1" in shown.text


class TestTheImportRefusesIt:
    @pytest.mark.parametrize("worklist_id", DOT_ONLY)
    def test_the_lims_is_not_asked_and_nothing_is_imported(
            self, lims_run, worklist_id):
        client, ctx, asked = lims_run

        refused = _import(client, worklist_id)

        assert asked == []
        assert refused.status_code == 400
        assert refused.headers.get("HX-Retarget") == "#error-banner"
        assert "only of dots" in refused.text
        assert ctx.run_repo.get_by_id(RUN).samples == []

    def test_a_bad_id_of_another_kind_is_answered_the_same_way(self, lims_run):
        client, ctx, asked = lims_run

        refused = _import(client, "WS/1")

        assert asked == []
        assert refused.status_code == 400
        assert refused.headers.get("HX-Retarget") == "#error-banner"
        assert ctx.run_repo.get_by_id(RUN).samples == []

    def test_an_ordinary_id_still_imports(self, lims_run):
        client, ctx, asked = lims_run

        imported = _import(client, "1.2")

        assert asked == ["https://lims.example.org/api/worksheets/1.2"]
        assert imported.status_code == 200
        assert [s.sample_id for s in ctx.run_repo.get_by_id(RUN).samples] == ["P1"]


class TestAWorksheetTheLimsListsWithSuchAnIdIsLeftOut:
    """The same bug reached through a hostile or broken LIMS reply: the list
    the UI offers goes through the same validation."""

    @pytest.mark.parametrize("worklist_id", DOT_ONLY)
    def test_it_is_not_offered_and_a_warning_names_it(
            self, logged_in_client, fresh_app, monkeypatch, worklist_id):
        _app, ctx, _db = fresh_app
        _run(ctx)
        _lims_on(ctx)
        monkeypatch.setattr(sample_api_module, "_api_get",
                            lambda url, api_key="": [{"id": "W1"}, {"id": worklist_id}])

        listed = logged_in_client.get(f"/runs/{RUN}/samples/worklists")

        assert f'<option value="{worklist_id}"' not in listed.text
        assert '<option value="W1"' in listed.text
        assert "not made only of dots" in listed.text
