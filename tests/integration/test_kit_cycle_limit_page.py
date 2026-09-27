"""Too many cycles for the kit: the setup page shows the limit, and Mark
Ready refuses a run over it.

Limits come from ``reagent_kit_max_cycles`` in the instrument config (the
fallback YAML here; no instruments are synced in these tests).
"""

import pytest

from seqsetup.models.sequencing_run import RunStatus

from .conftest import mark_ready
from .test_smoke_validation import _make_ready_eligible_run

ORIGIN = {"Origin": "http://testserver"}
NOVASEQ_X = "NovaSeq X Series"
NEXTSEQ = "NextSeq 1000/2000"


@pytest.fixture
def kit_limit(monkeypatch):
    """Set reagent_kit_max_cycles for an instrument in the fallback YAML."""
    from seqsetup.data import instruments as instruments_module

    def set_limit(instrument, limits):
        config = dict(instruments_module._instruments[instrument])
        config["reagent_kit_max_cycles"] = limits
        monkeypatch.setitem(instruments_module._instruments, instrument, config)
    return set_limit


def _new_run(client) -> str:
    r = client.post("/runs/new", headers=ORIGIN, follow_redirects=False)
    return r.headers["location"].split("run_id=", 1)[1]


def _post_cycles(client, run_id, read1, read2, index1=10, index2=10):
    return client.post(
        f"/runs/{run_id}/cycles",
        data={"read1_cycles": read1, "read2_cycles": read2,
              "index1_cycles": index1, "index2_cycles": index2},
        headers=ORIGIN,
    )


class TestSetupPageTotal:
    """The total line shows the kit's limit when the config gives one."""

    def test_shows_limit(self, logged_in_client, kit_limit):
        kit_limit(NOVASEQ_X, {300: 338})
        run_id = _new_run(logged_in_client)
        page = logged_in_client.get(f"/runs/new/step/1?run_id={run_id}").text
        assert "Total: 322 / 338 max (300-cycle kit)" in page
        assert "Too many cycles for this kit." not in page

    def test_without_limit_unchanged(self, logged_in_client):
        run_id = _new_run(logged_in_client)
        page = logged_in_client.get(f"/runs/new/step/1?run_id={run_id}").text
        assert "Total: 322 / 300 cycles" in page

    def test_over_limit_after_cycle_change(self, logged_in_client, kit_limit):
        kit_limit(NOVASEQ_X, {300: 338})
        run_id = _new_run(logged_in_client)
        r = _post_cycles(logged_in_client, run_id, 301, 301)
        assert r.status_code == 200
        assert "Total: 622 / 338 max (300-cycle kit)" in r.text
        assert "Too many cycles for this kit." in r.text

    def test_kit_change_shows_that_kits_limit(self, logged_in_client, kit_limit):
        kit_limit(NOVASEQ_X, {200: 238, 300: 338})
        run_id = _new_run(logged_in_client)
        r = logged_in_client.post(
            f"/runs/{run_id}/reagent-kit", data={"reagent_cycles": "200"}, headers=ORIGIN)
        assert "/ 238 max (200-cycle kit)" in r.text


class TestTotalRefreshesWithInstrumentAndFlowcell:
    """Instrument and flowcell changes swap the total line out of band, since
    they can change which limit applies."""

    def test_instrument_change(self, logged_in_client, kit_limit):
        kit_limit(NEXTSEQ, {300: 340})
        run_id = _new_run(logged_in_client)
        r = logged_in_client.post(
            f"/runs/{run_id}/instrument", data={"instrument_platform": NEXTSEQ}, headers=ORIGIN)
        assert r.status_code == 200
        assert 'id="cycle-total" hx-swap-oob="true"' in r.text
        assert "Total: 322 / 340 max (300-cycle kit)" in r.text

    def test_flowcell_change(self, logged_in_client, kit_limit):
        kit_limit(NOVASEQ_X, {300: 338})
        run_id = _new_run(logged_in_client)
        r = logged_in_client.post(
            f"/runs/{run_id}/flowcell", data={"flowcell_type": "25B"}, headers=ORIGIN)
        assert r.status_code == 200
        assert 'id="cycle-total" hx-swap-oob="true"' in r.text
        assert "Total: 322 / 338 max (300-cycle kit)" in r.text


class TestMarkReadyRefusesTooManyCycles:
    """Too many cycles is an error, so Mark Ready refuses the run."""

    def test_refused_over_limit(self, logged_in_client, fresh_app, kit_limit):
        _app, ctx, _db = fresh_app
        kit_limit(NOVASEQ_X, {300: 310})
        run_id = _make_ready_eligible_run(ctx)  # 151 + 151 + 8 + 8 = 318
        r = logged_in_client.post(f"/runs/{run_id}/status/ready", headers=ORIGIN)
        assert "Too many cycles: 318" in r.text
        assert ctx.run_repo.get_by_id(run_id).status == RunStatus.DRAFT

    def test_same_run_without_limit_is_marked_ready(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _make_ready_eligible_run(ctx)
        mark_ready(logged_in_client, run_id, ORIGIN)
        assert ctx.run_repo.get_by_id(run_id).status == RunStatus.READY

    def test_check_panel_is_red_on_an_empty_run(self, logged_in_client, kit_limit):
        kit_limit(NOVASEQ_X, {300: 338})
        run_id = _new_run(logged_in_client)
        _post_cycles(logged_in_client, run_id, 301, 301)
        panel = logged_in_client.get(f"/runs/{run_id}/validate-panel").text
        assert "Too many cycles: 622" in panel
        assert "Add samples first" not in panel
