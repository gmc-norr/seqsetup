"""Changing the instrument keeps a reagent kit the new flowcell offers.

A new run defaults to NovaSeq X Series / 10B / 300 cycles. Switching to an
instrument whose first flowcell does not offer 300 must not leave a
now-invalid kit selected — ``update_flowcell`` already applies this rule
when the flowcell itself changes; ``update_instrument`` must apply the same
rule for the flowcell it auto-selects, and must send the reagent-kit select
back out of band since ``#reagent-kit-select`` is not the element HTMX
targets for this request.

GAIIx's only flowcell ("Standard") offers ``[36, 50, 76, 100, 150]`` — no
300 — so switching to it is the "kit no longer offered" case. NovaSeq 6000's
first flowcell ("SP") offers ``[100, 200, 300, 500]``, which does include
300, so switching to it is the "kit still offered" case.
"""

from seqsetup.models.sequencing_run import InstrumentPlatform

ORIGIN = {"Origin": "http://testserver"}
GAIIX = "GAIIx"
NOVASEQ_6000 = "NovaSeq 6000"


def _new_run(client) -> str:
    r = client.post("/runs/new", headers=ORIGIN, follow_redirects=False)
    return r.headers["location"].split("run_id=", 1)[1]


class TestInstrumentChangeReplacesUnofferedKit:
    """GAIIx's only flowcell doesn't offer the 300-cycle kit a new run
    starts with, so the saved kit must move to one it does offer."""

    def test_reagent_cycles_moves_to_a_kit_the_flowcell_offers(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _new_run(logged_in_client)

        r = logged_in_client.post(
            f"/runs/{run_id}/instrument", data={"instrument_platform": GAIIX}, headers=ORIGIN)

        assert r.status_code == 200
        run = ctx.run_repo.get_by_id(run_id)
        assert run.instrument_platform == InstrumentPlatform.GAIIX
        assert run.flowcell_type == "Standard"
        assert run.reagent_cycles == 36
        assert run.reagent_cycles in [36, 50, 76, 100, 150]

    def test_response_sends_reagent_kit_select_out_of_band(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _new_run(logged_in_client)

        r = logged_in_client.post(
            f"/runs/{run_id}/instrument", data={"instrument_platform": GAIIX}, headers=ORIGIN)

        text = r.text
        assert 'id="reagent-kit-select"' in text
        assert 'hx-swap-oob="true"' in text
        assert '<option value="36" selected>36 cycles</option>' in text
        assert '<option value="50" >50 cycles</option>' in text
        assert '<option value="76" >76 cycles</option>' in text
        assert '<option value="100" >100 cycles</option>' in text
        assert '<option value="150" >150 cycles</option>' in text
        # Only the new flowcell's kits are listed — no stray 300 option.
        assert '<option value="300"' not in text

    def test_response_still_carries_the_cycle_total_out_of_band(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _new_run(logged_in_client)

        r = logged_in_client.post(
            f"/runs/{run_id}/instrument", data={"instrument_platform": GAIIX}, headers=ORIGIN)

        assert 'id="cycle-total" hx-swap-oob="true"' in r.text
        # run_cycles are untouched by the instrument change (322 total),
        # only reagent_cycles (the kit label) changes to 36.
        assert "Total: 322 cycles (36-cycle kit)" in r.text


class TestInstrumentChangeKeepsOfferedKit:
    """NovaSeq 6000's first flowcell still offers 300, so the run's saved
    kit is left alone."""

    def test_reagent_cycles_unchanged_when_still_offered(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _new_run(logged_in_client)

        r = logged_in_client.post(
            f"/runs/{run_id}/instrument", data={"instrument_platform": NOVASEQ_6000}, headers=ORIGIN)

        assert r.status_code == 200
        run = ctx.run_repo.get_by_id(run_id)
        assert run.instrument_platform == InstrumentPlatform.NOVASEQ_6000
        assert run.flowcell_type == "SP"
        assert run.reagent_cycles == 300
        assert '<option value="300" selected>300 cycles</option>' in r.text
