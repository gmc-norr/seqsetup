"""Run checks, group 1b, through the real routes (spec 2026-09-27)."""

import re

from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, SequencingRun

from .conftest import disable_repos


ORIGIN = {"Origin": "http://testserver"}


def _pair(i7: str, i5: str, name: str = "p1") -> IndexPair:
    return IndexPair(
        id=name, name=name,
        index1=Index(name=f"{name}-i7", sequence=i7, index_type=IndexType.I7),
        index2=Index(name=f"{name}-i5", sequence=i5, index_type=IndexType.I5),
    )


# No blocking error and no color-balance error: i7 CCCCCCCC lights both
# channels; NovaSeq X reads i5 as its reverse complement, so i5 GGGGGGGG is
# read as CCCCCCCC (i5 CCCCCCCC would be read GGGGGGGG: a dark-cycle error).
CLEAN_PAIR = ("CCCCCCCC", "GGGGGGGG")


def _seed(ctx, run_id: str, pairs=(("ATTACTCG", "TATAGCCT"),), platform=InstrumentPlatform.NOVASEQ_X,
          flowcell="10B", read1_pattern: str | None = None, lanes=(1,)) -> str:
    """A DRAFT run with one indexed sample per pair, in lane 1 only (a sample
    without lanes is in every lane: 8 on a 10B flowcell); 151/10/10/151 cycles."""
    run = SequencingRun(
        id=run_id, run_name="Checks", instrument_platform=platform, flowcell_type=flowcell,
        run_cycles=RunCycles(151, 151, 10, 10),
    )
    for n, (i7, i5) in enumerate(pairs, start=1):
        sample = Sample(sample_id=f"S{n}", index_pair=_pair(i7, i5, f"p{n}"), lanes=list(lanes))
        if read1_pattern:
            sample.read1_override_pattern = read1_pattern
        run.add_sample(sample)
    ctx.run_repo.save(run)
    return run.id


class TestOverrideCyclesRefusedAtSave:
    """A value that does not fit the run is refused when saved, typed or
    calculated ("Auto"); nothing is saved (F11)."""

    def test_typed_value_that_does_not_fit_is_refused(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _seed(ctx, "oc-typed")
        run = ctx.run_repo.get_by_id(run_id)
        sample = run.samples[0]
        before = (sample.override_cycles, run.updated_at)

        resp = logged_in_client.post(
            f"/runs/{run_id}/samples/{sample.id}/settings",
            data={"override_cycles": "Y151;I10;Y151"}, headers=ORIGIN,
        )

        assert resp.status_code == 400
        assert "does not fit this run" in resp.text
        after = ctx.run_repo.get_by_id(run_id)
        assert (after.samples[0].override_cycles, after.updated_at) == before

    def test_typed_value_that_fits_is_saved(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _seed(ctx, "oc-typed-ok")
        sample_id = ctx.run_repo.get_by_id(run_id).samples[0].id

        resp = logged_in_client.post(
            f"/runs/{run_id}/samples/{sample_id}/settings",
            data={"override_cycles": "Y151;I8N2;I8N2;Y151"}, headers=ORIGIN,
        )

        assert resp.status_code == 200
        assert ctx.run_repo.get_by_id(run_id).samples[0].override_cycles == "Y151;I8N2;I8N2;Y151"

    def test_calculated_value_that_does_not_fit_is_refused(self, logged_in_client, fresh_app):
        """A kit whose default read override is Y100 calculates
        Y100;I8N2;I8N2;Y151 on a 151-cycle run (Astra's review)."""
        _app, ctx, _db = fresh_app
        run_id = _seed(ctx, "oc-auto", read1_pattern="Y100")
        run = ctx.run_repo.get_by_id(run_id)
        sample = run.samples[0]
        before = (sample.override_cycles, run.updated_at)

        resp = logged_in_client.post(
            f"/runs/{run_id}/samples/{sample.id}/settings",
            data={"override_cycles": ""}, headers=ORIGIN,
        )

        assert resp.status_code == 400
        assert "calculated for S1" in resp.text
        assert "Y100;I8N2;I8N2;Y151" in resp.text
        after = ctx.run_repo.get_by_id(run_id)
        assert (after.samples[0].override_cycles, after.updated_at) == before

    def test_bulk_typed_value_that_does_not_fit_changes_no_sample(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _seed(ctx, "oc-bulk", pairs=(("ATTACTCG", "TATAGCCT"), ("TCCGGAGA", "ATAGAGGC")))
        run = ctx.run_repo.get_by_id(run_id)
        before = ([s.override_cycles for s in run.samples], run.updated_at)

        resp = logged_in_client.post(
            f"/runs/{run_id}/samples/set-override-cycles",
            data={"sample_ids": f'["{run.samples[0].id}", "{run.samples[1].id}"]',
                  "override_cycles": "Y151;I10;Y151"},
            headers=ORIGIN,
        )

        assert resp.status_code == 400
        after = ctx.run_repo.get_by_id(run_id)
        assert ([s.override_cycles for s in after.samples], after.updated_at) == before

    def test_bulk_auto_with_one_failing_sample_changes_no_sample(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _seed(ctx, "oc-bulk-auto", pairs=(("ATTACTCG", "TATAGCCT"), ("TCCGGAGA", "ATAGAGGC")))
        run = ctx.run_repo.get_by_id(run_id)
        run.samples[1].read1_override_pattern = "Y100"
        ctx.run_repo.save(run)
        run = ctx.run_repo.get_by_id(run_id)
        before = ([s.override_cycles for s in run.samples], run.updated_at)

        resp = logged_in_client.post(
            f"/runs/{run_id}/samples/set-override-cycles",
            data={"sample_ids": f'["{run.samples[0].id}", "{run.samples[1].id}"]',
                  "override_cycles": ""},
            headers=ORIGIN,
        )

        assert resp.status_code == 400
        assert "calculated for S2" in resp.text
        after = ctx.run_repo.get_by_id(run_id)
        assert ([s.override_cycles for s in after.samples], after.updated_at) == before

    def test_bulk_value_that_fits_is_saved_for_every_sample(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _seed(ctx, "oc-bulk-ok", pairs=(("ATTACTCG", "TATAGCCT"), ("TCCGGAGA", "ATAGAGGC")))
        run = ctx.run_repo.get_by_id(run_id)

        resp = logged_in_client.post(
            f"/runs/{run_id}/samples/set-override-cycles",
            data={"sample_ids": f'["{run.samples[0].id}", "{run.samples[1].id}"]',
                  "override_cycles": "Y151;I8N2;I8N2;Y151"},
            headers=ORIGIN,
        )

        assert resp.status_code == 200
        assert [s.override_cycles for s in ctx.run_repo.get_by_id(run_id).samples] == [
            "Y151;I8N2;I8N2;Y151"] * 2


class TestReadyMessageSlot:
    """Mark Ready's refusal goes to #ready-message, and a successful status
    change empties it; #error-banner is left to save failures."""

    def test_refusal_targets_the_ready_slot(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = SequencingRun(id="slot-refused", run_name="R", instrument_platform=InstrumentPlatform.NOVASEQ_X,
                            flowcell_type="10B", run_cycles=RunCycles(151, 151, 10, 10))
        ctx.run_repo.save(run)  # no samples: a real refusal

        resp = logged_in_client.post("/runs/slot-refused/status/ready", headers=ORIGIN)

        assert resp.headers.get("HX-Retarget") == "#ready-message"
        assert resp.headers.get("HX-Reswap") == "innerHTML"
        assert "Cannot mark ready" in resp.text

    def test_success_empties_the_ready_slot(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        run_id = _seed(ctx, "slot-ok", pairs=(CLEAN_PAIR,))

        resp = logged_in_client.post(f"/runs/{run_id}/status/ready", headers=ORIGIN)

        assert ctx.run_repo.get_by_id(run_id).status.value == "ready", resp.text[:400]
        assert re.search(r'<div id="ready-message" class="empty:hidden" hx-swap-oob="true"></div>', resp.text)

    def test_edit_page_has_the_ready_slot(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _seed(ctx, "slot-page")

        page = logged_in_client.get(f"/runs/{run_id}").text

        assert '<div id="ready-message" class="empty:hidden"></div>' in page
