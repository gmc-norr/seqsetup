"""A Draft's flow cell and reagent kit must be ones its instrument offers
(project review of 7d970c7, 2026-10-21, found by four reviewers). A flow
cell the instrument does not list counted as one lane, so a NovaSeq X run
whose 10B a sync had renamed went Ready with lane 1 only in its sheet and no
"lanes without samples" question; the setup routes stored any name and any
kit, and a kit that is not a number became kit 1 with the cycles reset."""

import html

import pytest

from seqsetup.models.sequencing_run import RunStatus
from seqsetup.services.validation import ValidationService, clear_validation_cache

from .conftest import mark_ready, nothing_stored, run_version
from .test_index_safety_net import _seed_profiles
from .test_lane_out_of_range import EIGHT_LANES, ORIGIN, TWO_LANES, _draft


@pytest.fixture(autouse=True)
def _profiles(fresh_app):
    _app, ctx, _db = fresh_app
    _seed_profiles(ctx)


def _errors(ctx, run_id: str, category: str) -> list[str]:
    clear_validation_cache()
    run = ctx.run_repo.get_by_id(run_id)
    result = ValidationService.validate_run(
        run, test_profile_repo=ctx.test_profile_repo, app_profile_repo=ctx.app_profile_repo,
        instrument_config=ctx.instrument_config)
    return [e.message for e in result.configuration_errors if e.category == category]


class TestTheCheck:
    """A Draft on a flow cell or kit its instrument does not offer is an
    error, as a disabled instrument is."""

    def test_a_flowcell_the_instrument_does_not_list_is_an_error(self, fresh_app):
        _app, ctx, _db = fresh_app
        _draft(ctx, "gone", "10B-retired", s1_lanes=[1], s2_lanes=[1])

        assert _errors(ctx, "gone", "flowcell_not_offered") == [
            "Flowcell '10B-retired' is not one NovaSeq X Series offers. "
            "Pick a flowcell in Run Setup before marking the run ready."]

    def test_no_flowcell_is_an_error(self, fresh_app):
        _app, ctx, _db = fresh_app
        _draft(ctx, "none", "", s1_lanes=[1], s2_lanes=[1])

        assert _errors(ctx, "none", "flowcell_not_offered") == [
            "The run has no flowcell. "
            "Pick a flowcell in Run Setup before marking the run ready."]

    def test_a_listed_flowcell_and_kit_are_not(self, fresh_app):
        _app, ctx, _db = fresh_app
        _draft(ctx, "listed", EIGHT_LANES, s1_lanes=[1], s2_lanes=[1])

        assert _errors(ctx, "listed", "flowcell_not_offered") == []
        assert _errors(ctx, "listed", "reagent_kit_not_offered") == []

    def test_a_kit_the_flowcell_does_not_list_is_an_error(self, fresh_app):
        _app, ctx, _db = fresh_app
        run = _draft(ctx, "kit", EIGHT_LANES, s1_lanes=[1], s2_lanes=[1])
        run.reagent_cycles = 999
        ctx.run_repo.save(run)

        assert _errors(ctx, "kit", "reagent_kit_not_offered") == [
            "A 999-cycle reagent kit is not one NovaSeq X Series offers on the 10B flowcell. "
            "Pick a reagent kit in Run Setup before marking the run ready."]

    def test_a_ready_run_is_left_alone(self, fresh_app):
        """As for a disabled instrument: a Ready run keeps the exports made
        before the flow cell was withdrawn."""
        _app, ctx, _db = fresh_app
        run = _draft(ctx, "ready", "10B-retired", s1_lanes=[1], s2_lanes=[1])
        run.status = RunStatus.READY
        ctx.run_repo.save(run)

        assert _errors(ctx, "ready", "flowcell_not_offered") == []


class TestMarkReady:

    def test_it_refuses_a_flowcell_the_instrument_does_not_list(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _draft(ctx, "gone", "10B-retired", s1_lanes=[1], s2_lanes=[1])

        resp = mark_ready(logged_in_client, "gone", ORIGIN)

        assert "Flowcell '10B-retired' is not one NovaSeq X Series offers" in html.unescape(resp.text)
        stored = ctx.run_repo.get_by_id("gone")
        assert stored.status == RunStatus.DRAFT
        assert nothing_stored(ctx, stored)


class TestTheSetupRoutes:
    """The setup page offers only listed flow cells and kits; a page loaded
    before a sync, or a hand-made request, could send another."""

    def _post(self, client, ctx, path, data):
        return client.post(f"/runs/pick/{path}", headers=ORIGIN,
                           data={**data, "run_version": run_version(ctx, "pick")})

    def test_a_flowcell_the_instrument_does_not_list_is_refused(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _draft(ctx, "pick", EIGHT_LANES, s1_lanes=[1], s2_lanes=[1])

        resp = self._post(logged_in_client, ctx, "flowcell", {"flowcell_type": "NOT-A-FLOWCELL"})

        assert resp.status_code == 400
        assert resp.text == "That flowcell is not one NovaSeq X Series offers. Nothing was saved."
        assert ctx.run_repo.get_by_id("pick").flowcell_type == EIGHT_LANES

    def test_a_listed_flowcell_is_taken(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _draft(ctx, "pick", EIGHT_LANES, s1_lanes=[1], s2_lanes=[1])

        resp = self._post(logged_in_client, ctx, "flowcell", {"flowcell_type": TWO_LANES})

        assert resp.status_code == 200, resp.text
        assert ctx.run_repo.get_by_id("pick").flowcell_type == TWO_LANES

    @pytest.mark.parametrize("kit", ["999", "abc", "", "300.0", "٣٠٠"])
    def test_a_kit_the_flowcell_does_not_list_is_refused(self, logged_in_client, fresh_app, kit):
        _app, ctx, _db = fresh_app
        before = _draft(ctx, "pick", EIGHT_LANES, s1_lanes=[1], s2_lanes=[1])

        resp = self._post(logged_in_client, ctx, "reagent-kit", {"reagent_cycles": kit})

        assert resp.status_code == 400
        assert resp.text == ("That reagent kit is not one NovaSeq X Series offers on the 10B "
                             "flowcell. Nothing was saved.")
        after = ctx.run_repo.get_by_id("pick")
        assert (after.reagent_cycles, after.run_cycles) == (before.reagent_cycles, before.run_cycles)
        assert after.updated_at == before.updated_at

    def test_a_listed_kit_is_taken(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _draft(ctx, "pick", EIGHT_LANES, s1_lanes=[1], s2_lanes=[1])

        resp = self._post(logged_in_client, ctx, "reagent-kit", {"reagent_cycles": "200"})

        assert resp.status_code == 200, resp.text
        assert ctx.run_repo.get_by_id("pick").reagent_cycles == 200
