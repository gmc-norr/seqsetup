"""A per-field route that is not sent its field writes nothing.

CLAUDE.md: "Partial updates update only what was submitted. Handlers
serving per-field HTMX inputs MUST check ``field in form`` before writing
— defaulting missing fields to empty and writing them back silently
destroys sibling values."

Four handlers used to write a default instead:

  - ``POST /runs/{id}/reagent-kit`` without ``reagent_cycles`` took the kit
    to be 1 cycle, reset all four cycle counts to the fallback defaults and
    recomputed EVERY sample's OverrideCycles — a typed UMI read
    ``U8Y143;I10;I10;Y151`` came back as ``Y151;I10;I10;Y151``, so the UMI
    bases would be read as Read 1. A clinical data change.
  - ``POST /runs/{id}/flowcell`` without ``flowcell_type`` stored "".
  - ``POST /runs/{id}/samples/set-lanes`` without ``lanes`` read it as "[]",
    which means "all lanes", and put the selected samples in every lane.
  - ``POST /runs/{id}/samples/set-test-id`` without ``test_id`` cleared the
    test and its version.

Every page that posts to these four always sends the field (a select sends
its value; the bulk panel and the Check panel use hidden inputs that app.js
fills in, including when a Clear button sends an empty value). An absent
field is therefore a request no page makes: it is refused with 400 and
nothing is saved. A field that IS sent, empty or not, behaves as before.
"""

import json

from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import (
    InstrumentPlatform,
    RunCycles,
    SequencingRun,
)

ORIGIN = {"Origin": "http://testserver"}
RUN_ID = "mf-run"
UMI_OVERRIDE = "U8Y143;I10;I10;Y151"


def _run(ctx, override_cycles=None, lanes=(1,), test_id="WGS", test_version="1"):
    """A draft run on NovaSeq X / 10B / 300 cycles with one sample."""
    run = SequencingRun(
        id=RUN_ID,
        run_name="Missing field run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X,
        flowcell_type="10B",
        reagent_cycles=300,
        run_cycles=RunCycles(151, 151, 10, 10),
    )
    run.add_sample(Sample(
        id="s1",
        sample_id="PAT-1",
        lanes=list(lanes),
        test_id=test_id,
        test_version=test_version,
        override_cycles=override_cycles,
    ))
    ctx.run_repo.save(run)
    return run


def _stored(ctx):
    return ctx.run_repo.get_by_id(RUN_ID)


class TestReagentKitNeedsItsField:
    """POST /runs/{id}/reagent-kit without reagent_cycles saves nothing."""

    def test_empty_post_is_refused_and_keeps_the_kit(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)

        response = logged_in_client.post(f"/runs/{RUN_ID}/reagent-kit", data={}, headers=ORIGIN)

        assert response.status_code == 400
        stored = _stored(ctx)
        assert stored.reagent_cycles == 300
        assert (stored.run_cycles.read1_cycles, stored.run_cycles.index1_cycles) == (151, 10)

    def test_typed_override_cycles_survive_an_empty_post(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, override_cycles=UMI_OVERRIDE)

        response = logged_in_client.post(f"/runs/{RUN_ID}/reagent-kit", data={}, headers=ORIGIN)

        assert response.status_code == 400
        assert _stored(ctx).get_sample("s1").override_cycles == UMI_OVERRIDE

    def test_a_sent_kit_is_still_saved_and_resets_the_cycles(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, override_cycles=UMI_OVERRIDE)

        response = logged_in_client.post(
            f"/runs/{RUN_ID}/reagent-kit", data={"reagent_cycles": "200"}, headers=ORIGIN)

        assert response.status_code == 200
        stored = _stored(ctx)
        assert stored.reagent_cycles == 200
        assert stored.get_sample("s1").override_cycles != UMI_OVERRIDE


class TestFlowcellNeedsItsField:
    """POST /runs/{id}/flowcell without flowcell_type saves nothing."""

    def test_empty_post_is_refused_and_keeps_the_flowcell(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)

        response = logged_in_client.post(f"/runs/{RUN_ID}/flowcell", data={}, headers=ORIGIN)

        assert response.status_code == 400
        assert _stored(ctx).flowcell_type == "10B"

    def test_a_sent_flowcell_is_still_saved(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)

        response = logged_in_client.post(
            f"/runs/{RUN_ID}/flowcell", data={"flowcell_type": "25B"}, headers=ORIGIN)

        assert response.status_code == 200
        assert _stored(ctx).flowcell_type == "25B"


class TestSetLanesNeedsItsField:
    """POST /runs/{id}/samples/set-lanes without lanes saves nothing."""

    def test_post_with_the_samples_but_no_lanes_is_refused(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, lanes=(1,))

        response = logged_in_client.post(
            f"/runs/{RUN_ID}/samples/set-lanes",
            data={"sample_ids": json.dumps(["s1"])}, headers=ORIGIN)

        assert response.status_code == 400
        assert _stored(ctx).get_sample("s1").lanes == [1]

    def test_empty_post_is_refused(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, lanes=(1,))

        response = logged_in_client.post(
            f"/runs/{RUN_ID}/samples/set-lanes", data={}, headers=ORIGIN)

        assert response.status_code == 400
        assert _stored(ctx).get_sample("s1").lanes == [1]

    def test_sent_lanes_are_still_set(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, lanes=(1,))

        response = logged_in_client.post(
            f"/runs/{RUN_ID}/samples/set-lanes",
            data={"sample_ids": json.dumps(["s1"]), "lanes": json.dumps([2])},
            headers=ORIGIN)

        assert response.status_code == 200
        assert _stored(ctx).get_sample("s1").lanes == [2]

    def test_a_sent_empty_lane_list_is_still_stored_as_all_lanes(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, lanes=(1,))

        response = logged_in_client.post(
            f"/runs/{RUN_ID}/samples/set-lanes",
            data={"sample_ids": json.dumps(["s1"]), "lanes": json.dumps([])},
            headers=ORIGIN)

        assert response.status_code == 200
        assert _stored(ctx).get_sample("s1").lanes == []


class TestSetTestIdNeedsItsField:
    """POST /runs/{id}/samples/set-test-id without test_id saves nothing."""

    def test_post_with_the_samples_but_no_test_id_is_refused(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, test_id="WGS", test_version="1")

        response = logged_in_client.post(
            f"/runs/{RUN_ID}/samples/set-test-id",
            data={"sample_ids": json.dumps(["s1"])}, headers=ORIGIN)

        assert response.status_code == 400
        sample = _stored(ctx).get_sample("s1")
        assert (sample.test_id, sample.test_version) == ("WGS", "1")

    def test_empty_post_is_refused(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, test_id="WGS", test_version="1")

        response = logged_in_client.post(
            f"/runs/{RUN_ID}/samples/set-test-id", data={}, headers=ORIGIN)

        assert response.status_code == 400
        sample = _stored(ctx).get_sample("s1")
        assert (sample.test_id, sample.test_version) == ("WGS", "1")

    def test_a_sent_test_is_still_set(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, test_id="", test_version="")

        response = logged_in_client.post(
            f"/runs/{RUN_ID}/samples/set-test-id",
            data={"sample_ids": json.dumps(["s1"]), "test_id": "WGS", "test_version": "2"},
            headers=ORIGIN)

        assert response.status_code == 200
        sample = _stored(ctx).get_sample("s1")
        assert (sample.test_id, sample.test_version) == ("WGS", "2")

    def test_a_sent_empty_test_still_clears_the_test(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, test_id="WGS", test_version="1")

        response = logged_in_client.post(
            f"/runs/{RUN_ID}/samples/set-test-id",
            data={"sample_ids": json.dumps(["s1"]), "test_id": "", "test_version": ""},
            headers=ORIGIN)

        assert response.status_code == 200
        sample = _stored(ctx).get_sample("s1")
        assert (sample.test_id, sample.test_version) == ("", "")
