"""A per-field route that is not sent its field writes nothing.

CLAUDE.md: "Partial updates update only what was submitted. Handlers
serving per-field HTMX inputs MUST check ``field in form`` before writing
— defaulting missing fields to empty and writing them back silently
destroys sibling values."

Five handlers used to write a default instead:

  - ``POST /runs/{id}/reagent-kit`` without ``reagent_cycles`` took the kit
    to be 1 cycle, reset all four cycle counts to the fallback defaults and
    recomputed EVERY sample's OverrideCycles — a typed UMI read
    ``U8Y143;I10;I10;Y151`` came back as ``Y151;I10;I10;Y151``, so the UMI
    bases would be read as Read 1. A clinical data change.
  - ``POST /runs/{id}/samples/set-override-cycles`` without
    ``override_cycles`` read it as the auto path and rewrote every selected
    sample's OverrideCycles from the run's cycles — the same typed UMI read
    lost the same way.
  - ``POST /runs/{id}/flowcell`` without ``flowcell_type`` stored "".
  - ``POST /runs/{id}/samples/set-lanes`` without ``lanes`` read it as "[]",
    which means "all lanes", and put the selected samples in every lane.
  - ``POST /runs/{id}/samples/set-test-id`` without ``test_id`` cleared the
    test and its version.

A sixth, ``POST /runs/{id}/bclconvert``, had the same fault and was fixed
the same way; it has since been removed, because no page ever posted to it
(see tests/integration/test_removed_bclconvert_route.py).

Every page that posts to these five always sends the field (a select sends
its value; the bulk panel and the Check panel use hidden inputs that
app.js fills in, including when a Clear or Auto button sends an empty
value). An absent field is therefore a request no page makes: it is
refused with 400 and nothing is saved. A field that IS sent, empty or not,
behaves as before.
"""

import json

from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import (
    InstrumentPlatform,
    RunCycles,
    SequencingRun,
)

from .conftest import run_version
from .conftest import hold_edit_lock

ORIGIN = {"Origin": "http://testserver"}
RUN_ID = "mf-run"
UMI_OVERRIDE = "U8Y143;I10;I10;Y151"
# What the auto path computes for a 10 bp / 10 bp pair on 151/151/10/10:
# the same reads, with the UMI segment gone.
AUTO_OVERRIDE = "Y151;I10;I10;Y151"


def _pair() -> IndexPair:
    return IndexPair(
        id="p1", name="p1",
        index1=Index(name="p1-i7", sequence="CCCCCCCCCC", index_type=IndexType.I7),
        index2=Index(name="p1-i5", sequence="GGGGGGGGGG", index_type=IndexType.I5),
    )


def _run(ctx, override_cycles=None, lanes=(1,), test_id="WGS", test_version="1",
         index_pair=None):
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
        index_pair=index_pair,
    ))
    ctx.run_repo.save(run)
    hold_edit_lock(ctx, run.id)
    return run


def _stored(ctx):
    return ctx.run_repo.get_by_id(RUN_ID)


class TestReagentKitNeedsItsField:
    """POST /runs/{id}/reagent-kit without reagent_cycles saves nothing."""

    def test_empty_post_is_refused_and_keeps_the_kit(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)

        response = logged_in_client.post(f"/runs/{RUN_ID}/reagent-kit", data={**{}, "run_version": run_version(ctx, RUN_ID)}, headers=ORIGIN)

        assert response.status_code == 400
        stored = _stored(ctx)
        assert stored.reagent_cycles == 300
        assert (stored.run_cycles.read1_cycles, stored.run_cycles.index1_cycles) == (151, 10)

    def test_typed_override_cycles_survive_an_empty_post(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, override_cycles=UMI_OVERRIDE)

        response = logged_in_client.post(f"/runs/{RUN_ID}/reagent-kit", data={**{}, "run_version": run_version(ctx, RUN_ID)}, headers=ORIGIN)

        assert response.status_code == 400
        assert _stored(ctx).get_sample("s1").override_cycles == UMI_OVERRIDE

    def test_a_sent_kit_is_still_saved_and_resets_the_cycles(self, logged_in_client, fresh_app):
        # A calculated value is recalculated; a typed one refuses the kit
        # (test_typed_override_cycles_kept.py).
        _app, ctx, _db = fresh_app
        _run(ctx, override_cycles=AUTO_OVERRIDE, index_pair=_pair())

        response = logged_in_client.post(
            f"/runs/{RUN_ID}/reagent-kit", data={**{"reagent_cycles": "200"}, "run_version": run_version(ctx, RUN_ID)}, headers=ORIGIN)

        assert response.status_code == 200
        stored = _stored(ctx)
        assert stored.reagent_cycles == 200
        assert stored.run_cycles == RunCycles(101, 101, 10, 10)
        assert stored.get_sample("s1").override_cycles == "Y101;I10;I10;Y101"


class TestFlowcellNeedsItsField:
    """POST /runs/{id}/flowcell without flowcell_type saves nothing."""

    def test_empty_post_is_refused_and_keeps_the_flowcell(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)

        response = logged_in_client.post(f"/runs/{RUN_ID}/flowcell", data={**{}, "run_version": run_version(ctx, RUN_ID)}, headers=ORIGIN)

        assert response.status_code == 400
        assert _stored(ctx).flowcell_type == "10B"

    def test_a_sent_flowcell_is_still_saved(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)

        response = logged_in_client.post(
            f"/runs/{RUN_ID}/flowcell", data={**{"flowcell_type": "25B"}, "run_version": run_version(ctx, RUN_ID)}, headers=ORIGIN)

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
            data={"sample_ids": json.dumps(["s1"]), "lanes": json.dumps([2]),
                  "target_lanes": json.dumps([[1]])},
            headers=ORIGIN)

        assert response.status_code == 200
        assert _stored(ctx).get_sample("s1").lanes == [2]

    def test_a_sent_empty_value_is_still_refused_as_malformed_json(
            self, logged_in_client, fresh_app):
        """A value that was sent is never treated as absent: an empty lanes
        field is refused for what it is, the unreadable JSON it was refused
        as before this check existed."""
        _app, ctx, _db = fresh_app
        _run(ctx, lanes=(1,))

        response = logged_in_client.post(
            f"/runs/{RUN_ID}/samples/set-lanes",
            data={"sample_ids": json.dumps(["s1"]), "lanes": ""}, headers=ORIGIN)

        assert response.status_code == 400
        assert response.text == "Invalid lanes JSON"
        assert _stored(ctx).get_sample("s1").lanes == [1]

    def test_a_sent_empty_lane_list_is_refused(self, logged_in_client, fresh_app):
        # No lane is never saved from the panel (test_lanes_never_empty.py).
        _app, ctx, _db = fresh_app
        _run(ctx, lanes=(1,))

        response = logged_in_client.post(
            f"/runs/{RUN_ID}/samples/set-lanes",
            data={"sample_ids": json.dumps(["s1"]), "lanes": json.dumps([])},
            headers=ORIGIN)

        assert response.status_code == 400
        assert _stored(ctx).get_sample("s1").lanes == [1]


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


class TestSetOverrideCyclesNeedsItsField:
    """POST /runs/{id}/samples/set-override-cycles without override_cycles saves nothing.

    The fifth site of the same pattern. An absent ``override_cycles`` read as
    "" became ``None``, which is the auto/recalculate path: every selected
    sample's OverrideCycles was rewritten from the run's cycles, so a typed
    UMI read ``U8Y143;I10;I10;Y151`` came back ``Y151;I10;I10;Y151`` and the
    UMI bases would be read as Read 1 — the reagent kit's data loss again.

    The bulk panel's hidden input always sends the field, "" among them when
    "Auto" is used, so a presence check cannot reach the auto path.
    """

    def test_post_with_the_samples_but_no_override_cycles_is_refused(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, override_cycles=UMI_OVERRIDE, index_pair=_pair())

        response = logged_in_client.post(
            f"/runs/{RUN_ID}/samples/set-override-cycles",
            data={"sample_ids": json.dumps(["s1"])}, headers=ORIGIN)

        assert response.status_code == 400
        assert _stored(ctx).get_sample("s1").override_cycles == UMI_OVERRIDE

    def test_empty_post_is_refused(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, override_cycles=UMI_OVERRIDE, index_pair=_pair())

        response = logged_in_client.post(
            f"/runs/{RUN_ID}/samples/set-override-cycles", data={}, headers=ORIGIN)

        assert response.status_code == 400
        assert _stored(ctx).get_sample("s1").override_cycles == UMI_OVERRIDE

    def test_a_sent_empty_value_still_recalculates(self, logged_in_client, fresh_app):
        """The auto path, unchanged: green before and after the refusal.

        This is the regression pin for "sent empty is not absent" — the
        panel's Auto button sends "" and must still recompute.
        """
        _app, ctx, _db = fresh_app
        _run(ctx, override_cycles=UMI_OVERRIDE, index_pair=_pair())

        response = logged_in_client.post(
            f"/runs/{RUN_ID}/samples/set-override-cycles",
            data={"sample_ids": json.dumps(["s1"]), "override_cycles": ""},
            headers=ORIGIN)

        assert response.status_code == 200
        assert _stored(ctx).get_sample("s1").override_cycles == AUTO_OVERRIDE

    def test_a_sent_value_is_still_stored(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, index_pair=_pair())

        response = logged_in_client.post(
            f"/runs/{RUN_ID}/samples/set-override-cycles",
            data={"sample_ids": json.dumps(["s1"]), "override_cycles": UMI_OVERRIDE},
            headers=ORIGIN)

        assert response.status_code == 200
        assert _stored(ctx).get_sample("s1").override_cycles == UMI_OVERRIDE
