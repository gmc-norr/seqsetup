"""A setup page that no longer shows the stored run cannot save over it.

The setup page's "Continue to Run" / "Back to Run" button posts the whole
form (name, description and all four cycle counts). A tab opened before
another window changed the run therefore reverted that window's run name
and cycles, and with the cycles every sample's OverrideCycles — a typed UMI
override was lost — and answered 200, as if nothing had happened. The page
now carries the version of the run it showed (its ``updated_at``) and the
save refuses a version that is not the stored one; each of the page's own
saves answers with the version it just wrote, so only another window's
change makes the page stale.
"""

import pytest

from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, SequencingRun

ORIGIN = {"Origin": "http://testserver"}
RUN = "stale-setup-run"
CHANGED = ("This run was changed in another window. Reload to see the latest version; "
           "nothing was saved.")

SETUP_FORM = {
    "run_name": "Old name", "run_description": "",
    "read1_cycles": "151", "read2_cycles": "151",
    "index1_cycles": "8", "index2_cycles": "8",
}


def _run(ctx, platform=InstrumentPlatform.NOVASEQ_X, flowcell="10B"):
    run = SequencingRun(
        id=RUN, run_name="Old name", instrument_platform=platform,
        flowcell_type=flowcell, run_cycles=RunCycles(151, 151, 8, 8),
    )
    run.add_sample(Sample(id="s1", sample_id="PAT1", lanes=[1]))
    ctx.run_repo.save(run)
    return run


def _stored(ctx):
    return ctx.run_repo.get_by_id(RUN)


def _version(ctx):
    return _stored(ctx).updated_at.isoformat()


def _another_window_changes_it(ctx):
    """What tab B does: rename, change the index cycles, set a UMI override."""
    stored = _stored(ctx)
    stored.run_name = "Tab B name"
    stored.run_cycles = RunCycles(151, 151, 10, 10)
    stored.samples[0].override_cycles = "Y151;U8I10;I10;Y151"
    stored.touch(updated_by="tabB")
    ctx.run_repo.save(stored)


def _state(run):
    return (run.run_name, run.run_cycles.index1_cycles, run.run_cycles.index2_cycles,
            run.samples[0].override_cycles)


class TestTheVersionIsOnThePage:
    def test_the_setup_page_carries_the_runs_version(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)

        resp = logged_in_client.get(f"/runs/new/step/1?run_id={RUN}")

        assert resp.status_code == 200
        assert 'name="run_version"' in resp.text
        assert _version(ctx) in resp.text


class TestAStaleTabIsRefused:
    def test_an_old_version_is_409_and_nothing_is_saved(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)
        stale = _version(ctx)
        _another_window_changes_it(ctx)
        before = _state(_stored(ctx))
        assert before == ("Tab B name", 10, 10, "Y151;U8I10;I10;Y151")

        resp = logged_in_client.post(
            f"/runs/{RUN}/setup", data={**SETUP_FORM, "run_version": stale}, headers=ORIGIN)

        assert resp.status_code == 409, resp.text[:300]
        assert CHANGED in resp.text
        assert _state(_stored(ctx)) == before

    def test_no_version_at_all_is_400_and_nothing_is_saved(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)
        _another_window_changes_it(ctx)
        before = _state(_stored(ctx))

        resp = logged_in_client.post(f"/runs/{RUN}/setup", data=SETUP_FORM, headers=ORIGIN)

        assert resp.status_code == 400, resp.text[:300]
        assert _state(_stored(ctx)) == before

    def test_an_empty_version_is_400_and_nothing_is_saved(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)
        before = _state(_stored(ctx))

        resp = logged_in_client.post(
            f"/runs/{RUN}/setup", data={**SETUP_FORM, "run_version": ""}, headers=ORIGIN)

        assert resp.status_code == 400, resp.text[:300]
        assert _state(_stored(ctx)) == before


class TestTheRightVersionStillSaves:
    def test_the_stored_version_saves_the_whole_form(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)

        resp = logged_in_client.post(
            f"/runs/{RUN}/setup",
            data={**SETUP_FORM, "run_name": "Typed here", "index1_cycles": "10",
                  "index2_cycles": "10", "run_version": _version(ctx)},
            headers=ORIGIN,
        )

        assert resp.status_code == 200, resp.text[:300]
        stored = _stored(ctx)
        assert (stored.run_name, stored.run_cycles.index1_cycles) == ("Typed here", 10)

    def test_the_answer_carries_the_version_it_wrote(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)

        resp = logged_in_client.post(
            f"/runs/{RUN}/setup",
            data={**SETUP_FORM, "run_name": "Typed here", "run_version": _version(ctx)},
            headers=ORIGIN,
        )

        assert 'hx-swap-oob' in resp.text
        assert _version(ctx) in resp.text


# Each save the setup page makes itself, with the form fields that page
# sends. Every one bumps the run's updated_at, so every one must answer with
# the version it wrote or the next Continue would be refused for no reason.
PAGE_SAVES = [
    ("name", {"run_name": "Named"}),
    ("cycles", {"read1_cycles": "151", "read2_cycles": "151",
                "index1_cycles": "10", "index2_cycles": "10"}),
    ("instrument", {"instrument_platform": "NovaSeq X Series"}),
    ("flowcell", {"flowcell_type": "10B"}),
    ("reagent-kit", {"reagent_cycles": "300"}),
    ("i5-workflow", {"i5_workflow": "Standard"}),
]


class TestThePagesOwnSavesKeepItFresh:
    @pytest.mark.parametrize("route,fields", PAGE_SAVES, ids=[r for r, _f in PAGE_SAVES])
    def test_the_answer_carries_the_new_version(
            self, logged_in_client, fresh_app, route, fields):
        _app, ctx, _db = fresh_app
        _run(ctx)

        resp = logged_in_client.post(
            f"/runs/{RUN}/{route}", data={**fields, "run_version": _version(ctx)},
            headers=ORIGIN)

        assert resp.status_code == 200, resp.text[:300]
        assert 'name="run_version"' in resp.text
        assert 'hx-swap-oob' in resp.text
        assert _version(ctx) in resp.text

    # Only the name save still takes a request without a version: the other
    # five refuse it (TestEveryPerFieldSaveChecksTheVersion, the night run's Q2).
    @pytest.mark.parametrize("route,fields", PAGE_SAVES[:1], ids=[r for r, _f in PAGE_SAVES[:1]])
    def test_a_request_without_a_version_gets_no_version_back(
            self, logged_in_client, fresh_app, route, fields):
        _app, ctx, _db = fresh_app
        _run(ctx)

        resp = logged_in_client.post(f"/runs/{RUN}/{route}", data=fields, headers=ORIGIN)

        assert resp.status_code == 200, resp.text[:300]
        assert "run_version" not in resp.text

    def test_a_tab_that_saves_then_continues_is_not_refused(self, logged_in_client, fresh_app):
        """The flow the browser suite walks: type a name (saved on change),
        then click Continue. The page uses the version the save answered
        with, so the Continue saves."""
        _app, ctx, _db = fresh_app
        _run(ctx)
        opened_with = _version(ctx)

        saved = logged_in_client.post(
            f"/runs/{RUN}/name", data={"run_name": "Typed here", "run_version": opened_with},
            headers=ORIGIN)
        assert saved.status_code == 200
        after_save = _version(ctx)
        assert after_save != opened_with
        assert after_save in saved.text

        resp = logged_in_client.post(
            f"/runs/{RUN}/setup",
            data={**SETUP_FORM, "run_name": "Typed here", "run_version": after_save},
            headers=ORIGIN)

        assert resp.status_code == 200, resp.text[:300]
        assert _stored(ctx).run_name == "Typed here"


class TestThePageSendsTheVersionWithEverySave:
    """Every control on the setup page that saves sends the version back, so
    the answer can refresh it; the Continue button's hx-include region holds
    the hidden field itself."""

    def test_each_control_sends_the_version(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        # MiSeq i100 Series is the one shipped instrument that lists more than
        # one i5 workflow, so it is the one whose setup page shows every
        # control -- the i5 workflow select included.
        _run(ctx, platform=InstrumentPlatform.MISEQ_I100, flowcell="5M")

        page = logged_in_client.get(f"/runs/new/step/1?run_id={RUN}").text

        for route in ("name", "cycles", "instrument", "flowcell", "reagent-kit", "i5-workflow"):
            post = f'hx-post="/runs/{RUN}/{route}"'
            assert post in page, post
            start_tag = page.split(post, 1)[1].split(">", 1)[0]
            assert "run-version" in start_tag, post

    def test_the_hidden_field_is_in_what_continue_sends(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)

        page = logged_in_client.get(f"/runs/new/step/1?run_id={RUN}").text

        included = page.split('id="run-setup-fields"', 1)[1].split('id="wizard-nav-step-', 1)[0]
        assert 'id="run-version"' in included
        assert 'hx-include="#run-setup-fields"' in page


def _per_field_saves():
    """Each per-field save the setup page makes, with a valid form for the
    NovaSeq X 10B run ``_run`` stores."""
    from seqsetup.data.instruments import get_reagent_kits_for_flowcell
    kit = get_reagent_kits_for_flowcell(InstrumentPlatform.NOVASEQ_X, "10B")[0]
    return [
        ("instrument", {"instrument_platform": "NovaSeq X Series"}),
        ("i5-workflow", {"i5_workflow": "Standard"}),
        ("flowcell", {"flowcell_type": "10B"}),
        ("reagent-kit", {"reagent_cycles": str(kit)}),
        ("cycles", {"read1_cycles": "151", "read2_cycles": "151",
                    "index1_cycles": "8", "index2_cycles": "8"}),
    ]


SAVES = ["instrument", "i5-workflow", "flowcell", "reagent-kit", "cycles"]


class TestEveryPerFieldSaveChecksTheVersion:
    """The night run's Q2, answered 2026-10-13: all six setup saves refuse a
    stale tab, not only "Continue" -- the cycles save rewrites every
    sample's OverrideCycles."""

    @pytest.mark.parametrize("route", SAVES)
    def test_an_old_version_is_409_and_nothing_is_saved(self, logged_in_client, fresh_app, route):
        _app, ctx, _db = fresh_app
        _run(ctx)
        stale = _version(ctx)
        _another_window_changes_it(ctx)
        before = _stored(ctx).to_dict()

        form = dict(_per_field_saves())[route]
        resp = logged_in_client.post(f"/runs/{RUN}/{route}", data={**form, "run_version": stale},
                                     headers=ORIGIN)

        assert resp.status_code == 409
        assert CHANGED in resp.text
        assert _stored(ctx).to_dict() == before
        assert _stored(ctx).samples[0].override_cycles == "Y151;U8I10;I10;Y151"

    @pytest.mark.parametrize("route", SAVES)
    def test_no_version_is_400_and_nothing_is_saved(self, logged_in_client, fresh_app, route):
        _app, ctx, _db = fresh_app
        _run(ctx)
        before = _stored(ctx).to_dict()

        form = dict(_per_field_saves())[route]
        resp = logged_in_client.post(f"/runs/{RUN}/{route}", data=form, headers=ORIGIN)

        assert resp.status_code == 400
        assert "did not send which version of the run it showed" in resp.text
        assert _stored(ctx).to_dict() == before

    @pytest.mark.parametrize("route", SAVES)
    def test_the_current_version_saves_and_hands_back_the_new_one(self, logged_in_client, fresh_app, route):
        _app, ctx, _db = fresh_app
        _run(ctx)
        form = dict(_per_field_saves())[route]

        resp = logged_in_client.post(f"/runs/{RUN}/{route}", data={**form, "run_version": _version(ctx)},
                                     headers=ORIGIN)

        assert resp.status_code == 200, resp.text[:300]
        assert _version(ctx) in resp.text
