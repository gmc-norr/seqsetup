"""The run setup page (name, instrument, cycles) saves what the user sees.

Problems this covers:
- Cycles typed on the New Run page were never saved: the form aimed its
  response at #sample-table, which is not on that page, so htmx sent
  nothing. The run kept the reagent kit's defaults.
- Missing cycle fields were silently written as 0.
- "Continue to Run" was a plain link; a name typed just before clicking
  it could be lost.
- Setup could not be reopened after step 1, and a Ready run's setup page
  showed live controls that only failed on use.
- Cancel left an empty "Untitled Run" draft behind.
"""

import pytest

from seqsetup.models.sequencing_run import RunCycles, RunStatus

ORIGIN = {"Origin": "http://testserver"}
CYCLES = {"read1_cycles": "101", "read2_cycles": "0", "index1_cycles": "8", "index2_cycles": "8"}


def _make_run(ctx, status=RunStatus.DRAFT):
    run = ctx.run_repo.create_run("tester")
    run = ctx.run_repo.get_by_id(run.id)
    run.run_name = "Before"
    run.run_description = "Old description"
    run.run_cycles = RunCycles(151, 151, 10, 10)
    run.status = status
    ctx.run_repo.save(run)
    return run.id


def _cycles(ctx, run_id):
    rc = ctx.run_repo.get_by_id(run_id).run_cycles
    return (rc.read1_cycles, rc.read2_cycles, rc.index1_cycles, rc.index2_cycles)


class TestUpdateCycles:
    """POST /runs/{id}/cycles saves all four counts or nothing."""

    def test_saves_all_four_values(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _make_run(ctx)
        resp = logged_in_client.post(f"/runs/{run_id}/cycles", data=CYCLES, headers=ORIGIN)
        assert resp.status_code == 200
        assert _cycles(ctx, run_id) == (101, 0, 8, 8)

    def test_response_shows_new_total(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _make_run(ctx)
        resp = logged_in_client.post(f"/runs/{run_id}/cycles", data=CYCLES, headers=ORIGIN)
        assert "Total: 117 cycles" in resp.text

    def test_missing_field_rejected_and_nothing_saved(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _make_run(ctx)
        resp = logged_in_client.post(
            f"/runs/{run_id}/cycles", data={"read1_cycles": "101"}, headers=ORIGIN)
        assert resp.status_code == 400
        assert "Read 2" in resp.text
        assert _cycles(ctx, run_id) == (151, 151, 10, 10)

    @pytest.mark.parametrize("value", ["abc", "", "1.5", "-1", "601"])
    def test_bad_value_rejected_and_nothing_saved(self, logged_in_client, fresh_app, value):
        _app, ctx, _db = fresh_app
        run_id = _make_run(ctx)
        resp = logged_in_client.post(
            f"/runs/{run_id}/cycles", data={**CYCLES, "read1_cycles": value}, headers=ORIGIN)
        assert resp.status_code == 400
        assert "Read 1" in resp.text
        assert _cycles(ctx, run_id) == (151, 151, 10, 10)

    def test_ready_run_refused(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _make_run(ctx, RunStatus.READY)
        resp = logged_in_client.post(f"/runs/{run_id}/cycles", data=CYCLES, headers=ORIGIN)
        assert resp.status_code == 403
        assert _cycles(ctx, run_id) == (151, 151, 10, 10)


class TestSaveSetup:
    """POST /runs/{id}/setup (the Continue button) saves name, description
    and cycles together, or nothing."""

    def _form(self, **over):
        return {"run_name": "  After  ", "run_description": "New description", **CYCLES, **over}

    def test_saves_name_description_and_cycles(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _make_run(ctx)
        resp = logged_in_client.post(f"/runs/{run_id}/setup", data=self._form(), headers=ORIGIN)
        assert resp.status_code == 200
        run = ctx.run_repo.get_by_id(run_id)
        assert run.run_name == "After"
        assert run.run_description == "New description"
        assert _cycles(ctx, run_id) == (101, 0, 8, 8)

    def test_bad_cycles_save_nothing(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _make_run(ctx)
        resp = logged_in_client.post(
            f"/runs/{run_id}/setup", data=self._form(index1_cycles="x"), headers=ORIGIN)
        assert resp.status_code == 400
        run = ctx.run_repo.get_by_id(run_id)
        assert run.run_name == "Before"
        assert _cycles(ctx, run_id) == (151, 151, 10, 10)

    @pytest.mark.parametrize("field", ["run_name", "run_description"])
    def test_missing_text_field_rejected(self, logged_in_client, fresh_app, field):
        _app, ctx, _db = fresh_app
        run_id = _make_run(ctx)
        form = self._form()
        del form[field]
        resp = logged_in_client.post(f"/runs/{run_id}/setup", data=form, headers=ORIGIN)
        assert resp.status_code == 400
        run = ctx.run_repo.get_by_id(run_id)
        assert (run.run_name, run.run_description) == ("Before", "Old description")

    def test_ready_run_refused(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _make_run(ctx, RunStatus.READY)
        resp = logged_in_client.post(f"/runs/{run_id}/setup", data=self._form(), headers=ORIGIN)
        assert resp.status_code == 403
        assert ctx.run_repo.get_by_id(run_id).run_name == "Before"


class TestSameCyclesKeepSampleOverrides:
    """Changing cycles recomputes every sample's OverrideCycles. Re-saving
    the SAME cycles (e.g. "Back to Run" after only renaming) must not, or
    it would silently wipe overrides the user set by hand."""

    SAME = {"read1_cycles": "151", "read2_cycles": "151", "index1_cycles": "10", "index2_cycles": "10"}

    def _run_with_override(self, ctx):
        from seqsetup.models.sample import Sample
        run_id = _make_run(ctx)
        run = ctx.run_repo.get_by_id(run_id)
        run.add_sample(Sample(sample_id="S1", override_cycles="Y151;I10;I10;Y151"))
        ctx.run_repo.save(run)
        return run_id

    def _override(self, ctx, run_id):
        return ctx.run_repo.get_by_id(run_id).samples[0].override_cycles

    def test_setup_with_same_cycles_keeps_override(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = self._run_with_override(ctx)
        form = {"run_name": "Renamed", "run_description": "", **self.SAME}
        resp = logged_in_client.post(f"/runs/{run_id}/setup", data=form, headers=ORIGIN)
        assert resp.status_code == 200
        assert ctx.run_repo.get_by_id(run_id).run_name == "Renamed"
        assert self._override(ctx, run_id) == "Y151;I10;I10;Y151"

    def test_cycles_with_same_values_keeps_override(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = self._run_with_override(ctx)
        resp = logged_in_client.post(f"/runs/{run_id}/cycles", data=self.SAME, headers=ORIGIN)
        assert resp.status_code == 200
        assert self._override(ctx, run_id) == "Y151;I10;I10;Y151"

    def test_changed_cycles_still_recompute(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = self._run_with_override(ctx)
        resp = logged_in_client.post(f"/runs/{run_id}/cycles", data=CYCLES, headers=ORIGIN)
        assert resp.status_code == 200
        # An un-indexed sample has no computed override.
        assert self._override(ctx, run_id) is None


class TestSetupPage:
    """GET /runs/new/step/1 — the setup page itself."""

    def test_new_run_is_marked_new(self, logged_in_client):
        resp = logged_in_client.post("/runs/new", headers=ORIGIN, follow_redirects=False)
        assert resp.status_code == 303
        assert "new=1" in resp.headers["location"]

    def test_new_run_cancel_deletes_the_run(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _make_run(ctx)
        page = logged_in_client.get(f"/runs/new/step/1?run_id={run_id}&new=1").text
        assert f'hx-delete="/runs/{run_id}"' in page
        assert 'data-navigate-after="/"' in page
        assert "New Run" in page

    def test_existing_run_has_no_delete(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _make_run(ctx)
        page = logged_in_client.get(f"/runs/new/step/1?run_id={run_id}").text
        assert "hx-delete" not in page
        assert "Run Setup" in page
        assert "Back to Run" in page

    def test_continue_saves_before_leaving(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _make_run(ctx)
        page = logged_in_client.get(f"/runs/new/step/1?run_id={run_id}").text
        assert f'hx-post="/runs/{run_id}/setup"' in page
        assert f'data-navigate-after="/runs/{run_id}"' in page

    def test_cycle_form_saves_on_change(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _make_run(ctx)
        page = logged_in_client.get(f"/runs/new/step/1?run_id={run_id}").text
        form = page.split('id="cycle-config"', 1)[1].split("</fieldset>", 1)[0]
        assert f'hx-post="/runs/{run_id}/cycles"' in page
        assert 'hx-trigger="change"' in form
        assert "#sample-table" not in form
        assert "Apply Cycles" not in form

    @pytest.mark.parametrize("status", [RunStatus.READY, RunStatus.ARCHIVED])
    def test_locked_run_goes_to_run_page(self, logged_in_client, fresh_app, status):
        _app, ctx, _db = fresh_app
        run_id = _make_run(ctx, status)
        resp = logged_in_client.get(f"/runs/new/step/1?run_id={run_id}", follow_redirects=False)
        assert resp.status_code == 303
        assert resp.headers["location"] == f"/runs/{run_id}"


class TestEditSetupLink:
    """The run page links back to setup while the run is a draft."""

    def test_draft_run_page_links_to_setup(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _make_run(ctx)
        page = logged_in_client.get(f"/runs/{run_id}").text
        assert f'href="/runs/new/step/1?run_id={run_id}"' in page

    @pytest.mark.parametrize("status", [RunStatus.READY, RunStatus.ARCHIVED])
    def test_locked_run_page_has_no_setup_link(self, logged_in_client, fresh_app, status):
        _app, ctx, _db = fresh_app
        run_id = _make_run(ctx, status)
        page = logged_in_client.get(f"/runs/{run_id}").text
        assert "/runs/new/step/1" not in page
