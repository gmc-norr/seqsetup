"""Group A2 through the real routes (spec 2026-10-04): the run's i5 workflow
(§3), the i5 rule in the sheets and checks (§2, §4), and what happens when
the synced instrument records cannot be used (§5)."""

import html
import re

import pytest

from seqsetup.models.run_template import RunTemplate
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun


ORIGIN = {"Origin": "http://testserver"}
I100 = InstrumentPlatform.MISEQ_I100
NOVASEQ_X = InstrumentPlatform.NOVASEQ_X
EMPTY_CONTAINER = '<div id="i5-workflow-config" class="form-group empty:hidden"></div>'


def _draft(ctx, run_id: str, platform=I100, flowcell: str = "5M", reagent: int = 100,
           **fields) -> SequencingRun:
    run = SequencingRun(
        id=run_id, run_name=run_id, instrument_platform=platform, flowcell_type=flowcell,
        reagent_cycles=reagent, run_cycles=RunCycles(151, 151, 10, 10), **fields,
    )
    ctx.run_repo.save(run)
    return ctx.run_repo.get_by_id(run_id)


def _workflow_select(html: str) -> str:
    """The i5 workflow container, as sent."""
    match = re.search(r'<div id="i5-workflow-config".*?</div>', html, re.S)
    assert match, html[:400]
    return match.group(0)


def _options(html: str) -> list[str]:
    return [re.sub(r"\s+", " ", text).strip()
            for text in re.findall(r"<option[^>]*>(.*?)</option>", _workflow_select(html), re.S)]


class TestANewRunGetsTheStandardWorkflow:
    """New Run and an instrument change store the instrument's standard name."""

    def test_new_run_stores_the_standard_name(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        resp = logged_in_client.post("/runs/new", headers=ORIGIN, follow_redirects=False)
        run_id = resp.headers["location"].split("run_id=", 1)[1]
        run = ctx.run_repo.get_by_id(run_id)
        assert run.instrument_platform == NOVASEQ_X
        assert run.i5_workflow == "Standard"

    def test_an_instrument_change_stores_the_new_standard_name(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = _draft(ctx, "a2-change", platform=NOVASEQ_X, flowcell="10B", reagent=300,
                     i5_workflow="Standard")

        resp = logged_in_client.post(f"/runs/{run.id}/instrument",
                                     data={"instrument_platform": I100.value}, headers=ORIGIN)

        assert resp.status_code == 200
        assert ctx.run_repo.get_by_id(run.id).i5_workflow == "Index-first"
        assert 'hx-swap-oob="true"' in _workflow_select(resp.text)
        assert _options(resp.text) == ["Index-first (standard)", "Read-first"]

    def test_a_change_to_a_one_workflow_instrument_empties_the_select(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = _draft(ctx, "a2-change-back", i5_workflow="Read-first")

        resp = logged_in_client.post(f"/runs/{run.id}/instrument",
                                     data={"instrument_platform": NOVASEQ_X.value},
                                     headers=ORIGIN)

        assert resp.status_code == 200
        assert ctx.run_repo.get_by_id(run.id).i5_workflow == "Standard"
        assert _workflow_select(resp.text) == (
            '<div id="i5-workflow-config" class="form-group empty:hidden" '
            'hx-swap-oob="true"></div>'
        )


class TestPickingAWorkflow:
    """POST /runs/{id}/i5-workflow saves only a name the instrument lists."""

    def test_a_listed_name_is_saved(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = _draft(ctx, "a2-pick", i5_workflow="Index-first")

        resp = logged_in_client.post(f"/runs/{run.id}/i5-workflow",
                                     data={"i5_workflow": "Read-first"}, headers=ORIGIN)

        assert resp.status_code == 200
        assert ctx.run_repo.get_by_id(run.id).i5_workflow == "Read-first"
        assert 'value="Read-first" selected' in resp.text

    @pytest.mark.parametrize("value", ["read-first", "Standard", "Read-first ", ""])
    def test_another_name_is_refused(self, logged_in_client, fresh_app, value):
        _app, ctx, _db = fresh_app
        run = _draft(ctx, "a2-pick-bad", i5_workflow="Index-first")
        before = ctx.run_repo.get_by_id(run.id).updated_at

        resp = logged_in_client.post(f"/runs/{run.id}/i5-workflow",
                                     data={"i5_workflow": value}, headers=ORIGIN)

        assert resp.status_code == 400
        assert (f"{value!r} is not an i5 workflow of MiSeq i100 Series "
                f"(it has: Index-first, Read-first). Nothing was saved.") in html.unescape(resp.text)
        after = ctx.run_repo.get_by_id(run.id)
        assert (after.i5_workflow, after.updated_at) == ("Index-first", before)

    def test_a_missing_field_is_refused(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = _draft(ctx, "a2-pick-none", i5_workflow="Index-first")
        before = ctx.run_repo.get_by_id(run.id).updated_at

        resp = logged_in_client.post(f"/runs/{run.id}/i5-workflow", data={}, headers=ORIGIN)

        assert resp.status_code == 400
        assert "No i5 workflow was sent. Nothing was saved." in resp.text
        assert ctx.run_repo.get_by_id(run.id).updated_at == before

    def test_a_ready_run_cannot_be_changed(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = _draft(ctx, "a2-pick-ready", i5_workflow="Index-first")
        run.status = RunStatus.READY
        ctx.run_repo.save(run)

        resp = logged_in_client.post(f"/runs/{run.id}/i5-workflow",
                                     data={"i5_workflow": "Read-first"}, headers=ORIGIN)

        assert resp.status_code == 403
        assert ctx.run_repo.get_by_id(run.id).i5_workflow == "Index-first"


class TestTheSetupPage:
    """The select shows for an instrument with more than one workflow, or a
    workflow the instrument does not list; otherwise the container is empty."""

    def _page(self, client, run_id: str) -> str:
        resp = client.get(f"/runs/new/step/1?run_id={run_id}")
        assert resp.status_code == 200
        return resp.text

    def test_two_workflows_show_the_select(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = _draft(ctx, "a2-page-i100", i5_workflow="Read-first")
        html = self._page(logged_in_client, run.id)
        assert _options(html) == ["Index-first (standard)", "Read-first"]
        assert 'value="Read-first" selected' in _workflow_select(html)

    def test_a_run_from_before_shows_the_standard_one(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = _draft(ctx, "a2-page-old")
        assert 'value="Index-first" selected' in _workflow_select(self._page(logged_in_client, run.id))

    def test_one_workflow_shows_nothing(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = _draft(ctx, "a2-page-nx", platform=NOVASEQ_X, flowcell="10B", reagent=300,
                     i5_workflow="Standard")
        assert _workflow_select(self._page(logged_in_client, run.id)) == EMPTY_CONTAINER

    def test_an_unlisted_workflow_is_shown_as_not_available(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = _draft(ctx, "a2-page-gone", platform=NOVASEQ_X, flowcell="10B", reagent=300,
                     i5_workflow="Old name")
        html = self._page(logged_in_client, run.id)
        assert _options(html) == ["Standard (standard)", "Old name (not available)"]
        assert 'value="Old name" selected' in _workflow_select(html)


class TestTheRunPage:
    """The Setup panel names the workflow where there is a choice."""

    def _panel(self, client, run_id: str) -> str:
        html = client.get(f"/runs/{run_id}").text
        return re.search(r'<fieldset id="run-config-panel".*?</fieldset>', html, re.S).group(0)

    def test_it_shows_the_workflow_of_an_instrument_with_two(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = _draft(ctx, "a2-panel-i100", i5_workflow="Read-first")
        assert "<dt>i5 workflow</dt><dd>Read-first</dd>" in self._panel(logged_in_client, run.id)

    def test_it_shows_no_line_for_one_workflow(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = _draft(ctx, "a2-panel-nx", platform=NOVASEQ_X, flowcell="10B", reagent=300,
                     i5_workflow="Standard")
        assert "i5 workflow" not in self._panel(logged_in_client, run.id)

    def test_it_shows_an_unlisted_workflow(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = _draft(ctx, "a2-panel-gone", platform=NOVASEQ_X, flowcell="10B", reagent=300,
                     i5_workflow="Old name")
        assert ("<dt>i5 workflow</dt><dd>Old name (not available)</dd>"
                in self._panel(logged_in_client, run.id))


class TestCopiesKeepTheWorkflow:
    """A duplicate, a template and a run from a template keep the workflow."""

    def _new_run_id(self, resp) -> str:
        assert resp.status_code == 303, resp.text[:300]
        return resp.headers["location"].rsplit("/", 1)[1]

    def test_a_duplicate_keeps_it(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = _draft(ctx, "a2-dup", i5_workflow="Read-first")
        resp = logged_in_client.post(f"/runs/{run.id}/duplicate",
                                     data={"include_samples": "false"}, headers=ORIGIN,
                                     follow_redirects=False)
        assert ctx.run_repo.get_by_id(self._new_run_id(resp)).i5_workflow == "Read-first"

    def test_a_template_and_its_runs_keep_it(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = _draft(ctx, "a2-tpl", i5_workflow="Read-first")
        resp = logged_in_client.post(
            f"/runs/{run.id}/save-as-template",
            data={"name": "A2 template", "description": "", "scaffold_sample_ids": "[]"},
            headers=ORIGIN, follow_redirects=False,
        )
        assert resp.status_code == 303
        (template,) = ctx.run_template_repo.list_all()
        assert template.i5_workflow == "Read-first"

        resp = logged_in_client.post(f"/runs/new/from-template/{template.id}", headers=ORIGIN,
                                     follow_redirects=False)
        assert ctx.run_repo.get_by_id(self._new_run_id(resp)).i5_workflow == "Read-first"

    def test_a_template_with_an_unlisted_workflow_is_refused(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        template = RunTemplate(name="Old", instrument_platform=I100, flowcell_type="5M",
                               reagent_cycles=100, i5_workflow="Old name")
        ctx.run_template_repo.save(template)
        before = len(ctx.run_repo.list_all())

        resp = logged_in_client.post(f"/runs/new/from-template/{template.id}", headers=ORIGIN,
                                     follow_redirects=False)

        assert resp.status_code == 400
        assert resp.text == (
            "Old name is no longer an i5 workflow of MiSeq i100 Series; "
            "this template cannot be used."
        )
        assert len(ctx.run_repo.list_all()) == before
