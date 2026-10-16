"""A run whose Read 1 is 0, or that has no cycle counts at all, must not be
saved silently nor marked Ready, and no page may show counts the run does
not have (outside review of f490536, finding F2).

Read 1 = 0 was saved with a 200: ``min="1"`` on the field never runs,
because the fieldset is not a ``<form>`` and htmx validates only forms. The
checks had no cycle prerequisite -- every cycle check returns early when
there are no counts, and none looked at Read 1 -- so the run went Ready with
``Read1Cycles,0`` in its sheet, or an empty ``[Reads]`` section. Meanwhile
the run page and the wizard showed ``150/10/10/150`` for a run with no
counts at all, and pressing Continue would have saved those unseen.

Read 2 = 0 is a single-end run and stays allowed.
"""

import pytest

from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import (
    InstrumentPlatform, RunCycles, RunStatus, SequencingRun)
from seqsetup.services.validation import ValidationService

from .conftest import hold_edit_lock

ORIGIN = {"Origin": "http://testserver"}
RUN = "cycles-run"


def _run(ctx, cycles=RunCycles(151, 151, 10, 10), status=RunStatus.DRAFT):
    run = SequencingRun(
        id=RUN, run_name="Cycles", instrument_platform=InstrumentPlatform.NOVASEQ_X,
        flowcell_type="10B", run_cycles=cycles, status=status,
    )
    run.add_sample(Sample(id="s1", sample_id="PAT1", lanes=[1]))
    ctx.run_repo.save(run)
    hold_edit_lock(ctx, RUN)
    return run


def _stored(ctx):
    return ctx.run_repo.get_by_id(RUN)


def _post_cycles(ctx, client, read1="151", read2="151", index1="10", index2="10"):
    return client.post(f"/runs/{RUN}/cycles", headers=ORIGIN, data={
        "read1_cycles": read1, "read2_cycles": read2,
        "index1_cycles": index1, "index2_cycles": index2,
        "run_version": _stored(ctx).updated_at.isoformat()})


def _categories(run, ctx):
    result = ValidationService.validate_run(
        run, test_profile_repo=ctx.test_profile_repo,
        app_profile_repo=ctx.app_profile_repo, instrument_config=ctx.instrument_config)
    return {e.category for e in result.configuration_errors}


class TestReadOneIsRefused:
    def test_read_one_zero_is_refused_and_nothing_is_saved(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)
        before = _stored(ctx).run_cycles

        resp = _post_cycles(ctx, logged_in_client, read1="0")

        assert resp.status_code == 400, resp.text[:300]
        assert "Read 1" in resp.text
        assert _stored(ctx).run_cycles == before

    def test_the_refusal_says_what_is_allowed(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)

        resp = _post_cycles(ctx, logged_in_client, read1="0")

        assert resp.text == ("Read 1 cycles must be a whole number from 1 to 600: "
                            "a run with no Read 1 has nothing to sequence."), resp.text

    def test_control_read_two_zero_is_a_single_end_run_and_is_saved(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)

        resp = _post_cycles(ctx, logged_in_client, read2="0")

        assert resp.status_code == 200, resp.text[:300]
        assert _stored(ctx).run_cycles.read2_cycles == 0

    @pytest.mark.parametrize("field", ["index1", "index2"])
    def test_control_an_index_of_zero_is_still_saved(
            self, logged_in_client, fresh_app, field):
        _app, ctx, _db = fresh_app
        _run(ctx)

        resp = _post_cycles(ctx, logged_in_client, **{field: "0"})

        assert resp.status_code == 200, resp.text[:300]
        assert getattr(_stored(ctx).run_cycles, f"{field}_cycles") == 0


class TestTheCheckRefusesARunWithoutUsableCycles:
    def test_no_cycles_at_all_is_a_check_error(self, fresh_app):
        _app, ctx, _db = fresh_app
        run = _run(ctx, cycles=None)

        assert "prerequisite_run_cycles" in _categories(run, ctx)

    def test_read_one_zero_is_a_check_error(self, fresh_app):
        _app, ctx, _db = fresh_app
        run = _run(ctx, cycles=RunCycles(0, 151, 10, 10))

        assert "prerequisite_run_cycles" in _categories(run, ctx)

    def test_control_a_single_end_run_is_not(self, fresh_app):
        _app, ctx, _db = fresh_app
        run = _run(ctx, cycles=RunCycles(151, 0, 10, 10))

        assert "prerequisite_run_cycles" not in _categories(run, ctx)

    def test_mark_ready_is_refused_for_read_one_zero(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, cycles=RunCycles(0, 151, 10, 10))

        resp = logged_in_client.post(f"/runs/{RUN}/status/ready", headers=ORIGIN)

        assert _stored(ctx).status == RunStatus.DRAFT, "a run with no Read 1 went Ready"
        assert "Read 1" in resp.text, resp.text[:400]

    def test_mark_ready_is_refused_for_a_run_with_no_cycles(
            self, logged_in_client, fresh_app):
        """The refusal must NAME the missing counts: this fixture has other
        errors too, so a test that only reads the status would pass with the
        whole cycle prerequisite deleted (review of 9fac120, P3-3)."""
        _app, ctx, _db = fresh_app
        _run(ctx, cycles=None)

        resp = logged_in_client.post(f"/runs/{RUN}/status/ready", headers=ORIGIN)

        assert _stored(ctx).status == RunStatus.DRAFT, "a run with no cycles went Ready"
        assert "no cycle counts" in resp.text, resp.text[:500]


class TestNoPageShowsCyclesTheRunDoesNotHave:
    def test_the_run_page_says_not_set(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, cycles=None)

        page = logged_in_client.get(f"/runs/{RUN}")

        assert page.status_code == 200
        cycles_row = page.text[page.text.index("<dt>Cycles</dt>"):][:400]
        assert "not set" in cycles_row, cycles_row
        for shown in ("150", "10"):
            assert f"Read 1: {shown}" not in cycles_row, cycles_row

    def test_the_cycle_fields_offer_no_numbers_to_keep(self, logged_in_client, fresh_app):
        """The editable fields are the run's "Edit setup" page
        (/runs/new/step/1?run_id=...). Leaving them empty is what makes
        Continue refuse instead of saving 150/10/10/150 unseen."""
        _app, ctx, _db = fresh_app
        _run(ctx, cycles=None)

        page = logged_in_client.get(f"/runs/new/step/1?run_id={RUN}")

        assert page.status_code == 200
        start = page.text.index('name="read1_cycles"')
        field = page.text[start:start + 300]
        field = field[:field.index("</div>")] if "</div>" in field else field
        assert 'value=""' in field, (
            f"the Read 1 field pre-fills a count the run does not have: {field!r}")

    def test_control_the_run_page_shows_the_counts_it_has(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, cycles=RunCycles(151, 151, 10, 10))

        page = logged_in_client.get(f"/runs/{RUN}")

        cycles_row = page.text[page.text.index("<dt>Cycles</dt>"):][:400]
        assert "Read 1: 151" in cycles_row
        assert "not set" not in cycles_row

    def test_the_index_fields_pick_nothing(self, logged_in_client, fresh_app):
        """A select with nothing picked still posts its first option, so a
        run with no counts would have saved Index 1 = that option unseen.
        An empty "not set" option is picked instead, and Continue refuses."""
        _app, ctx, _db = fresh_app
        _run(ctx, cycles=None)

        page = logged_in_client.get(f"/runs/new/step/1?run_id={RUN}")

        for field in ("index1_cycles", "index2_cycles"):
            start = page.text.index(f'name="{field}"')
            block = page.text[start:page.text.index("</select>", start)]
            assert '<option value="" selected>not set</option>' in block, (
                f"{field} picks a count the run does not have: {block!r}")

    def test_continue_refuses_a_run_whose_cycles_were_never_set(
            self, logged_in_client, fresh_app):
        """What the empty fields post: nothing is saved and the field is named."""
        _app, ctx, _db = fresh_app
        _run(ctx, cycles=None)

        resp = _post_cycles(ctx, logged_in_client, read1="", read2="", index1="", index2="")

        assert resp.status_code == 400, resp.text[:300]
        assert "Read 1" in resp.text
        assert _stored(ctx).run_cycles is None


class TestTheStepBarAgreesWithTheCheck:
    """A fresh review found the Setup step saying "done" for a run with no
    cycle counts, and for Read 1 = 0: the step is keyed on the run name
    alone, so the one prerequisite the review added was not in it."""

    def _setup_step(self, client):
        page = client.get(f"/runs/{RUN}/step-bar")
        assert page.status_code == 200, page.text[:200]
        start = page.text.index('data-step="setup"')
        return page.text[start:start + 500]

    def test_no_cycles_is_not_a_done_setup(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, cycles=None)

        step = self._setup_step(logged_in_client)

        assert 'data-state="done"' not in step, step
        assert "cycle" in step.lower(), step

    def test_read_one_zero_is_not_a_done_setup(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, cycles=RunCycles(0, 151, 10, 10))

        step = self._setup_step(logged_in_client)

        assert 'data-state="done"' not in step, step

    def test_control_a_run_with_counts_has_a_done_setup(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, cycles=RunCycles(151, 151, 10, 10))

        step = self._setup_step(logged_in_client)

        assert 'data-state="done"' in step, step


class TestTheRefusalForAnUnsetCountSaysWhatToDo:
    """The index fields are a dropdown of 8, 10, 12, 17 and 24, so "must be a
    whole number from 0 to 600" named nothing the field can offer. And the
    fieldset posts on every change, so a run with no counts answers while
    the person is still typing Read 1: the message must say why."""

    def test_an_unset_index_says_it_is_not_set(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, cycles=None)

        resp = _post_cycles(ctx, logged_in_client, read1="151", read2="151",
                            index1="", index2="")

        assert resp.status_code == 400
        assert "is not set" in resp.text, resp.text
        assert "all four" in resp.text, resp.text
        assert "from 0 to 600" not in resp.text, resp.text

    def test_control_an_out_of_range_index_still_says_the_range(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)

        resp = _post_cycles(ctx, logged_in_client, index1="900")

        assert resp.status_code == 400
        assert "from 0 to 600" in resp.text, resp.text
