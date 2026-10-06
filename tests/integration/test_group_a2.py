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


INDEX2_ORDER_RULE = (
    "Index 2 in OverrideCycles is written in reading order in SeqSetup: the index first, "
    "then the masked cycles (for example I8N2). SeqSetup writes it the way the instrument "
    "needs."
)
INDEX2_ORDER_HINT = "Index 2 in reading order: the index first, then masked cycles (for example I8N2)"


def _indexed_draft(ctx, run_id: str, platform=NOVASEQ_X, override: str = "",
                   i5: str = "TATAGCCT", index2_cycles=None) -> SequencingRun:
    from seqsetup.models.index import Index, IndexPair, IndexType
    from seqsetup.models.sample import Sample
    flowcell = {NOVASEQ_X: "10B", InstrumentPlatform.NEXTSEQ_500_550: "High"}[platform]
    run = SequencingRun(id=run_id, run_name=run_id, instrument_platform=platform,
                        flowcell_type=flowcell, run_cycles=RunCycles(151, 151, 10, 10))
    run.add_sample(Sample(sample_id="S1", lanes=[1], override_cycles=override or None,
                          index2_cycles=index2_cycles,
                          index_pair=IndexPair(
                              id="p1", name="p1",
                              index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
                              index2=Index(name="i5", sequence=i5, index_type=IndexType.I5),
                          )))
    ctx.run_repo.save(run)
    return ctx.run_repo.get_by_id(run_id)


PLATFORMS = [pytest.param(NOVASEQ_X, id="novaseq-x"),
             pytest.param(InstrumentPlatform.NEXTSEQ_500_550, id="nextseq-500")]


class TestATypedIndex2MaskedFirstIsRefused:
    """N or U before the first I in the Index 2 part is refused at the input
    and at Mark Ready, on every instrument (spec §2)."""

    @pytest.mark.parametrize("platform", PLATFORMS)
    def test_the_sample_input_refuses_it(self, logged_in_client, fresh_app, platform):
        _app, ctx, _db = fresh_app
        run = _indexed_draft(ctx, "a2-typed-row", platform)
        resp = logged_in_client.post(
            f"/runs/{run.id}/samples/{run.samples[0].id}/settings",
            data={"override_cycles": "Y151;I8N2;N2I8;Y151"}, headers=ORIGIN,
        )
        assert resp.status_code == 400
        assert f"{INDEX2_ORDER_RULE} Nothing was saved." in html.unescape(resp.text)
        assert ctx.run_repo.get_by_id(run.id).samples[0].override_cycles is None

    @pytest.mark.parametrize("platform", PLATFORMS)
    def test_the_bulk_input_refuses_it(self, logged_in_client, fresh_app, platform):
        _app, ctx, _db = fresh_app
        run = _indexed_draft(ctx, "a2-typed-bulk", platform)
        resp = logged_in_client.post(
            f"/runs/{run.id}/samples/set-override-cycles",
            data={"sample_ids": f'["{run.samples[0].id}"]', "override_cycles": "Y151;I8N2;U2I8;Y151"},
            headers=ORIGIN,
        )
        assert resp.status_code == 400
        assert f"{INDEX2_ORDER_RULE} Nothing was saved." in html.unescape(resp.text)
        assert ctx.run_repo.get_by_id(run.id).samples[0].override_cycles is None

    @pytest.mark.parametrize("value", ["Y151;I8N2;I8N2;Y151", "Y151;I8N2;N10;Y151"])
    def test_the_index_first_is_saved(self, logged_in_client, fresh_app, value):
        _app, ctx, _db = fresh_app
        run = _indexed_draft(ctx, "a2-typed-ok")
        resp = logged_in_client.post(
            f"/runs/{run.id}/samples/{run.samples[0].id}/settings",
            data={"override_cycles": value}, headers=ORIGIN,
        )
        assert resp.status_code == 200
        assert ctx.run_repo.get_by_id(run.id).samples[0].override_cycles == value

    @pytest.mark.parametrize("platform", PLATFORMS)
    def test_mark_ready_refuses_a_stored_one(self, logged_in_client, fresh_app, platform):
        from .conftest import disable_repos
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        run = _indexed_draft(ctx, "a2-typed-ready", platform, override="Y151;I8N2;N2I8;Y151")

        resp = logged_in_client.post(f"/runs/{run.id}/status/ready", headers=ORIGIN)

        assert resp.headers.get("HX-Retarget") == "#ready-message"
        assert INDEX2_ORDER_RULE in html.unescape(resp.text)
        assert ctx.run_repo.get_by_id(run.id).status == RunStatus.DRAFT

    def test_the_inputs_say_so(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = _indexed_draft(ctx, "a2-typed-hint")
        page = html.unescape(logged_in_client.get(f"/runs/{run.id}").text)
        assert page.count(f'title="{INDEX2_ORDER_HINT}"') == 2


class TestAShortenedI5OnAReversedReadIsRefused:
    """An i5 used shorter than it is stored, inside a longer Index 2 read,
    stops Mark Ready where the i5 is read reversed (spec §2) — since group A3,
    by the length rule, on every instrument (spec 2026-10-05 group A3, §4)."""

    @pytest.mark.parametrize("platform", PLATFORMS)
    def test_mark_ready_refuses_it(self, logged_in_client, fresh_app, platform):
        from .conftest import disable_repos
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        run = _indexed_draft(ctx, "a2-short-i5", platform, i5="ACGGTTCAAG", index2_cycles=8)

        resp = logged_in_client.post(f"/runs/{run.id}/status/ready", headers=ORIGIN)

        assert resp.headers.get("HX-Retarget") == "#ready-message"
        assert (
            "1 sample(s) have an index whose length differs from the index cycles their "
            "OverrideCycles reads: S1 (i5: 10 bases, 8 read)."
        ) in html.unescape(resp.text)
        assert ctx.run_repo.get_by_id(run.id).status == RunStatus.DRAFT


class TestProfilesCannotChangeTheRule:
    """A BCL Convert profile with one of the four settings is refused at sync,
    and a stored one stops Mark Ready (spec §2)."""

    def test_the_sync_refuses_it(self, fresh_app, monkeypatch):
        from .test_sheet_followups import _app_profile_yaml, _sync
        _app, ctx, _db = fresh_app
        bad = _app_profile_yaml("Bad", '"4.3.6"').replace(
            "Settings:\n", "Settings:\n  OverrideReads: Y151;I10;I10;Y151\n")
        ok, message, _count = _sync(ctx, monkeypatch, {
            "Good.yaml": _app_profile_yaml("Good", '"4.3.6"'),
            "Bad.yaml": bad,
        })
        assert ok, message
        assert [p.name for p in ctx.app_profile_repo.list_all()] == ["Good"]

    def test_a_stored_one_stops_mark_ready(self, logged_in_client, fresh_app):
        from .test_sheet_safety import _seed_draft, _seed_synced_profile
        _app, ctx, _db = fresh_app
        _seed_synced_profile(ctx, "BCLConvert",
                             {"SoftwareVersion": "4.3.6", "RunInfoIndex2ReverseComplement": "1"})
        run_id = _seed_draft(ctx, "a2-profile-key", test_id="GUARD_T")

        resp = logged_in_client.post(f"/runs/{run_id}/status/ready", headers=ORIGIN)

        assert resp.status_code == 500
        assert resp.text == "Failed to generate exports"
        assert ctx.run_repo.get_by_id(run_id).status == RunStatus.DRAFT



REMEDY = (
    "Update the instrument files and run a config sync with Also sync instruments on "
    "(Admin > Config Sync)."
)
OLD_FORMAT_MESSAGE = (
    "The synced instrument settings cannot be used: NovaSeq X Series: i5_read_orientation: "
    "Replaced by i5_workflows and runinfo_marks_i5_reversed; see Instruments in the admin "
    "guide; samplesheet_v2_i5_orientation: Replaced by i5_workflows and "
    "runinfo_marks_i5_reversed; see Instruments in the admin guide; i5_workflows: Required: "
    "the instrument's i5 workflows (name and i5_read_orientation each), the standard one "
    f"first; runinfo_marks_i5_reversed: Required: true or false. {REMEDY}"
)
DATABASE_MESSAGE = (
    "The synced instrument settings could not be read from the database. "
    "Try again, or ask an administrator to check the database."
)


def _store_old_format_record(ctx) -> None:
    """A NovaSeq X record as an older SeqSetup stored it: the two old keys,
    neither new fact."""
    from seqsetup.data import instruments as instruments_module
    from .test_group_1c import _sync
    _sync(ctx, names=(NOVASEQ_X.value,))
    doc = ctx.instrument_definition_repo.collection.find_one({"name": NOVASEQ_X.value})
    ctx.instrument_definition_repo.collection.update_one({"_id": doc["_id"]}, {
        "$unset": {"i5_workflows": "", "runinfo_marks_i5_reversed": ""},
        "$set": {"i5_read_orientation": "reverse-complement",
                 "samplesheet_v2_i5_orientation": "forward"},
    })
    instruments_module.clear_synced_instruments_cache()


def _store_damaged_record(ctx) -> None:
    """A NovaSeq X record whose flowcells are not mappings."""
    from seqsetup.data import instruments as instruments_module
    from .test_group_1c import _sync
    _sync(ctx, names=(NOVASEQ_X.value,))
    ctx.instrument_definition_repo.collection.update_one(
        {"name": NOVASEQ_X.value}, {"$set": {"flowcells": ["10B"]}})
    instruments_module.clear_synced_instruments_cache()


def _denials(ctx) -> list:
    return ctx.audit_event_repo.search(limit=50, event_prefix="run.status.denied")


class TestAnInstrumentLeftOutOfTheSync:
    """While synced records exist, an instrument not among them has no
    settings, is called "not among the synced instruments" (never
    "disabled"), and its runs cannot be marked Ready; their pages open."""

    def _setup(self, fresh_app):
        from .test_group_1c import _clean_run, _sync
        _app, ctx, _db = fresh_app
        _sync(ctx, names=(NOVASEQ_X.value,))
        run = _clean_run(ctx, "a2-left-out", platform=I100, flowcell="5M")
        return ctx, run

    def test_mark_ready_is_refused(self, logged_in_client, fresh_app):
        from .conftest import disable_repos
        ctx, run = self._setup(fresh_app)
        disable_repos(ctx, "test_profile", "app_profile")

        resp = logged_in_client.post(f"/runs/{run.id}/status/ready", headers=ORIGIN)

        assert resp.headers.get("HX-Retarget") == "#ready-message"
        text = html.unescape(resp.text)
        assert ("MiSeq i100 Series is not among the synced instruments. "
                "Pick another instrument in Run Setup.") in text
        assert "disabled" not in text
        assert ctx.run_repo.get_by_id(run.id).status == RunStatus.DRAFT

    def test_its_pages_open(self, logged_in_client, fresh_app):
        from .test_group_1c import _platform_options
        ctx, run = self._setup(fresh_app)
        assert logged_in_client.get(f"/runs/{run.id}").status_code == 200
        setup = logged_in_client.get(f"/runs/new/step/1?run_id={run.id}")
        assert setup.status_code == 200
        assert (I100.value, True, f"{I100.value} (not available)") in _platform_options(setup.text)
        assert _workflow_select(setup.text) == EMPTY_CONTAINER

    def test_the_instrument_route_refuses_it(self, logged_in_client, fresh_app):
        from .test_group_1c import _clean_run
        ctx, _run = self._setup(fresh_app)
        run = _clean_run(ctx, "a2-left-out-change")
        before = ctx.run_repo.get_by_id(run.id).updated_at

        resp = logged_in_client.post(f"/runs/{run.id}/instrument",
                                     data={"instrument_platform": I100.value}, headers=ORIGIN)

        assert resp.status_code == 400
        assert ("MiSeq i100 Series is not among the synced instruments. The run still uses "
                "NovaSeq X Series.") in html.unescape(resp.text)
        assert ctx.run_repo.get_by_id(run.id).updated_at == before

    def test_a_template_on_it_is_refused(self, logged_in_client, fresh_app):
        ctx, _run = self._setup(fresh_app)
        template = RunTemplate(name="Left out", instrument_platform=I100, flowcell_type="5M",
                               reagent_cycles=100, i5_workflow="Index-first")
        ctx.run_template_repo.save(template)

        resp = logged_in_client.post(f"/runs/new/from-template/{template.id}", headers=ORIGIN,
                                     follow_redirects=False)

        assert resp.status_code == 400
        assert resp.text == ("MiSeq i100 Series is not among the synced instruments; "
                             "this template/run cannot be instantiated.")

    def test_new_run_works_when_novaseq_x_is_left_out(self, logged_in_client, fresh_app):
        from .test_group_1c import _platform_options, _sync
        _app, ctx, _db = fresh_app
        _sync(ctx, names=(I100.value,))

        resp = logged_in_client.post("/runs/new", headers=ORIGIN, follow_redirects=False)

        run_id = resp.headers["location"].split("run_id=", 1)[1]
        assert ctx.run_repo.get_by_id(run_id).i5_workflow == ""
        setup = logged_in_client.get(f"/runs/new/step/1?run_id={run_id}").text
        assert (NOVASEQ_X.value, True, f"{NOVASEQ_X.value} (not available)") in _platform_options(setup)


class TestRecordsThatCannotBeUsed:
    """An old-format record, a damaged record or a database error: run pages
    show the message, Mark Ready is refused with nothing saved, and the
    local file is never used."""

    @pytest.mark.parametrize("store,message", [
        pytest.param(_store_old_format_record, OLD_FORMAT_MESSAGE, id="old-format"),
        pytest.param(_store_damaged_record, None, id="damaged"),
    ])
    def test_the_run_page_shows_the_message(self, logged_in_client, fresh_app, store, message):
        from .test_group_1c import _clean_run
        _app, ctx, _db = fresh_app
        run = _clean_run(ctx, "a2-unusable-page")
        store(ctx)

        resp = logged_in_client.get(f"/runs/{run.id}")

        assert resp.status_code == 503
        text = html.unescape(resp.text)
        assert text.startswith("<!DOCTYPE html>")
        if message:
            assert message in text
        else:
            assert "The synced instrument settings cannot be used: NovaSeq X Series: " in text
            assert text.rstrip().endswith(f"{REMEDY}</div></body></html>")

    def test_an_htmx_request_gets_the_banner(self, logged_in_client, fresh_app):
        from .test_group_1c import _clean_run
        _app, ctx, _db = fresh_app
        run = _clean_run(ctx, "a2-unusable-htmx")
        _store_old_format_record(ctx)

        resp = logged_in_client.post(f"/runs/{run.id}/instrument",
                                     data={"instrument_platform": I100.value},
                                     headers={**ORIGIN, "HX-Request": "true"})

        assert resp.status_code == 503
        assert resp.headers["HX-Retarget"] == "#error-banner"
        assert html.unescape(resp.text) == f'<div class="error-message">{OLD_FORMAT_MESSAGE}</div>'

    def test_mark_ready_is_refused_and_audited(self, logged_in_client, fresh_app):
        from .test_group_1c import _clean_run
        _app, ctx, _db = fresh_app
        run = _clean_run(ctx, "a2-unusable-ready")
        _store_old_format_record(ctx)

        resp = logged_in_client.post(f"/runs/{run.id}/status/ready", headers=ORIGIN)

        assert resp.status_code == 503
        assert OLD_FORMAT_MESSAGE in html.unescape(resp.text)
        stored = ctx.run_repo.get_by_id(run.id)
        assert stored.status == RunStatus.DRAFT and stored.generated_samplesheet_v2 is None
        (event,) = _denials(ctx)
        assert event.details["reason"] == "synced_instruments_unusable"

    def test_a_database_error_shows_the_fixed_sentence(self, logged_in_client, fresh_app,
                                                         monkeypatch):
        from pymongo.errors import ServerSelectionTimeoutError
        from seqsetup.data import instruments as instruments_module
        from .test_group_1c import _clean_run, _sync
        _app, ctx, _db = fresh_app
        run = _clean_run(ctx, "a2-unusable-db")
        _sync(ctx, names=(NOVASEQ_X.value,))

        def unreachable():
            raise ServerSelectionTimeoutError("db-host-7:27017: timed out")

        monkeypatch.setattr(instruments_module._instrument_definition_repo, "list_all", unreachable)
        instruments_module.clear_synced_instruments_cache()

        resp = logged_in_client.get(f"/runs/{run.id}")

        assert resp.status_code == 503
        assert DATABASE_MESSAGE in resp.text
        assert "db-host-7" not in resp.text

    @pytest.mark.parametrize("path", [
        "export/samplesheet-v2", "export/samplesheet-v1", "export/validation-report",
        "export/validation-pdf",
    ])
    def test_the_live_exports_show_it(self, logged_in_client, fresh_app, path):
        from .test_group_1c import _clean_run
        _app, ctx, _db = fresh_app
        # A Ready run from before exports were pre-generated: the export routes
        # make them live.
        platform = NOVASEQ_X if "v1" not in path else InstrumentPlatform.NOVASEQ_6000
        run = _clean_run(ctx, "a2-unusable-export", platform=platform,
                         flowcell="10B" if platform == NOVASEQ_X else "S4",
                         status=RunStatus.READY)
        _store_old_format_record(ctx)

        resp = logged_in_client.get(f"/runs/{run.id}/{path}")

        assert resp.status_code == 503
        assert OLD_FORMAT_MESSAGE in html.unescape(resp.text)

    def test_a_failure_while_exports_are_made_is_not_failed_to_generate(
            self, logged_in_client, fresh_app, monkeypatch):
        from seqsetup.data.instruments import SyncedInstrumentsUnusable
        from seqsetup.routes import runs as runs_module
        from .conftest import disable_repos
        from .test_group_1c import _clean_run
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        run = _clean_run(ctx, "a2-unusable-export-step")

        def unusable(run_, ctx_):
            raise SyncedInstrumentsUnusable(DATABASE_MESSAGE)

        monkeypatch.setattr(runs_module, "_pregenerate_exports", unusable)

        resp = logged_in_client.post(f"/runs/{run.id}/status/ready", headers=ORIGIN)

        assert resp.status_code == 503
        assert DATABASE_MESSAGE in resp.text
        assert ctx.run_repo.get_by_id(run.id).status == RunStatus.DRAFT
        (event,) = _denials(ctx)
        assert event.details["reason"] == "synced_instruments_unusable"

    def test_the_switch_re_read_is_covered(self, logged_in_client, fresh_app, monkeypatch):
        from seqsetup.models.instrument_definition import InstrumentRecordError
        from .conftest import disable_repos
        from .test_group_1c import _clean_run, _sync
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        _sync(ctx, names=(NOVASEQ_X.value,))
        run = _clean_run(ctx, "a2-unusable-reread")

        def damaged(name):
            raise InstrumentRecordError(f"{name}: flowcells: damaged")

        monkeypatch.setattr(ctx.instrument_definition_repo, "get_by_name", damaged)

        resp = logged_in_client.post(f"/runs/{run.id}/status/ready", headers=ORIGIN)

        assert resp.status_code == 503
        assert (f"The synced instrument settings cannot be used: NovaSeq X Series: flowcells: "
                f"damaged. {REMEDY}") in html.unescape(resp.text)
        assert ctx.run_repo.get_by_id(run.id).status == RunStatus.DRAFT
        (event,) = _denials(ctx)
        assert event.details["reason"] == "synced_instruments_unusable"

    def test_a_database_error_at_the_switch_re_read_is_the_fixed_sentence(
            self, logged_in_client, fresh_app, monkeypatch):
        from pymongo.errors import ServerSelectionTimeoutError
        from .conftest import disable_repos
        from .test_group_1c import _clean_run, _sync
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        _sync(ctx, names=(NOVASEQ_X.value,))
        run = _clean_run(ctx, "a2-unusable-reread-db")

        def unreachable(name):
            raise ServerSelectionTimeoutError("db-host-7:27017: timed out")

        monkeypatch.setattr(ctx.instrument_definition_repo, "get_by_name", unreachable)

        resp = logged_in_client.post(f"/runs/{run.id}/status/ready", headers=ORIGIN)

        assert resp.status_code == 503
        assert DATABASE_MESSAGE in resp.text
        assert "db-host-7" not in resp.text
        assert ctx.run_repo.get_by_id(run.id).status == RunStatus.DRAFT
        (event,) = _denials(ctx)
        assert event.details["reason"] == "synced_instruments_unusable"

    @pytest.mark.parametrize("method,path,data", [
        pytest.param("get", "/admin/instruments", None, id="page"),
        pytest.param("post", "/admin/instruments/synced/toggle",
                     {"instrument_id": "x", "enabled": "false"}, id="toggle"),
        pytest.param("post", "/admin/instruments/synced/enable-all", {}, id="enable-all"),
    ])
    def test_a_database_error_on_the_admin_instruments_page_is_the_fixed_sentence(
            self, logged_in_client, fresh_app, monkeypatch, method, path, data):
        from pymongo.errors import ServerSelectionTimeoutError
        _app, ctx, _db = fresh_app

        def unreachable():
            raise ServerSelectionTimeoutError("db-host-7:27017: timed out")

        monkeypatch.setattr(ctx.instrument_definition_repo, "list_all", unreachable)

        if method == "get":
            resp = logged_in_client.get(path)
        else:
            resp = logged_in_client.post(path, data=data, headers=ORIGIN)

        assert resp.status_code == 503
        assert DATABASE_MESSAGE in resp.text
        assert "db-host-7" not in resp.text

    def test_the_admin_toggle_saves_then_shows_the_message(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _store_old_format_record(ctx)
        doc = ctx.instrument_definition_repo.collection.find_one({"name": NOVASEQ_X.value})

        resp = logged_in_client.post("/admin/instruments/synced/toggle",
                                     data={"instrument_id": doc["_id"], "enabled": "false"},
                                     headers=ORIGIN)

        assert resp.status_code == 503
        assert OLD_FORMAT_MESSAGE in html.unescape(resp.text)
        assert ctx.instrument_definition_repo.collection.find_one(
            {"_id": doc["_id"]})["enabled"] is False

    def test_the_config_sync_page_still_opens(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _store_old_format_record(ctx)
        assert logged_in_client.get("/admin/config-sync").status_code == 200

    def test_a_ready_run_keeps_its_exports_and_the_api(self, logged_in_client, fresh_app):
        from .test_group_1c import _clean_run
        _app, ctx, _db = fresh_app
        run = _clean_run(ctx, "a2-unusable-pregenerated", status=RunStatus.READY)
        run.generated_samplesheet_v2 = "[Header]\nmade before\n"
        ctx.run_repo.save(run)
        _store_old_format_record(ctx)

        resp = logged_in_client.get(f"/runs/{run.id}/export/samplesheet-v2")

        assert resp.status_code == 200
        assert resp.text == "[Header]\nmade before\n"


KIT_YAML = """\
name: "A2 Kit"
version: "1.0.0"
index_mode: unique_dual
index_pairs:
  - name: "A01"
    index1:
      name: "i7-01"
      sequence: "ATTACTCG"
    index2:
      name: "i5-01"
      sequence: "TATAGCCT"
"""


def _instrument_text(name: str, **changes) -> str:
    """The shipped local entry for ``name``, as a one-instrument sync file."""
    import yaml
    from seqsetup.data import instruments as instruments_module
    return yaml.safe_dump({**instruments_module._instruments[name], "name": name, **changes})


def _sync_with_instruments(ctx, monkeypatch, instrument_files: dict, fail_download=(),
                           fail_listing=()):
    """One real config sync, with only the GitHub fetches replaced: the
    profile folders hold one good profile and its test profile, the index-kit
    folder one kit, and the instrument folder ``instrument_files`` (name ->
    text, or a mapping for a subfolder)."""
    from .test_sheet_followups import TEST_PROFILE_YAML, _app_profile_yaml
    from seqsetup.services.github_sync import GitHubSyncError
    config = ctx.profile_sync_config_repo.get()
    config.github_repo_url = "https://github.com/example/config"
    config.sync_instruments_enabled = True
    config.sync_index_kits_enabled = True
    ctx.profile_sync_config_repo.save(config)
    folders = {
        config.application_profiles_path.strip("/"): {
            "GuardProfile.yaml": _app_profile_yaml("GuardProfile", '"4.3.6"')},
        config.test_profiles_path.strip("/"): {"Wgs.yaml": TEST_PROFILE_YAML},
        config.index_kits_path.strip("/"): {"a2kit.yaml": KIT_YAML},
        config.instruments_path.strip("/"): instrument_files,
    }
    texts = {}

    def listing(owner, repo, branch, path):
        path = path.strip("/")
        if path in fail_listing:
            raise GitHubSyncError("GitHub API error: 500 Server Error")
        entries = []
        for name, value in folders[path].items():
            item_path = f"{path}/{name}"
            if isinstance(value, dict):
                folders[item_path] = value
                entries.append({"type": "dir", "name": name, "path": item_path})
            else:
                url = f"https://raw.githubusercontent.com/example/config/main/{item_path}"
                texts[url] = value
                entries.append({"type": "file", "name": name, "path": item_path,
                                "download_url": url})
        return entries

    def content(url):
        if url.rsplit("/", 1)[1] in fail_download:
            raise GitHubSyncError("Failed to fetch file: 404 Not Found")
        return texts[url]

    service = ctx.get_github_sync_service()
    monkeypatch.setattr(service, "_fetch_directory_contents", listing)
    monkeypatch.setattr(service, "_fetch_file_content", content)
    # mongomock's bulk_write does not take pymongo's ReplaceOne; save the kits
    # one by one (what bulk_save stores is not under test here).
    monkeypatch.setattr(ctx.index_kit_repo, "bulk_save",
                        lambda kits: [ctx.index_kit_repo.save(kit) for kit in kits])
    return service.sync()


def _stored_switches(ctx) -> dict:
    return {doc["name"]: doc["enabled"]
            for doc in ctx.instrument_definition_repo.collection.find({})}


GOOD_FILES = {
    "novaseq-x.yaml": _instrument_text(NOVASEQ_X.value),
    "i100.yaml": _instrument_text(I100.value),
}


class TestASyncThatRefusesAnInstrumentFile:
    """Any refused instrument file means no instrument records are stored;
    the stored ones and their switches stay; the sync says it failed and
    which file; profiles and index kits are still synced (spec §5)."""

    def _before(self, ctx):
        """Stored records with NovaSeq X switched off, as a sync left them."""
        from .test_group_1c import _sync
        _sync(ctx, names=(NOVASEQ_X.value, I100.value), disabled=(NOVASEQ_X.value,))
        return {doc["_id"] for doc in ctx.instrument_definition_repo.collection.find({})}

    def _assert_nothing_stored(self, ctx, before_ids, ok, message, problem):
        assert ok is False
        assert {doc["_id"] for doc in ctx.instrument_definition_repo.collection.find({})} == before_ids
        assert _stored_switches(ctx) == {NOVASEQ_X.value: False, I100.value: True}
        assert problem in message
        assert ("Instrument files were refused, so no instrument settings were stored "
                "and the stored ones are kept") in message
        assert "Synced 1 application profiles, 1 test profiles, 1 index kits." in message
        status = ctx.profile_sync_config_repo.get()
        assert (status.last_sync_status, status.last_sync_message) == ("error", message)
        assert [p.name for p in ctx.app_profile_repo.list_all()] == ["GuardProfile"]
        assert [k.name for k in ctx.index_kit_repo.list_all() if k.source == "github"] == ["A2 Kit"]

    def test_a_file_the_check_refuses(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        before = self._before(ctx)
        ok, message, _ = _sync_with_instruments(ctx, monkeypatch, {
            **GOOD_FILES, "i100.yaml": _instrument_text(I100.value, runinfo_marks_i5_reversed="yes"),
        })
        self._assert_nothing_stored(
            ctx, before, ok, message,
            "instruments/i100.yaml: MiSeq i100 Series: runinfo_marks_i5_reversed: "
            "Must be true or false (got: 'yes')")

    def test_a_file_that_cannot_be_downloaded(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        before = self._before(ctx)
        ok, message, _ = _sync_with_instruments(ctx, monkeypatch, GOOD_FILES,
                                                fail_download=("i100.yaml",))
        self._assert_nothing_stored(ctx, before, ok, message,
                                    "instruments/i100.yaml: Failed to fetch file: 404 Not Found")

    def test_a_subfolder_that_cannot_be_listed(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        before = self._before(ctx)
        ok, message, _ = _sync_with_instruments(
            ctx, monkeypatch, {**GOOD_FILES, "old": {}}, fail_listing=("instruments/old",))
        self._assert_nothing_stored(
            ctx, before, ok, message,
            "instruments/old/: could not be listed: GitHub API error: 500 Server Error")

    def test_two_files_with_the_same_name(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        before = self._before(ctx)
        ok, message, _ = _sync_with_instruments(ctx, monkeypatch, {
            **GOOD_FILES, "copy.yaml": _instrument_text(I100.value, samplesheet_name="Copy"),
        })
        self._assert_nothing_stored(ctx, before, ok, message,
                                    "i100.yaml and copy.yaml both give name 'MiSeq i100 Series'")

    def test_every_file_refused_still_syncs_profiles_and_kits(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        before = self._before(ctx)
        ok, message, _ = _sync_with_instruments(ctx, monkeypatch, {
            "i100.yaml": _instrument_text(I100.value, i5_workflows=[]),
        })
        self._assert_nothing_stored(
            ctx, before, ok, message,
            "instruments/i100.yaml: MiSeq i100 Series: i5_workflows: Must be a non-empty list "
            "of workflows, the standard one first")
        assert "Refusing to replace" not in message


class TestASyncThatRepairsOldRecords:
    """With every file good, the records are replaced, an instrument that was
    switched off stays off, and the next lookup works (spec §5)."""

    def test_old_format_records_are_replaced(self, logged_in_client, fresh_app, monkeypatch):
        from .test_group_1c import _clean_run
        _app, ctx, _db = fresh_app
        _store_old_format_record(ctx)
        ctx.instrument_definition_repo.collection.update_one(
            {"name": NOVASEQ_X.value}, {"$set": {"enabled": False}})
        run = _clean_run(ctx, "a2-repair", platform=I100, flowcell="5M")
        assert logged_in_client.get(f"/runs/{run.id}").status_code == 503

        ok, message, _ = _sync_with_instruments(ctx, monkeypatch, GOOD_FILES)

        assert ok, message
        assert ctx.profile_sync_config_repo.get().last_sync_status == "success"
        assert _stored_switches(ctx) == {NOVASEQ_X.value: False, I100.value: True}
        assert logged_in_client.get(f"/runs/{run.id}").status_code == 200

    def test_a_good_sync_still_refuses_to_store_nothing(self, fresh_app, monkeypatch):
        # The empty-fetch guard still stands when no file was refused.
        from .test_group_1c import _sync
        _app, ctx, _db = fresh_app
        _sync(ctx, names=(NOVASEQ_X.value,))
        ok, message, _ = _sync_with_instruments(ctx, monkeypatch, {})
        assert ok is False
        assert "Refusing to replace 1 existing instrument definitions with 0 fetched items" in message
