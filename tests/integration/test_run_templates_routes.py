"""Integration tests for clone + template routes."""

import json

import pytest

from seqsetup.models.run_template import RunTemplate
from seqsetup.models.sequencing_run import RunStatus


def _origin() -> dict:
    return {"Origin": "http://testserver"}


def _create_run(client) -> str:
    r = client.post("/runs/new", follow_redirects=False, headers=_origin())
    assert r.status_code == 303, r.text[:300]
    return r.headers["location"].split("run_id=", 1)[1].split("&", 1)[0]


def _add_sample(client, run_id, sample_id="S1"):
    r = client.post(
        f"/runs/{run_id}/samples", data={"sample_id": sample_id}, headers=_origin()
    )
    assert r.status_code == 200


class TestCloneRun:
    def test_duplicate_config_only_creates_draft_without_samples(
        self, logged_in_client, fresh_app
    ):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        _add_sample(logged_in_client, run_id, "S1")
        before = len(ctx.run_repo.list_all())

        r = logged_in_client.post(
            f"/runs/{run_id}/duplicate",
            data={"include_samples": "false"},
            headers=_origin(),
            follow_redirects=False,
        )
        assert r.status_code == 303
        new_id = r.headers["location"].rsplit("/", 1)[1]
        assert len(ctx.run_repo.list_all()) == before + 1

        new_run = ctx.run_repo.get_by_id(new_id)
        assert new_run.status == RunStatus.DRAFT
        assert new_run.samples == []
        assert new_run.generated_samplesheet_v2 is None

    def test_duplicate_include_samples_copies_samples(
        self, logged_in_client, fresh_app
    ):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        _add_sample(logged_in_client, run_id, "S1")

        r = logged_in_client.post(
            f"/runs/{run_id}/duplicate",
            data={"include_samples": "true"},
            headers=_origin(),
            follow_redirects=False,
        )
        assert r.status_code == 303
        new_id = r.headers["location"].rsplit("/", 1)[1]
        new_run = ctx.run_repo.get_by_id(new_id)
        assert [s.sample_id for s in new_run.samples] == ["S1"]

    def test_duplicate_does_not_mutate_source(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        _add_sample(logged_in_client, run_id, "S1")
        logged_in_client.post(
            f"/runs/{run_id}/duplicate",
            data={"include_samples": "true"}, headers=_origin(),
            follow_redirects=False,
        )
        src = ctx.run_repo.get_by_id(run_id)
        assert len(src.samples) == 1
        assert src.status == RunStatus.DRAFT

    def test_duplicate_missing_run_404(self, logged_in_client):
        r = logged_in_client.post(
            "/runs/does-not-exist/duplicate",
            data={"include_samples": "false"}, headers=_origin(),
            follow_redirects=False,
        )
        assert r.status_code == 404


class TestSaveAsTemplate:
    def test_save_as_template_captures_config_and_selected_samples(
        self, logged_in_client, fresh_app
    ):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        _add_sample(logged_in_client, run_id, "CTRL_POS")
        run = ctx.run_repo.get_by_id(run_id)
        scaffold_uuid = run.samples[0].id

        r = logged_in_client.post(
            f"/runs/{run_id}/save-as-template",
            data={
                "name": "WGS Standard",
                "description": "std",
                "scaffold_sample_ids": json.dumps([scaffold_uuid]),
            },
            headers=_origin(),
            follow_redirects=False,
        )
        assert r.status_code == 303
        templates = ctx.run_template_repo.list_all()
        assert len(templates) == 1
        t = templates[0]
        assert t.name == "WGS Standard"
        assert t.flowcell_type == run.flowcell_type
        assert [s.sample_id for s in t.scaffold_samples] == ["CTRL_POS"]

    def test_save_as_template_with_no_scaffold_is_config_only(
        self, logged_in_client, fresh_app
    ):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        _add_sample(logged_in_client, run_id, "S1")
        r = logged_in_client.post(
            f"/runs/{run_id}/save-as-template",
            data={"name": "Config Only", "description": "", "scaffold_sample_ids": "[]"},
            headers=_origin(), follow_redirects=False,
        )
        assert r.status_code == 303
        t = ctx.run_template_repo.list_all()[0]
        assert t.scaffold_samples == []

    def test_save_as_template_requires_name(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        r = logged_in_client.post(
            f"/runs/{run_id}/save-as-template",
            data={"name": "  ", "description": "", "scaffold_sample_ids": "[]"},
            headers=_origin(), follow_redirects=False,
        )
        assert r.status_code == 400
        assert ctx.run_template_repo.list_all() == []

    def test_save_as_template_is_create_only(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        for _ in range(2):
            logged_in_client.post(
                f"/runs/{run_id}/save-as-template",
                data={"name": "Dup", "description": "", "scaffold_sample_ids": "[]"},
                headers=_origin(), follow_redirects=False,
            )
        # Two saves with the same name -> two distinct templates.
        assert len(ctx.run_template_repo.list_all()) == 2

    def _run_with_analysis(self, logged_in_client, ctx, sample_ids):
        from seqsetup.models.analysis import Analysis, AnalysisType, DRAGENPipeline
        run_id = _create_run(logged_in_client)
        _add_sample(logged_in_client, run_id, "S1")
        _add_sample(logged_in_client, run_id, "CTRL_POS")
        run = ctx.run_repo.get_by_id(run_id)
        run.analyses = [Analysis(
            name="g", analysis_type=AnalysisType.DRAGEN_ONBOARD,
            dragen_pipeline=DRAGENPipeline.GERMLINE, sample_ids=sample_ids,
        )]
        ctx.run_repo.save(run)
        ctrl = next(s for s in run.samples if s.sample_id == "CTRL_POS")
        return run_id, ctrl.id

    def test_save_as_template_filters_analyses_to_scaffold(
        self, logged_in_client, fresh_app
    ):
        # Analysis references S1 (not scaffolded) + CTRL_POS (scaffolded); the
        # stored template must keep only the scaffold reference.
        _app, ctx, _db = fresh_app
        run_id, ctrl_id = self._run_with_analysis(
            logged_in_client, ctx, ["S1", "CTRL_POS"]
        )
        r = logged_in_client.post(
            f"/runs/{run_id}/save-as-template",
            data={"name": "Filtered", "description": "",
                  "scaffold_sample_ids": json.dumps([ctrl_id])},
            headers=_origin(), follow_redirects=False,
        )
        assert r.status_code == 303
        t = ctx.run_template_repo.list_all()[0]
        assert [s.sample_id for s in t.scaffold_samples] == ["CTRL_POS"]
        assert len(t.analyses) == 1
        assert t.analyses[0].sample_ids == ["CTRL_POS"]

    def test_save_as_template_drops_analysis_with_no_scaffold_samples(
        self, logged_in_client, fresh_app
    ):
        # Analysis references only S1, which is NOT scaffolded → analysis dropped.
        _app, ctx, _db = fresh_app
        run_id, ctrl_id = self._run_with_analysis(logged_in_client, ctx, ["S1"])
        r = logged_in_client.post(
            f"/runs/{run_id}/save-as-template",
            data={"name": "Dropped", "description": "",
                  "scaffold_sample_ids": json.dumps([ctrl_id])},
            headers=_origin(), follow_redirects=False,
        )
        assert r.status_code == 303
        t = ctx.run_template_repo.list_all()[0]
        assert t.analyses == []


class TestTemplateCrud:
    def _make_template(self, logged_in_client, ctx) -> str:
        run_id = _create_run(logged_in_client)
        logged_in_client.post(
            f"/runs/{run_id}/save-as-template",
            data={"name": "Orig", "description": "d", "scaffold_sample_ids": "[]"},
            headers=_origin(), follow_redirects=False,
        )
        return ctx.run_template_repo.list_all()[0].id

    def test_list_page_renders_template(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        self._make_template(logged_in_client, ctx)
        r = logged_in_client.get("/templates")
        assert r.status_code == 200
        assert "Orig" in r.text

    def test_edit_updates_name_description_and_touches(
        self, logged_in_client, fresh_app
    ):
        _app, ctx, _db = fresh_app
        tid = self._make_template(logged_in_client, ctx)
        before = ctx.run_template_repo.get_by_id(tid).updated_at
        r = logged_in_client.post(
            f"/templates/{tid}",
            data={"name": "Renamed", "description": "new"},
            headers=_origin(), follow_redirects=False,
        )
        assert r.status_code == 303
        t = ctx.run_template_repo.get_by_id(tid)
        assert t.name == "Renamed"
        assert t.description == "new"
        assert t.updated_at >= before
        assert t.updated_by  # actor recorded

    def test_delete_removes_template(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        tid = self._make_template(logged_in_client, ctx)
        r = logged_in_client.delete(f"/templates/{tid}", headers=_origin())
        assert r.status_code in (200, 204)
        assert ctx.run_template_repo.get_by_id(tid) is None

    def test_template_never_appears_in_run_repo(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        self._make_template(logged_in_client, ctx)
        # The save-as-template flow created exactly one run (the source);
        # the template is NOT a run.
        assert len(ctx.run_repo.list_all()) == 1

    def test_edit_missing_template_404(self, logged_in_client, fresh_app):
        r = logged_in_client.post(
            "/templates/nope",
            data={"name": "x", "description": ""},
            headers=_origin(), follow_redirects=False,
        )
        assert r.status_code == 404

    def test_delete_missing_template_404(self, logged_in_client, fresh_app):
        r = logged_in_client.delete("/templates/nope", headers=_origin())
        assert r.status_code == 404


class TestCreateFromTemplate:
    def _make_template_with_scaffold(self, logged_in_client, ctx) -> str:
        run_id = _create_run(logged_in_client)
        _add_sample(logged_in_client, run_id, "CTRL_POS")
        run = ctx.run_repo.get_by_id(run_id)
        sid = run.samples[0].id
        logged_in_client.post(
            f"/runs/{run_id}/save-as-template",
            data={"name": "WithCtrl", "description": "",
                  "scaffold_sample_ids": json.dumps([sid])},
            headers=_origin(), follow_redirects=False,
        )
        return ctx.run_template_repo.list_all()[0].id

    def test_from_template_creates_draft_with_scaffold(
        self, logged_in_client, fresh_app
    ):
        _app, ctx, _db = fresh_app
        tid = self._make_template_with_scaffold(logged_in_client, ctx)
        r = logged_in_client.post(
            f"/runs/new/from-template/{tid}",
            headers=_origin(), follow_redirects=False,
        )
        assert r.status_code == 303
        new_id = r.headers["location"].rsplit("/", 1)[1]
        new_run = ctx.run_repo.get_by_id(new_id)
        assert new_run.status == RunStatus.DRAFT
        assert new_run.run_name == "WithCtrl"
        assert [s.sample_id for s in new_run.samples] == ["CTRL_POS"]
        assert new_run.generated_samplesheet_v2 is None

    def test_from_template_refuses_stale_reference(
        self, logged_in_client, fresh_app, monkeypatch
    ):
        # Empty flowcell set => instrument no longer available; this proves
        # the route wires check_references=True and turns RunInstantiationError
        # into a 400. (The three distinct refusal branches are unit-tested in
        # tests/unit/test_run_builder.py::TestAssertReferencesAvailable.)
        _app, ctx, _db = fresh_app
        tid = self._make_template_with_scaffold(logged_in_client, ctx)
        monkeypatch.setattr(
            "seqsetup.services.run_builder.get_flowcells_for_instrument",
            lambda platform, cfg=None: {},
        )
        r = logged_in_client.post(
            f"/runs/new/from-template/{tid}",
            headers=_origin(), follow_redirects=False,
        )
        assert r.status_code == 400
        assert "no longer available" in r.text.lower()

    def test_from_template_missing_template_404(self, logged_in_client):
        r = logged_in_client.post(
            "/runs/new/from-template/nope",
            headers=_origin(), follow_redirects=False,
        )
        assert r.status_code == 404


class TestUiHooks:
    def test_dashboard_shows_duplicate_action(self, logged_in_client, fresh_app):
        run_id = _create_run(logged_in_client)
        r = logged_in_client.get("/")
        assert r.status_code == 200
        assert f"/runs/{run_id}/duplicate" in r.text

    def test_edit_page_shows_save_as_template(self, logged_in_client, fresh_app):
        run_id = _create_run(logged_in_client)
        r = logged_in_client.get(f"/runs/{run_id}")
        assert r.status_code == 200
        assert "save-as-template" in r.text


class TestSafetyBoundaries:
    """Clinical invariants that must not regress: a malicious/invalid scaffold
    cannot bypass model validation, and a clone never resurrects a non-DRAFT
    status or stale exports from its source."""

    def test_non_acgtn_index_in_template_dict_is_rejected(self):
        # Deserializing a template whose scaffold sample carries a non-ACGTN
        # index must RAISE, not silently produce a valid-looking template.
        # Index.__post_init__ rejects characters outside [ACGTN].
        bad = {
            "id": "t1",
            "name": "evil",
            "instrument_platform": "NovaSeq X Series",
            "scaffold_samples": [{
                "id": "x", "sample_id": "S1",
                "index1": {"name": "i", "sequence": "ZZZZ", "index_type": "i7"},
            }],
        }
        with pytest.raises(ValueError):
            RunTemplate.from_dict(bad)

    def test_clone_of_archived_run_does_not_resurrect_status(
        self, logged_in_client, fresh_app
    ):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        run = ctx.run_repo.get_by_id(run_id)
        run.status = RunStatus.ARCHIVED
        run.generated_samplesheet_v2 = "snapshot"
        ctx.run_repo.save(run)

        r = logged_in_client.post(
            f"/runs/{run_id}/duplicate",
            data={"include_samples": "true"}, headers=_origin(),
            follow_redirects=False,
        )
        assert r.status_code == 303
        new_id = r.headers["location"].rsplit("/", 1)[1]
        new_run = ctx.run_repo.get_by_id(new_id)
        assert new_run.status == RunStatus.DRAFT
        assert new_run.generated_samplesheet_v2 is None
