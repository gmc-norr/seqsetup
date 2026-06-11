"""Integration tests for clone + template routes."""

import json

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
