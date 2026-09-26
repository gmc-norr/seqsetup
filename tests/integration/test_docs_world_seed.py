"""The made-up demo world the documentation pictures are taken in."""

from seqsetup.models.sequencing_run import RunStatus
from tests.browser.docs_world import DEMO_ADMIN, DEMO_KIT_NAME, DEMO_STAFF, seed_demo

FIXTURE_WORDS = ("browser", "screenshot", "seed", "test")


def test_seed_demo_builds_runs_in_every_state(fresh_app):
    _app, ctx, _db = fresh_app

    ids = seed_demo(ctx)

    status = {key: ctx.run_repo.get_by_id(run_id).status for key, run_id in ids.items()}
    assert status == {
        "draft": RunStatus.DRAFT, "problem": RunStatus.DRAFT, "fill": RunStatus.DRAFT,
        "ready": RunStatus.READY, "archived": RunStatus.ARCHIVED,
    }


def test_seed_demo_users_and_kit(fresh_app):
    _app, ctx, _db = fresh_app

    seed_demo(ctx)

    assert ctx.local_user_repo.get_by_username(DEMO_ADMIN["username"]) is not None
    assert ctx.local_user_repo.get_by_username(DEMO_STAFF["username"]) is not None
    assert ctx.index_kit_repo.get_by_name_and_version(DEMO_KIT_NAME, "1.0") is not None


def test_seed_demo_uses_no_fixture_looking_names(fresh_app):
    _app, ctx, _db = fresh_app

    ids = seed_demo(ctx)

    for run_id in ids.values():
        run = ctx.run_repo.get_by_id(run_id)
        names = [run.run_name] + [s.sample_id for s in run.samples]
        assert not any(w in n.lower() for n in names for w in FIXTURE_WORDS), names
