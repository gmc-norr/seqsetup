"""The bulk panel's Override Cycles: Apply with the box empty saves nothing
and says so; Auto works the values out again (project review of 7d970c7,
2026-10-21, EDITING-2). Apply with an empty box was the same request as Auto,
so a typed UMI read was replaced with no word."""

from datetime import datetime

import pytest
from playwright.sync_api import expect

from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun
from .conftest import SCREENSHOT_KIT_NAME, hold_edit_lock

RUN_ID = "oc-empty-apply"
TYPED = "U8Y143;I8;I8;Y151"  # a UMI read typed by hand; fits 151/8/8/151


@pytest.fixture
def run_id(app_ctx):
    t = datetime(2026, 1, 10, 9, 0, 0)
    run = SequencingRun(
        id=RUN_ID, run_name="OC empty apply",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=RunStatus.DRAFT,
        created_at=t, updated_at=t,
    )
    s = Sample(id=f"{RUN_ID}-s1", sample_id="UMI-01", lanes=[1], index_pair=IndexPair(
        id="sck-p1", name="UDP0001",
        index1=Index(name="i7-01", sequence="ATTACTCG", index_type=IndexType.I7),
        index2=Index(name="i5-01", sequence="TATAGCCT", index_type=IndexType.I5)),
        index_kit_name=SCREENSHOT_KIT_NAME)
    s.override_cycles = TYPED
    run.add_sample(s)
    app_ctx.run_repo.save(run)
    hold_edit_lock(app_ctx, RUN_ID)
    yield RUN_ID
    app_ctx.run_repo.collection.delete_one({"_id": RUN_ID})


def _tick(page, base_url):
    page.goto(f"{base_url}/runs/{RUN_ID}")
    page.wait_for_load_state("networkidle")
    expect(page.locator(f"#override-cycles-{RUN_ID}-s1")).to_have_value(TYPED)
    page.locator(f"#sample-row-{RUN_ID}-s1 .sample-checkbox").check()


def _stored(app_ctx):
    return app_ctx.run_repo.get_by_id(RUN_ID).samples[0].override_cycles


@pytest.mark.browser
def test_apply_with_the_box_empty_keeps_the_typed_value_and_says_so(
        logged_in_page, base_url, app_ctx, run_id):
    page = logged_in_page
    _tick(page, base_url)

    with page.expect_response(lambda r: r.url.endswith("/samples/set-override-cycles")) as answer:
        page.locator('[data-action="bulk-apply-override"]').click()

    assert answer.value.status == 400
    expect(page.locator("#error-banner")).to_contain_text("Type an Override Cycles to apply")
    assert _stored(app_ctx) == TYPED


@pytest.mark.browser
def test_auto_works_the_value_out(logged_in_page, base_url, app_ctx, run_id):
    page = logged_in_page
    _tick(page, base_url)

    with page.expect_response(lambda r: r.url.endswith("/samples/set-override-cycles")) as answer:
        page.locator('[data-action="bulk-clear-override"]').click()

    assert answer.value.status == 200
    assert _stored(app_ctx) == "Y151;I8;I8;Y151"
