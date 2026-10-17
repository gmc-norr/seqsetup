"""Deleting a sample: two tabs, and the row button's own target (design
note docs/design/2026-10-17-stale-page-checks-design.md, step 3).
"""

from datetime import datetime

import pytest
from playwright.sync_api import expect

from seqsetup.models.index import Index, IndexKit, IndexMode, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun
from .conftest import hold_edit_lock

RUN_ID = "stale-delete-run"
KIT = "Stale-Delete-Kit"
SEQS = [("ACGTACGT", "AACCGGTT"), ("TGCATGCA", "TTGGCCAA")]
CHANGED = "The index on these samples changed since this page was loaded"


@pytest.fixture
def kit(app_ctx):
    from seqsetup.services.validation import clear_validation_cache
    app_ctx.index_kit_repo.save(IndexKit(
        name=KIT, version="1.0", index_mode=IndexMode.UNIQUE_DUAL, index_pairs=[
            IndexPair(id=f"{KIT}_SD{k}", name=f"SD{k}",
                      index1=Index(f"SD{k}", i7, IndexType.I7),
                      index2=Index(f"SD{k}", i5, IndexType.I5))
            for k, (i7, i5) in enumerate(SEQS)
        ]))
    clear_validation_cache()
    yield
    app_ctx.index_kit_repo.delete(KIT, "1.0")
    clear_validation_cache()


@pytest.fixture
def run_id(app_ctx):
    t = datetime(2026, 1, 10, 9, 0, 0)
    run = SequencingRun(
        id=RUN_ID, run_name="Stale delete run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=RunStatus.DRAFT,
        created_at=t, updated_at=t,
    )
    for n in (1, 2, 3):
        run.add_sample(Sample(id=f"{RUN_ID}-s{n}", sample_id=f"SD-0{n}", lanes=[1]))
    app_ctx.run_repo.save(run)
    hold_edit_lock(app_ctx, RUN_ID)
    yield RUN_ID
    app_ctx.run_repo.collection.delete_one({"_id": RUN_ID})


def _open(page, base_url):
    page.goto(f"{base_url}/runs/{RUN_ID}")
    page.wait_for_load_state("networkidle")
    page.on("dialog", lambda d: d.accept())      # "Delete this sample?"


def _the_other_tab_indexes(app_ctx, n):
    run = app_ctx.run_repo.get_by_id(RUN_ID)
    run.samples[n - 1].assign_index1(Index("other", "GGGGGGGG", IndexType.I7))
    app_ctx.run_repo.save(run)
    hold_edit_lock(app_ctx, RUN_ID)


def _delete_row(page, n):
    with page.expect_response(lambda r: "/samples/" in r.url and r.request.method == "DELETE") as a:
        page.locator(f"#sample-row-{RUN_ID}-s{n} .btn-danger").click()
    return a.value


def _ids(app_ctx):
    return [s.sample_id for s in app_ctx.run_repo.get_by_id(RUN_ID).samples]


@pytest.mark.browser
def test_the_rows_delete_button_leaves_one_sample_section(
        logged_in_page, base_url, app_ctx, run_id):
    """The button swapped the whole sample section in where the table was,
    which nested a second #sample-section inside the first: two paste
    forms, two index panels, two of every id -- and the kit dropdown then
    drove the wrong list. Deleting again nested another."""
    page = logged_in_page
    _open(page, base_url)

    assert _delete_row(page, 1).status == 200
    page.wait_for_timeout(200)
    assert _delete_row(page, 2).status == 200
    page.wait_for_timeout(200)

    assert page.locator("#sample-section").count() == 1
    assert page.locator("#sample-table").count() == 1
    assert page.locator("#index-list-container").count() <= 1
    assert _ids(app_ctx) == ["SD-03"]


@pytest.mark.browser
def test_a_row_another_tab_indexed_is_not_deleted(
        logged_in_page, base_url, app_ctx, kit, run_id):
    page = logged_in_page
    _open(page, base_url)
    _the_other_tab_indexes(app_ctx, 1)

    answer = _delete_row(page, 1)

    assert answer.status == 409
    assert "target_indexes" in answer.url, answer.url
    expect(page.locator("#error-banner")).to_contain_text(CHANGED)
    expect(page.locator("#error-banner")).to_contain_text("SD-01")
    assert _ids(app_ctx) == ["SD-01", "SD-02", "SD-03"]


@pytest.mark.browser
def test_delete_selected_on_a_row_another_tab_indexed_is_refused(
        logged_in_page, base_url, app_ctx, kit, run_id):
    page = logged_in_page
    _open(page, base_url)
    for n in (1, 2):
        page.locator(f"#sample-row-{RUN_ID}-s{n} .sample-checkbox").check()
    _the_other_tab_indexes(app_ctx, 2)

    with page.expect_response(lambda r: r.url.endswith("/bulk-delete")) as a:
        page.locator("#bulk-delete-btn").click()

    assert a.value.status == 409
    assert "target_indexes" in a.value.request.post_data, a.value.request.post_data
    expect(page.locator("#error-banner")).to_contain_text("SD-02")
    assert _ids(app_ctx) == ["SD-01", "SD-02", "SD-03"]


@pytest.mark.browser
def test_delete_selected_still_deletes_what_the_page_showed(
        logged_in_page, base_url, app_ctx, kit, run_id):
    page = logged_in_page
    _open(page, base_url)
    for n in (1, 2):
        page.locator(f"#sample-row-{RUN_ID}-s{n} .sample-checkbox").check()

    with page.expect_response(lambda r: r.url.endswith("/bulk-delete")) as a:
        page.locator("#bulk-delete-btn").click()

    assert a.value.status == 200, a.value.text()
    assert _ids(app_ctx) == ["SD-03"]
