"""Group 1c in a real browser (spec 2026-09-28): a mistyped mismatch count is
refused, not turned into "clear" (F6, review P1); the Sample ID is shown
whole (F5)."""

from datetime import datetime

import pytest
from playwright.sync_api import expect

from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun


LONG_IDS = ("GROUP1C-LONG-SAMPLE-ID-00001-A", "GROUP1C-LONG-SAMPLE-ID-00002-B")
REFUSAL = "Barcode mismatches must be 0, 1 or 2"


@pytest.fixture
def group_1c_run_id(app_ctx):
    """A draft with two samples in lane 1, mismatches 2 / 2 each; the first
    has an index, the second none. Neither has a test ID, so the Check panel
    flags both rows. Deleted afterwards."""
    t = datetime(2026, 1, 10, 9, 0, 0)
    run = SequencingRun(
        id="group-1c-run", run_name="Group 1c run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=RunStatus.DRAFT,
        created_at=t, updated_at=t,
    )
    pair = IndexPair(
        id="g1c", name="g1c",
        index1=Index(name="g1c-i7", sequence="ATTACTCG", index_type=IndexType.I7),
        index2=Index(name="g1c-i5", sequence="TATAGCCT", index_type=IndexType.I5),
    )
    run.add_sample(Sample(id=f"{run.id}-s1", sample_id=LONG_IDS[0], lanes=[1], index_pair=pair,
                          barcode_mismatches_index1=2, barcode_mismatches_index2=2))
    run.add_sample(Sample(id=f"{run.id}-s2", sample_id=LONG_IDS[1], lanes=[1],
                          barcode_mismatches_index1=2, barcode_mismatches_index2=2))
    app_ctx.run_repo.save(run)
    yield run.id
    app_ctx.run_repo.delete(run.id)


def _open(page, base_url, run_id):
    page.goto(f"{base_url}/runs/{run_id}")
    page.wait_for_load_state("networkidle")


def _type(box, text):
    """Type key by key, as a person does. Playwright's fill() refuses text a
    number box cannot hold, so it could not show the old behaviour."""
    box.click()
    box.press("Control+A")
    box.press_sequentially(text)


def _stored(app_ctx, run_id):
    run = app_ctx.run_repo.get_by_id(run_id)
    return [(s.barcode_mismatches_index1, s.barcode_mismatches_index2) for s in run.samples]


@pytest.mark.browser
def test_unreadable_row_value_is_refused_not_cleared(logged_in_page, base_url, group_1c_run_id, app_ctx):
    page = logged_in_page
    _open(page, base_url, group_1c_run_id)
    box = page.locator(f'#sample-row-{group_1c_run_id}-s1 input[name="barcode_mismatches_index1"]')

    _type(box, "1e")
    box.press("Tab")

    expect(page.locator("#error-banner")).to_contain_text(REFUSAL)
    assert _stored(app_ctx, group_1c_run_id) == [(2, 2), (2, 2)]


@pytest.mark.browser
def test_unreadable_bulk_value_is_refused_not_cleared(logged_in_page, base_url, group_1c_run_id, app_ctx):
    page = logged_in_page
    _open(page, base_url, group_1c_run_id)
    page.locator(f"#sample-row-{group_1c_run_id}-s1 .sample-checkbox").check()
    page.locator(f"#sample-row-{group_1c_run_id}-s2 .sample-checkbox").check()

    _type(page.locator("#bulk-mismatch-i7-input"), "1e")
    _type(page.locator("#bulk-mismatch-i5-input"), "1")
    page.locator('[data-action="bulk-apply-mismatches"]').click()

    expect(page.locator("#error-banner")).to_contain_text(REFUSAL)
    assert _stored(app_ctx, group_1c_run_id) == [(2, 2), (2, 2)]


@pytest.mark.browser
def test_bulk_apply_with_i5_blank_leaves_i5_alone(logged_in_page, base_url, group_1c_run_id, app_ctx):
    """A box left blank leaves that column alone (the user's decision after
    the build review, 2026-09-28)."""
    page = logged_in_page
    _open(page, base_url, group_1c_run_id)
    page.locator(f"#sample-row-{group_1c_run_id}-s1 .sample-checkbox").check()
    page.locator(f"#sample-row-{group_1c_run_id}-s2 .sample-checkbox").check()

    _type(page.locator("#bulk-mismatch-i7-input"), "1")
    with page.expect_response(lambda r: r.url.endswith("/samples/set-mismatches")) as resp_info:
        page.locator('[data-action="bulk-apply-mismatches"]').click()

    assert resp_info.value.status == 200
    assert _stored(app_ctx, group_1c_run_id) == [(1, 2), (1, 2)]


@pytest.mark.browser
def test_bulk_clear_resets_both_columns(logged_in_page, base_url, group_1c_run_id, app_ctx):
    page = logged_in_page
    _open(page, base_url, group_1c_run_id)
    page.locator(f"#sample-row-{group_1c_run_id}-s1 .sample-checkbox").check()
    page.locator(f"#sample-row-{group_1c_run_id}-s2 .sample-checkbox").check()

    with page.expect_response(lambda r: r.url.endswith("/samples/set-mismatches")) as resp_info:
        page.locator('[data-action="bulk-clear-mismatches"]').click()

    assert resp_info.value.status == 200
    assert _stored(app_ctx, group_1c_run_id) == [(None, None), (None, None)]


@pytest.mark.browser
def test_long_sample_ids_are_shown_whole(logged_in_page, base_url, group_1c_run_id):
    page = logged_in_page
    _open(page, base_url, group_1c_run_id)

    for n, sample_id in enumerate(LONG_IDS, start=1):
        cell = page.locator(f'#sample-row-{group_1c_run_id}-s{n} td[title="{sample_id}"]')
        expect(cell.locator(".row-error-badge")).to_have_count(1)
        scroll, client, overflow = cell.evaluate(
            "el => [el.scrollWidth, el.clientWidth, getComputedStyle(el).textOverflow]")
        assert overflow != "ellipsis", sample_id
        assert scroll <= client, (sample_id, scroll, client)
