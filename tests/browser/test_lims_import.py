"""The LIMS import from a draft run's page, with the page's own requests:
Load Worklists, pick, Preview, then the preview's Import button. The samples
section is swapped, not nested; a refusal goes to the banner and stays there,
also right after a failed import from the same button (spec 2026-10-10 later
list slice 2, §1, §2). The import adds only what the preview showed, and
picking another worksheet clears the preview (outside review of 7f858e0,
finding 2). The LIMS is replaced in the test server's process."""

import pytest
from playwright.sync_api import expect

from seqsetup.models.sample_api_config import SampleApiConfig
from seqsetup.models.sequencing_run import RunStatus
from seqsetup.services import sample_api as sample_api_module
from .conftest import hold_edit_lock

GOOD = [{"sample_id": "LIMS-01", "test_id": ""}, {"sample_id": "LIMS-02", "test_id": ""}]
REPEATED = [{"sample_id": "LIMS-01", "test_id": ""}, {"sample_id": "LIMS-01", "test_id": ""}]
CHANGED = [{"sample_id": "LIMS-01", "test_id": ""}, {"sample_id": "LIMS-03", "test_id": ""}]


@pytest.fixture
def lims(app_ctx, monkeypatch):
    """The sample API on, and a LIMS that lists worksheets WS1 and WS2 and
    answers their rows from ``lims.rows``; the stored config is put back
    afterwards."""
    before = app_ctx.sample_api_config_repo.get()
    app_ctx.sample_api_config_repo.save(
        SampleApiConfig(base_url="https://lims.example.org/api", enabled=True))

    class Lims:
        rows = GOOD

    def answer(url, api_key=""):
        if "/worksheets/" in url:
            return [dict(row) for row in Lims.rows]
        return [{"id": "WS1"}, {"id": "WS2"}]

    monkeypatch.setattr(sample_api_module, "_api_get", answer)
    yield Lims
    app_ctx.sample_api_config_repo.save(before)


def _load_worksheets(page, base_url, run_id):
    page.goto(f"{base_url}/runs/{run_id}")
    page.wait_for_load_state("networkidle")
    page.locator("summary.paste-section-summary").click()
    page.get_by_role("button", name="Load Worklists").click()
    expect(page.locator("#worklist-select")).to_have_count(1)
    page.locator("#worklist-select").select_option("WS1")


def _preview(page):
    page.locator("#worklist-select-area").get_by_role("button", name="Preview").click()
    expect(page.locator("#worklist-preview")).to_contain_text("LIMS-02")


def _import_button(page):
    return page.locator("#worklist-preview").get_by_role("button", name="Import 2 samples")


def _set_status(app_ctx, run_id, status):
    run = app_ctx.run_repo.get_by_id(run_id)
    run.status = status
    app_ctx.run_repo.save(run)
    hold_edit_lock(app_ctx, run.id)


@pytest.mark.browser
def test_load_preview_and_import(logged_in_page, base_url, app_ctx, mutable_run_id, lims):
    page = logged_in_page
    _load_worksheets(page, base_url, mutable_run_id)
    expect(page.locator("#worklist-select-area").get_by_role("button", name="Import Samples")
           ).to_have_count(0)
    _preview(page)

    with page.expect_response(lambda r: r.url.endswith("/samples/fetch-worklist") and r.status == 200):
        _import_button(page).click()

    expect(page.locator("#error-banner")).to_contain_text("Added 2 samples from worklist.")
    expect(page.locator("#sample-section")).to_have_count(1)    # swapped, not nested
    expect(page.locator("#sample-table")).to_have_count(1)
    expect(page.locator("#sample-table")).to_contain_text("LIMS-02")
    ids = [s.sample_id for s in app_ctx.run_repo.get_by_id(mutable_run_id).samples]
    assert ids[-2:] == ["LIMS-01", "LIMS-02"]


@pytest.mark.browser
def test_a_worksheet_changed_since_the_preview_adds_nothing(logged_in_page, base_url, app_ctx,
                                                            mutable_run_id, lims):
    page = logged_in_page
    before = app_ctx.run_repo.get_by_id(mutable_run_id).to_dict()
    _load_worksheets(page, base_url, mutable_run_id)
    _preview(page)
    lims.rows = CHANGED

    with page.expect_response(lambda r: r.url.endswith("/samples/fetch-worklist") and r.status == 409):
        _import_button(page).click()

    expect(page.locator("#error-banner")).to_contain_text(
        "The worksheet or the run changed since the preview. Nothing was added. Preview again.")
    expect(page.locator("#sample-table")).not_to_contain_text("LIMS-03")
    assert app_ctx.run_repo.get_by_id(mutable_run_id).to_dict() == before


@pytest.mark.browser
def test_picking_another_worksheet_clears_the_preview(logged_in_page, base_url, mutable_run_id,
                                                      lims):
    page = logged_in_page
    _load_worksheets(page, base_url, mutable_run_id)
    _preview(page)

    page.locator("#worklist-select").select_option("WS2")

    expect(page.locator("#worklist-preview")).to_be_empty()
    expect(page.locator("#worklist-preview").get_by_role("button")).to_have_count(0)


@pytest.mark.browser
def test_a_refused_import_leaves_the_table(logged_in_page, base_url, app_ctx, mutable_run_id, lims):
    page = logged_in_page
    before = app_ctx.run_repo.get_by_id(mutable_run_id).to_dict()
    _load_worksheets(page, base_url, mutable_run_id)
    _preview(page)
    lims.rows = REPEATED

    with page.expect_response(lambda r: r.url.endswith("/samples/fetch-worklist") and r.status == 400):
        _import_button(page).click()

    expect(page.locator("#error-banner")).to_contain_text(
        "Worklist import rejected: these sample IDs appear more than once in the worklist: LIMS-01.")
    expect(page.locator("#sample-section")).to_have_count(1)
    expect(page.locator("#sample-table")).to_contain_text("MUT-01")
    assert app_ctx.run_repo.get_by_id(mutable_run_id).to_dict() == before


@pytest.mark.browser
def test_a_refusal_after_a_failed_import_stays(logged_in_page, base_url, app_ctx, mutable_run_id,
                                               lims):
    page = logged_in_page
    _load_worksheets(page, base_url, mutable_run_id)
    _preview(page)

    _set_status(app_ctx, mutable_run_id, RunStatus.READY)       # Import now answers 403
    with page.expect_response(lambda r: r.url.endswith("/samples/fetch-worklist") and r.status == 403):
        _import_button(page).click()
    expect(page.locator("#error-banner")).not_to_be_empty()

    _set_status(app_ctx, mutable_run_id, RunStatus.DRAFT)
    lims.rows = REPEATED
    # Any status: what counts is that the banner keeps the refusal.
    with page.expect_response(lambda r: r.url.endswith("/samples/fetch-worklist")):
        _import_button(page).click()
    expect(page.locator("#error-banner")).to_contain_text(
        "Worklist import rejected: these sample IDs appear more than once in the worklist: LIMS-01.")


@pytest.mark.browser
def test_a_success_after_a_refusal_shows_its_message(logged_in_page, base_url, app_ctx,
                                                     mutable_run_id, lims):
    """app.js cleared the banner after a success from a button whose last
    request failed, after the swap, so the import's own "Added 2 samples"
    was wiped (build review of later list slice 2, E-1)."""
    page = logged_in_page
    _load_worksheets(page, base_url, mutable_run_id)
    _preview(page)
    lims.rows = REPEATED
    with page.expect_response(lambda r: r.url.endswith("/samples/fetch-worklist")):
        _import_button(page).click()
    expect(page.locator("#error-banner")).to_contain_text("appear more than once")

    lims.rows = GOOD
    with page.expect_response(lambda r: r.url.endswith("/samples/fetch-worklist")):
        _import_button(page).click()
    expect(page.locator("#error-banner")).to_contain_text("Added 2 samples from worklist.")


@pytest.mark.browser
def test_the_lanes_picked_are_the_lanes_imported_to(logged_in_page, base_url, app_ctx,
                                                     mutable_run_id, lims):
    """Not lane 1 unseen (index mix-up audit, 2026-10-14; the user's choice
    "Same rules as paste")."""
    page = logged_in_page
    _load_worksheets(page, base_url, mutable_run_id)
    page.locator('#worklist-lanes input[value="1"]').uncheck()
    page.locator('#worklist-lanes input[value="2"]').check()
    _preview(page)
    expect(page.locator("#worklist-preview")).to_contain_text("to add to lane 2")

    with page.expect_response(lambda r: r.url.endswith("/samples/fetch-worklist") and r.status == 200):
        _import_button(page).click()

    samples = app_ctx.run_repo.get_by_id(mutable_run_id).samples
    assert [(s.sample_id, s.lanes) for s in samples[-2:]] == [("LIMS-01", [2]), ("LIMS-02", [2])]


@pytest.mark.browser
def test_changing_a_lane_clears_the_preview(logged_in_page, base_url, mutable_run_id, lims):
    page = logged_in_page
    _load_worksheets(page, base_url, mutable_run_id)
    _preview(page)

    page.locator('#worklist-lanes input[value="3"]').check()

    expect(page.locator("#worklist-preview")).to_be_empty()
