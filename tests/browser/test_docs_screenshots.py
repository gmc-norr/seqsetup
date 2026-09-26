"""Documentation screenshots: drive the real app in a made-up demo world and
save outlined crops into docs/_static/screenshots/.

Skipped unless SEQSETUP_DOCS_SCREENSHOTS=1 (`pixi run docs-screenshots`).
Tests run in file order; later tests may rely on what earlier ones did.
The browser-test database is snapshotted before and restored after, so
other browser tests never see the demo world.
"""

import os
import re
from pathlib import Path

import pytest

from seqsetup.data.instruments import clear_synced_instruments_cache
from seqsetup.models.instrument_definition import FlowcellDefinition, InstrumentDefinition
from seqsetup.services import database

from .docs_shots import shoot
from .docs_world import DEMO_ADMIN, clear, reset_caches, restore, seed_demo, snapshot

SHOTS = Path(__file__).resolve().parents[2] / "docs" / "_static" / "screenshots"

pytestmark = [
    pytest.mark.browser,
    pytest.mark.skipif(
        os.environ.get("SEQSETUP_DOCS_SCREENSHOTS") != "1",
        reason="documentation screenshots: run `pixi run docs-screenshots`",
    ),
]


@pytest.fixture(scope="module")
def demo(app_ctx):
    db = database.get_db()
    saved = snapshot(db)
    clear(db)
    reset_caches()
    try:
        ids = seed_demo(app_ctx)
        yield ids
    finally:
        restore(db, saved)
        reset_caches()


@pytest.fixture
def demo_page(page, base_url, demo):
    page.set_viewport_size({"width": 1280, "height": 800})
    page.goto(f"{base_url}/login")
    page.fill('input[name="username"]', DEMO_ADMIN["username"])
    page.fill('input[name="password"]', DEMO_ADMIN["password"])
    page.click('button[type="submit"]')
    page.wait_for_url(f"{base_url}/", timeout=5000)
    return page


def snap(page, name: str, target, region=None, pad: int = 16) -> Path:
    return shoot(page, SHOTS / f"{name}.png", target, region=region, pad=pad)


def test_login_form(page, base_url, demo):
    page.set_viewport_size({"width": 1280, "height": 800})
    page.goto(f"{base_url}/login")
    form = page.locator("form").filter(has=page.locator('input[name="username"]'))
    snap(page, "login/login-form", form, pad=24)


def test_dashboard_tabs(demo_page, base_url, demo):
    page = demo_page
    tabs = page.locator("#dashboard .flex.gap-2.border-b")
    snap(page, "dashboard/tabs", tabs)


def test_dashboard_search(demo_page, base_url, demo):
    page = demo_page
    page.fill("#dashboard-search", "DEMO-RUN-01")
    # The unfiltered dashboard already links DEMO-RUN-01, so waiting on that
    # link races the 300ms-debounced HTMX swap. Wait instead for something
    # that exists ONLY in a completed search result: the status badge next
    # to the run name (dashboard.html renders it only when show_status is
    # set, which is true for search results and never for the plain tabs).
    page.wait_for_selector("#dashboard .run-status-badge", timeout=5000)
    search_box = page.locator("#dashboard-search")
    snap(page, "dashboard/search", search_box, region=page.locator("#main"))


def test_dashboard_new_run_button(demo_page, base_url, demo):
    page = demo_page
    button = page.get_by_role("button", name="New Run")
    snap(page, "dashboard/new-run-button", button)


def test_new_run_template_choice(demo_page, base_url, demo):
    page = demo_page
    # The demo world seeds no run templates (docs_world.py has none), so the
    # New Run page's "start from a template" section has nothing to offer
    # unless one exists. Create one for real, through the run page's own
    # "Save as template" form -- the same way a user would.
    page.goto(f"{base_url}/runs/{demo['draft']}")
    page.fill("#template-name", "Standard WGS Setup")
    with page.expect_navigation(url=re.compile(r"/templates$")):
        page.get_by_role("button", name="Save as template").click()

    page.goto(f"{base_url}/")
    with page.expect_navigation(url=re.compile(r"/runs/new/step/1")):
        page.get_by_role("button", name="New Run").click()

    page.select_option("#template_id", label="Standard WGS Setup")
    template_section = page.locator("form.template-start")
    snap(page, "new-run/template-choice", template_section)


def test_new_run_name_and_description(demo_page, base_url, demo):
    page = demo_page
    page.goto(f"{base_url}/")
    with page.expect_navigation(url=re.compile(r"/runs/new/step/1")):
        page.get_by_role("button", name="New Run").click()

    form = page.locator("form.run-name-form")
    snap(page, "new-run/name-and-description", form)


def test_new_run_instrument_and_flowcell(demo_page, base_url, demo):
    page = demo_page
    page.goto(f"{base_url}/")
    with page.expect_navigation(url=re.compile(r"/runs/new/step/1")):
        page.get_by_role("button", name="New Run").click()

    fieldset = page.locator("fieldset.instrument-config")
    snap(page, "new-run/instrument-and-flowcell", fieldset)


def test_new_run_cycle_config(demo_page, base_url, demo):
    page = demo_page
    page.goto(f"{base_url}/")
    with page.expect_navigation(url=re.compile(r"/runs/new/step/1")):
        page.get_by_role("button", name="New Run").click()

    cycles = page.locator("#cycle-config")
    snap(page, "new-run/cycle-config", cycles)


def test_new_run_cycle_limit_exceeded(demo_page, base_url, demo, app_ctx):
    page = demo_page
    # config/instruments.yaml ships reagent_kit_max_cycles for no instrument
    # at all (see the comment at the end of that file) -- the limit that
    # drives the "Too many cycles" warning only exists once an admin syncs
    # instrument definitions that carry one (services/github_sync.py). Seed
    # one directly, the same way docs_world.py seeds runs/users/index kits
    # straight through the repositories instead of the UI, so the warning
    # rendered below is the real template branch, not a mock-up.
    definition = InstrumentDefinition(
        name="NovaSeq X Series",
        samplesheet_name="NovaSeqXSeries",
        chemistry_type="2-color",
        i5_read_orientation="reverse-complement",
        samplesheet_v2_i5_orientation="forward",
        has_dragen_onboard=True,
        flowcells=[
            FlowcellDefinition(
                name="10B", lanes=8, reads=10_000_000_000,
                reagent_kits=[100, 200, 300],
                description="10 billion reads, 8 lanes",
            ),
        ],
        reagent_kit_max_cycles={300: 300},
    )
    app_ctx.instrument_definition_repo.save(definition)
    clear_synced_instruments_cache()
    try:
        # A brand-new run defaults to NovaSeq X Series / 10B / 300 cycles,
        # whose default Read1+Read2+Index1+Index2 (151+151+10+10=322) is
        # already over the 300-cycle limit just seeded -- no field needs
        # to be touched to see the warning.
        page.goto(f"{base_url}/")
        with page.expect_navigation(url=re.compile(r"/runs/new/step/1")):
            page.get_by_role("button", name="New Run").click()

        warning = page.locator(".cycle-total-over")
        snap(page, "new-run/cycle-limit-exceeded", warning, region=page.locator("#cycle-config"))
    finally:
        app_ctx.instrument_definition_repo.delete_all()
        clear_synced_instruments_cache()


def test_new_run_continue_button(demo_page, base_url, demo):
    page = demo_page
    page.goto(f"{base_url}/")
    with page.expect_navigation(url=re.compile(r"/runs/new/step/1")):
        page.get_by_role("button", name="New Run").click()

    nav = page.locator(".wizard-nav")
    snap(page, "new-run/continue-button", nav)


# Header row + a blank line + 3 new data rows: the blank line and the
# header are not samples, so "lines read" (5, via str.splitlines()) and
# "samples read" (3, via the parser) genuinely differ -- the discrepancy
# the paste-preview picture is asked to show.
_SAMPLES_PASTE_TEXT = "sample_id\ttest_id\nSAMPLE-B01\tWGS\n\nSAMPLE-B02\tWGS\nSAMPLE-B03\tWGS"


def test_samples_add_button(demo_page, base_url, demo):
    page = demo_page
    # demo['draft'] already has 8 samples, so runs/_sample_section.html
    # renders the <details> collapsed -- the state a returning user meets.
    page.goto(f"{base_url}/runs/{demo['draft']}")
    toggle = page.locator(".paste-section-summary")
    snap(page, "samples/add-button", toggle)


def test_samples_paste_form(demo_page, base_url, demo):
    page = demo_page
    page.goto(f"{base_url}/runs/{demo['draft']}")
    page.locator(".paste-section-summary").click()
    form = page.locator("#paste-area .paste-form")
    snap(page, "samples/paste-form", form, pad=24)


def test_samples_paste_preview(demo_page, base_url, demo):
    page = demo_page
    page.goto(f"{base_url}/runs/{demo['draft']}")
    page.locator(".paste-section-summary").click()
    page.fill("#paste_data", _SAMPLES_PASTE_TEXT)
    page.get_by_role("button", name="Preview").click()
    # Only the completed preview renders a .paste-counts row -- the form
    # being replaced (innerHTML swap of #paste-area) has no such element.
    page.wait_for_selector("#paste-area .paste-counts")
    preview = page.locator("#paste-area .paste-preview")
    snap(page, "samples/paste-preview", preview.locator(".paste-counts"), region=preview)


def test_samples_sample_table(demo_page, base_url, demo):
    page = demo_page
    page.goto(f"{base_url}/runs/{demo['draft']}")
    page.locator(".paste-section-summary").click()
    page.fill("#paste_data", _SAMPLES_PASTE_TEXT)
    page.get_by_role("button", name="Preview").click()
    page.wait_for_selector("#paste-area .paste-counts")
    page.get_by_role("button", name="Add 3 samples").click()
    # Two HTMX round trips follow this click: the POST swaps #sample-section
    # (the new row lands immediately), then #validate-panel's own
    # hx-trigger (any successful non-GET, delay:300ms -- see
    # templates/runs/_validate_panel.html) refetches the Validate box and
    # app.js's markSampleErrors() re-marks every unindexed row from that
    # fresh data, including the ones just pasted. Waiting only for the new
    # row (not this second trip) would catch the table mid-flight, still
    # missing the error badge every other unindexed row already has.
    page.wait_for_selector(
        "#sample-table tr.sample-row:has-text('SAMPLE-B01') .row-error-badge"
    )
    table = page.locator("#sample-table")
    snap(page, "samples/sample-table", table)


def test_samples_row_edit(demo_page, base_url, demo):
    page = demo_page
    page.goto(f"{base_url}/runs/{demo['draft']}")
    row = page.locator("tr.sample-row").filter(has_text="SAMPLE-A01")
    box = row.locator('input[name="override_cycles"]')
    box.fill("Y151;I8;I8;Y151")
    box.dispatch_event("change")
    # The row is swapped outerHTML by POST .../settings; wait for the
    # saved value to actually be on the page, not the pre-swap input.
    page.wait_for_selector(
        'tr.sample-row:has-text("SAMPLE-A01") '
        'input[name="override_cycles"][value="Y151;I8;I8;Y151"]'
    )
    row = page.locator("tr.sample-row").filter(has_text="SAMPLE-A01")
    snap(page, "samples/row-edit", row.locator('input[name="override_cycles"]'), region=row)
