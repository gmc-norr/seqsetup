"""Documentation screenshots: drive the real app in a made-up demo world and
save outlined crops into docs/_static/screenshots/.

Skipped unless SEQSETUP_DOCS_SCREENSHOTS=1 (`pixi run docs-screenshots`).
Tests run in file order; later tests may rely on what earlier ones did.
The browser-test database is snapshotted before and restored after, so
other browser tests never see the demo world.
"""

import os
import re
import tempfile
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

import pytest
from playwright.sync_api import expect

from seqsetup.data.instruments import clear_synced_instruments_cache
from seqsetup.models.instrument_definition import FlowcellDefinition, InstrumentDefinition
from seqsetup.models.deleted_run import DeletedRun
from seqsetup.models.run_history import RunHistoryEntry
from seqsetup.models.sequencing_run import RunStatus
from seqsetup.services import database

from .docs_shots import replace_text, shoot
from .docs_world import (DEMO_ADMIN, DEMO_KIT_NAME, _pair, _run, _sample, clear, reset_caches,
                         restore, seed_demo, snapshot)

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
    # Pages show times in the TZ zone (utils/clock.py): one fixed zone, so the
    # pictures do not depend on the machine they are taken on.
    with pytest.MonkeyPatch.context() as zone:
        zone.setenv("TZ", "Europe/Stockholm")
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


def test_chromium_draws_whole_tiles(browser_type_launch_args):
    # conftest.browser_type_launch_args: without it a rounded edge can come
    # out one shade different from run to run (docs_shots.docs_launch_args).
    assert "--disable-partial-raster" in browser_type_launch_args["args"]


def test_login_form(page, base_url, demo):
    page.set_viewport_size({"width": 1280, "height": 800})
    page.goto(f"{base_url}/login")
    form = page.locator("form").filter(has=page.locator('input[name="username"]'))
    snap(page, "login/login-form", form, pad=24)


def test_login_ended_message(demo_page, base_url, demo, app_ctx):
    page = demo_page
    page.goto(f"{base_url}/runs/{demo['draft']}")
    page.locator(".paste-section-summary").click()
    page.fill("#paste_data", _SAMPLES_PASTE_TEXT)
    # End the login server-side, as the idle limit or an admin would; the
    # next background action is refused and the page is kept.
    app_ctx.web_session_repo.delete_for_user(DEMO_ADMIN["username"])
    with page.expect_response(
            lambda r: r.url.endswith("/samples/preview") and r.status == 401):
        page.get_by_role("button", name="Preview").click()
    banner = page.locator("#error-banner")
    expect(banner).to_contain_text("Your login has ended, so this was not saved.")
    expect(page.locator("#paste_data")).to_have_value(_SAMPLES_PASTE_TEXT)
    snap(page, "login/login-ended", banner)


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
        i5_workflows=[{"name": "Standard", "i5_read_orientation": "reverse-complement"}],
        runinfo_marks_i5_reversed=True,
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
    # The outline on .paste-section-summary itself only ever paints a
    # bottom underline (verified: switching the target to its <details>
    # parent renders the exact same bottom-only line -- this is not a
    # `<summary>`-specific quirk). getBoundingClientRect shows why:
    # .paste-section-summary sits flush (identical x/y/width) against
    # #sample-section, whose `overflow-x: auto` (components.css:441-442)
    # computes overflow-y to `auto` too, per spec, clipping any painted
    # content -- including a descendant's outline -- that pokes past its
    # box. The outline's 3px width + docs_shots.py's fixed 2px offset
    # extend 5px outward on every side; with zero clearance on top/left/
    # right that 5px is clipped away, while the bottom survives because
    # the sample table below leaves ~900px of clearance before
    # #sample-section's actual bottom edge. .paste-form (paste-form.png)
    # is unaffected because it sits ~17px inside that same edge (1px
    # <details> border + the 16px .paste-section-content padding).
    # Neutralise the clip for the moment of capture only, the same way
    # shoot() itself neutralises the outline style: set + revert an
    # inline style on #sample-section, no src/ or docs_shots.py change.
    section = page.locator("#sample-section")
    previous_overflow = section.evaluate(
        "(e) => { const old = e.style.overflow; e.style.overflow = 'visible'; return old; }"
    )
    try:
        snap(page, "samples/add-button", toggle)
    finally:
        section.evaluate("(e, old) => { e.style.overflow = old; }", previous_overflow)


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
    # region=row alone clipped to a 65px sliver -- half of the row above and
    # below, unreadable. Capture the whole table (header + every row) so the
    # edited row is whole and has its neighbours for context; the outline
    # stays on just the Override Cycles input.
    table = page.locator("table.sample-table")
    snap(page, "samples/row-edit", row.locator('input[name="override_cycles"]'), region=table, pad=24)


# ---------------------------------------------------------------------------
# Index assignment: kit picker, drag-and-drop, shift-click selection, ticked
# rows, and "fill empty samples in order".
# ---------------------------------------------------------------------------


@contextmanager
def _sample_section_unclipped(page):
    """#sample-section's overflow-x:auto computes overflow-y to auto too
    (components.css:441-442), which clips the outline on any descendant
    flush with its box -- the index panel and sample table both live inside
    it. Neutralise the clip for the moment of capture only, the same way
    test_samples_add_button does for a single shot, then restore it."""
    section = page.locator("#sample-section")
    previous = section.evaluate(
        "(e) => { const old = e.style.overflow; e.style.overflow = 'visible'; return old; }"
    )
    try:
        yield
    finally:
        section.evaluate("(e, old) => { e.style.overflow = old; }", previous)


def _drag_index(page, chip, drop_zone):
    """Fire a real HTML5 drag-and-drop sequence from ``chip`` to
    ``drop_zone``. Playwright's high-level drag_to() drives mouse events,
    which Chromium does not turn into dragstart/drop for a custom
    draggable="true" element the way a real OS-level drag does -- app.js's
    dragstart/dragover/drop listeners (app.js:769-793) never fire. Instead,
    build one DataTransfer in the page and dispatch the same event sequence
    a browser would during a real drag, all carrying that one DataTransfer
    object -- this is Playwright's own documented recipe for HTML5 drag and
    drop. handleDragStart (app.js:90-107) and handleIndexDrop (app.js:109-
    226) are the real, unmodified handlers; nothing about the drop is
    faked."""
    data_transfer = page.evaluate_handle("new DataTransfer()")
    chip.dispatch_event("dragstart", {"dataTransfer": data_transfer})
    drop_zone.dispatch_event("dragenter", {"dataTransfer": data_transfer})
    drop_zone.dispatch_event("dragover", {"dataTransfer": data_transfer})
    drop_zone.dispatch_event("drop", {"dataTransfer": data_transfer})
    chip.dispatch_event("dragend", {"dataTransfer": data_transfer})


def _pair_chip(page, name: str):
    return page.locator(".draggable-index-compact.draggable-pair").filter(has_text=name)


def test_indexes_kit_picker(demo_page, base_url, demo):
    page = demo_page
    # demo['draft'] has un-indexed samples (SAMPLE-A05..A08, plus the pasted
    # SAMPLE-B01..B03), so runs/_sample_section.html's has_unindexed branch
    # renders the index panel next to the table.
    page.goto(f"{base_url}/runs/{demo['draft']}")
    dropdown = page.locator("#index-kit-dropdown")
    # Demo world seeds exactly one kit -- confirm the picker actually names
    # it, not just that a <select> exists.
    assert DEMO_KIT_NAME in dropdown.locator("option:checked").text_content()
    with _sample_section_unclipped(page):
        snap(page, "indexes/kit-picker", dropdown, pad=8)


def test_indexes_drag_drop(demo_page, base_url, demo):
    page = demo_page
    page.goto(f"{base_url}/runs/{demo['draft']}")
    chip = _pair_chip(page, "UDI0005")
    row = page.locator("tr.sample-row").filter(has_text="SAMPLE-A05")
    _drag_index(page, chip, row.locator(".drop-zone.i7-drop"))
    # assign-index swaps only the row; #validate-panel refreshes separately,
    # 300ms after any successful non-GET request (_validate_panel.html:41-46).
    # markSampleErrors() (app.js:383-413) runs on every htmx:afterSettle,
    # including this row's own settle -- the first run reuses the *stale*
    # data-sample-errors still naming SAMPLE-A05 as having no index, and
    # marks the fresh row wrongly until the panel's own refresh lands.
    # Waiting only for the assigned index (as elsewhere) would photograph
    # that stale badge; wait for it to be removed instead.
    page.wait_for_selector('tr.sample-row:has-text("SAMPLE-A05") .assigned-index.i7')
    page.wait_for_selector('tr.sample-row:has-text("SAMPLE-A05") .row-error-badge', state="detached")
    row = page.locator("tr.sample-row").filter(has_text="SAMPLE-A05")
    with _sample_section_unclipped(page):
        snap(page, "indexes/drag-drop", row.locator(".assigned-index.i7"), region=row, pad=24)


def test_indexes_several_in_order(demo_page, base_url, demo):
    page = demo_page
    page.goto(f"{base_url}/runs/{demo['draft']}")
    chip6, chip8 = _pair_chip(page, "UDI0006"), _pair_chip(page, "UDI0008")
    chip6.click()
    chip8.click(modifiers=["Shift"])
    # Click + shift-click select the whole visible range between them
    # (app.js:31-59): UDI0006, UDI0007, UDI0008.
    assert page.locator(".draggable-index-compact.index-selected").count() == 3
    with _sample_section_unclipped(page):
        snap(page, "indexes/several-in-order", chip8,
             region=page.locator("#index-list-items"), pad=16)

    # Prove the selection is real, not just styled: drag it onto
    # SAMPLE-A06 and check it filled three consecutive rows in table order
    # (app.js:201-222, routes/samples.py assign-indexes-bulk).
    row = page.locator("tr.sample-row").filter(has_text="SAMPLE-A06")
    _drag_index(page, chip6, row.locator(".drop-zone.i7-drop"))
    page.wait_for_selector('tr.sample-row:has-text("SAMPLE-A08") .assigned-index.i7')
    # A unique-dual pair sets both i7 and i5, so .index-name-display appears
    # twice per row (one per column) -- .first is enough to prove it landed.
    assert "UDI0006" in page.locator("tr.sample-row").filter(has_text="SAMPLE-A06").locator(".index-name-display").first.text_content()
    assert "UDI0007" in page.locator("tr.sample-row").filter(has_text="SAMPLE-A07").locator(".index-name-display").first.text_content()
    assert "UDI0008" in page.locator("tr.sample-row").filter(has_text="SAMPLE-A08").locator(".index-name-display").first.text_content()


def test_indexes_ticked_rows(demo_page, base_url, demo):
    page = demo_page
    page.goto(f"{base_url}/runs/{demo['draft']}")
    row_b01 = page.locator("tr.sample-row").filter(has_text="SAMPLE-B01")
    row_b02 = page.locator("tr.sample-row").filter(has_text="SAMPLE-B02")
    row_b01.locator(".sample-checkbox").check()
    row_b02.locator(".sample-checkbox").check()
    with _sample_section_unclipped(page):
        snap(page, "indexes/ticked-rows", row_b02, region=page.locator("table.sample-table"), pad=24)

    # Dropping one index on a ticked row gives that SAME index to every
    # ticked sample plus the one dropped on (app.js:150-183) -- confirmed
    # first, because two samples must not silently share an index. The
    # dialog itself cannot be screenshotted; capture its exact wording
    # (app.js:164-167) instead of picturing it, and accept it so the real
    # assignment goes through.
    messages = []
    page.on("dialog", lambda d: (messages.append(d.message), d.accept()))
    chip = _pair_chip(page, "UDI0010")
    _drag_index(page, chip, row_b01.locator(".drop-zone.i7-drop"))
    page.wait_for_selector('tr.sample-row:has-text("SAMPLE-B02") .assigned-index.i7')
    assert messages == [
        "Give this same index to all 2 samples "
        "(the ticked ones and the one you dropped on)?\n\n"
        "Samples in the same lane must not share an index."
    ]


def test_indexes_fill_preview(demo_page, base_url, demo):
    page = demo_page
    # demo['fill'] (DEMO-RUN-05) has 6 samples and no indexes at all.
    page.goto(f"{base_url}/runs/{demo['fill']}")
    page.get_by_role("button", name="Fill empty samples in order…").click()
    page.wait_for_selector("#index-fill-preview .index-fill-summary")
    preview = page.locator("#index-fill-preview")
    with _sample_section_unclipped(page):
        snap(page, "indexes/fill-preview", preview.locator(".index-fill-table"), region=preview, pad=16)


def test_indexes_fill_assigned(demo_page, base_url, demo):
    page = demo_page
    page.goto(f"{base_url}/runs/{demo['fill']}")
    page.get_by_role("button", name="Fill empty samples in order…").click()
    page.wait_for_selector("#index-fill-preview .index-fill-summary")
    page.get_by_role("button", name="Assign 6 indexes").click()
    # index-fill swaps #sample-section outerHTML; wait for a row to actually
    # carry the assigned index, not the pre-fill drop-zone placeholder.
    page.wait_for_selector('tr.sample-row:has-text("SAMPLE-A01") .assigned-index.i7')
    # #validate-panel refreshes separately, 300ms after any successful
    # non-GET request (_validate_panel.html:41-46); markSampleErrors() (app.js:
    # 383-413) runs on this swap's own htmx:afterSettle first, reusing the
    # *stale* "6 sample(s) have no index" data and wrongly badging every row
    # until the panel's own refresh lands. SAMPLE-A02 gets UDI0002, which has
    # no dark-cycle problem, so its stale badge is the one that must clear;
    # SAMPLE-A01 gets UDI0001, whose i5 read as its reverse complement on
    # NovaSeq X starts with two dark bases -- a genuine dark-cycle error --
    # so its badge is expected to stay.
    page.wait_for_selector('tr.sample-row:has-text("SAMPLE-A02") .row-error-badge', state="detached")
    with _sample_section_unclipped(page):
        snap(page, "indexes/fill-assigned", page.locator("#sample-table"))


# ---------------------------------------------------------------------------
# Lane assignment and override cycles: the bulk-action panel's Lanes and
# Override Cycles rows, the per-row Lanes display, and the per-row Override
# Cycles cell.
# ---------------------------------------------------------------------------


def test_lanes_bulk_panel(demo_page, base_url, demo):
    page = demo_page
    page.goto(f"{base_url}/runs/{demo['draft']}")
    page.locator("tr.sample-row").filter(has_text="SAMPLE-A02").locator(".sample-checkbox").check()
    page.locator("tr.sample-row").filter(has_text="SAMPLE-A03").locator(".sample-checkbox").check()
    # Ticking a sample toggles #bulk-action-panel's has-selection class
    # (app.js updateSampleSelection(), pure client-side), which is what
    # unhides .bulk-action-grid (components.css:633-636) -- the Lanes row
    # lives inside it and is not interactable before this.
    lanes_row = page.locator(".bulk-action-row").filter(has_text="Lanes:")
    lanes_row.locator("input.bulk-lane-checkbox[value='2']").check()
    lanes_row.locator("input.bulk-lane-checkbox[value='3']").check()
    with _sample_section_unclipped(page):
        snap(page, "lanes/bulk-panel", lanes_row, region=page.locator("#bulk-action-panel"), pad=16)

    lanes_row.get_by_role("button", name="Apply").click()
    # set-lanes swaps #sample-section outerHTML; wait for the saved lanes to
    # actually be on the page, not the pre-swap "All" display -- this also
    # proves the save reached the database before this test ends, since
    # test_lanes_row_lanes (below) reads the same run with a fresh page load.
    page.wait_for_selector('tr.sample-row:has-text("SAMPLE-A02") .lanes-display:has-text("2,3")')
    assert page.locator("tr.sample-row").filter(has_text="SAMPLE-A03").locator(".lanes-display").text_content() == "2,3"


def test_lanes_row_lanes(demo_page, base_url, demo):
    page = demo_page
    # test_lanes_bulk_panel (above) already applied lanes 2,3 to SAMPLE-A02
    # and SAMPLE-A03 and confirmed the save landed before returning; this is
    # a fresh full-page load (not an HTMX swap), so the saved lanes are
    # simply what the initial render shows.
    page.goto(f"{base_url}/runs/{demo['draft']}")
    row = page.locator("tr.sample-row").filter(has_text="SAMPLE-A02")
    assert row.locator(".lanes-display").text_content() == "2,3"
    table = page.locator("table.sample-table")
    with _sample_section_unclipped(page):
        snap(page, "lanes/row-lanes", row.locator(".lanes-display"), region=table, pad=24)


def test_override_cycles_cell(demo_page, base_url, demo):
    page = demo_page
    page.goto(f"{base_url}/runs/{demo['draft']}")
    # SAMPLE-A02 was seeded with an index pair written straight into the
    # database (docs_world._sample), bypassing the app's own assign-index
    # routes -- unlike SAMPLE-A05..A08 (assigned by drag-and-drop earlier in
    # this module, which recalculates and stores Override Cycles), A02's
    # Override Cycles was never computed: the cell is empty and shows the
    # "Auto" placeholder even though a real index is assigned.
    row = page.locator("tr.sample-row").filter(has_text="SAMPLE-A02")
    box = row.locator('input[name="override_cycles"]')
    assert box.input_value() == ""
    assert row.locator(".assigned-index.i7").count() == 1
    table = page.locator("table.sample-table")
    with _sample_section_unclipped(page):
        snap(page, "override-cycles/cell", box, region=table, pad=24)


def test_override_cycles_bulk(demo_page, base_url, demo):
    page = demo_page
    page.goto(f"{base_url}/runs/{demo['draft']}")
    page.locator("tr.sample-row").filter(has_text="SAMPLE-A02").locator(".sample-checkbox").check()
    override_row = page.locator(".bulk-action-row").filter(has_text="Override Cycles:")
    override_row.locator("#bulk-override-cycles-input").fill("Y151;I8;I8;Y151")
    with _sample_section_unclipped(page):
        snap(page, "override-cycles/bulk", override_row, region=page.locator("#bulk-action-panel"), pad=16)

    override_row.get_by_role("button", name="Apply").click()
    # set-override-cycles swaps #sample-section outerHTML; wait for the
    # saved value to actually be on the page, not the pre-swap empty input.
    page.wait_for_selector(
        'tr.sample-row:has-text("SAMPLE-A02") input[name="override_cycles"][value="Y151;I8;I8;Y151"]'
    )


# ---------------------------------------------------------------------------
# Check, Mark Ready, downloads and archive.
#
# demo['problem'] (DEMO-RUN-02) is untouched by every test above it: A01 and
# A02 carry the exact same index pair (UDI0001, both i7 and i5 -- a real
# collision), A03 has no index and no test_id. It is never navigated to
# above, so its errors are exactly as seeded. It plays the "run with
# problems" role for the whole Check group below.
#
# demo['ready'] and demo['archived'] were written straight into the database
# with that status (docs_world.seed_demo) -- they never went through the
# real DRAFT->READY route, so their generated_* export fields are None and
# their Export panel would not show what a genuinely-promoted run looks
# like. A brand-new run is built and driven through Mark Ready / Return to
# Draft / Archive for real instead, using UDI0005-UDI0008 -- the same four
# pairs demo['archived'] uses, proven collision- and dark-cycle-free.
# _CLEAN_RUN carries that run's id from test_ready_mark_ready to the tests
# after it (mirroring how test_lanes_bulk_panel hands state to
# test_lanes_row_lanes, except the id itself, not just DB state, has to be
# threaded through since this run isn't one of docs_world's fixed ids).
# ---------------------------------------------------------------------------

_CLEAN_RUN: dict[str, str] = {}


@contextmanager
def _overflow_visible(locator):
    """Same clip as #sample-section (see _sample_section_unclipped above),
    generalised to any locator: an ancestor with overflow-x:auto computes
    overflow-y to auto too (CSS spec), clipping a flush child's outline.
    .table-scroll (components.css:3626) wraps both the Heatmaps and Color
    Balance tables the exact same flush way -- neutralise it for the
    capture only, then restore."""
    previous = locator.evaluate(
        "(e) => { const old = e.style.overflow; e.style.overflow = 'visible'; return old; }"
    )
    try:
        yield
    finally:
        locator.evaluate("(e, old) => { e.style.overflow = old; }", previous)


def test_check_panel(demo_page, base_url, demo):
    page = demo_page
    page.goto(f"{base_url}/runs/{demo['problem']}")
    snap(page, "check/panel", page.locator("#validate-panel"))


def test_check_validation_issues(demo_page, base_url, demo):
    page = demo_page
    page.goto(f"{base_url}/runs/{demo['problem']}/validation")
    # The Issues tab is Alpine's default activeTab and carries no x-cloak
    # (templates/validation/page.html), so it is visible on first paint --
    # no click or wait needed to reach it.
    issues = page.locator(".issues-tab-content")
    snap(page, "check/validation-issues", issues, region=page.locator("#validation-tabs"))


def test_check_heatmaps(demo_page, base_url, demo):
    page = demo_page
    # demo['problem'] only has two indexed samples (A01/A02), and they carry
    # the exact SAME index pair (a deliberate collision, for the Issues-tab
    # picture) -- their heatmap is a single repeated "0 ⚠" cell against two
    # names both truncated to "SAMPLE-A..", which teaches nothing about the
    # "lower = redder = riskier" gradient validation.rst:92-95 describes,
    # and crops out the legend and the i7/i5/combined selector entirely.
    #
    # Build a dedicated Draft run instead, with five samples given short,
    # non-truncating ids and five DIFFERENT index pairs from the same Demo
    # UDI Set A kit, chosen for a genuine spread of pairwise i7 distances --
    # computed directly from docs_world._seq (the kit's own generator, same
    # formula, run offline): UDI0001/UDI0016 are 2 apart (the closest pair in
    # the whole 24-pair kit, still triggering the <=2 warning marker),
    # UDI0009/UDI0024 are 3 apart, UDI0001/UDI0009 are 5, UDI0001/UDI0024 and
    # UDI0016/UDI0009 are 6, and UDI0006 sits 8 away from both UDI0001 and
    # UDI0016 -- distances 2, 3, 5, 6, 8 all appear, so every colour band
    # from dist-2 through dist-8 shows in one table. This run is never
    # marked Ready, so a close pair here is fine -- nothing requires it to
    # be error-free.
    page.goto(f"{base_url}/")
    with page.expect_navigation(url=re.compile(r"/runs/new/step/1")):
        page.get_by_role("button", name="New Run").click()
    run_id = re.search(r"run_id=([^&]+)", page.url).group(1)
    page.fill("#run_name", "DEMO-RUN-07")
    with page.expect_navigation(url=f"{base_url}/runs/{run_id}"):
        page.get_by_role("button", name="Continue to Run").click()

    sample_ids = ["HEAT-01", "HEAT-02", "HEAT-03", "HEAT-04", "HEAT-05"]
    page.fill("#paste_data", "sample_id\ttest_id\n" + "\n".join(
        f"{sid}\tWGS" for sid in sample_ids
    ))
    page.get_by_role("button", name="Preview").click()
    page.wait_for_selector("#paste-area .paste-counts")
    page.get_by_role("button", name=f"Add {len(sample_ids)} samples").click()
    page.wait_for_selector(f'tr.sample-row:has-text("{sample_ids[-1]}")')

    udi_for_sample = dict(zip(
        sample_ids, ["UDI0001", "UDI0016", "UDI0009", "UDI0024", "UDI0006"]
    ))
    for sid, udi in udi_for_sample.items():
        chip = _pair_chip(page, udi)
        row = page.locator("tr.sample-row").filter(has_text=sid)
        _drag_index(page, chip, row.locator(".drop-zone.i7-drop"))
        page.wait_for_selector(f'tr.sample-row:has-text("{sid}") .assigned-index.i7')

    page.goto(f"{base_url}/runs/{run_id}/validation")
    # Every sample is indexed, so the lane's Heatmaps tab is enabled.
    page.get_by_role("button", name="Heatmaps").click()
    lane = page.locator(".lane-heatmap-simple").first
    # .heatmap-header repeats once per view (i7/i5/combined all render into
    # the DOM at once, x-show only toggling which is visible) -- scope the
    # count to the first (i7, the default-visible) .table-scroll.
    assert lane.locator(".table-scroll").first.locator(".heatmap-header").count() == len(sample_ids)
    # region is the WHOLE tab -- selector buttons, description line, the
    # lane table and the legend -- not just the table, so the crop this
    # time includes the i7/i5/combined selector and the colour legend that
    # validation.rst:58 and :101 both point readers at.
    with _overflow_visible(lane.locator(".table-scroll").first):
        snap(page, "check/heatmaps", lane.locator(".heatmap-table").first,
             region=page.locator(".heatmaps-tab-content"))


def test_check_color_balance(demo_page, base_url, demo):
    page = demo_page
    page.goto(f"{base_url}/runs/{demo['problem']}/validation")
    # Button text is "Color Balance" or "Color Balance (N)" depending on
    # whether calculate_color_balance() found any lane issues -- match
    # either (routes/validation.py:_build_color_balance_ctx, templates/
    # validation/page.html).
    page.get_by_role("button", name=re.compile(r"^Color Balance")).click()
    lane = page.locator(".lane-colorbalance-section").first
    with _overflow_visible(lane.locator(".table-scroll").first):
        snap(page, "check/color-balance", lane.locator(".colorbalance-table").first, region=lane)


def test_ready_mark_ready_refused(demo_page, base_url, demo):
    page = demo_page
    # demo['problem'] has real errors (a collision plus a missing test_id),
    # so this refusal is genuine, not staged -- Mark Ready is always
    # clickable in Draft (templates/runs/_run_status_bar.html) and runs its
    # own real-time validation (routes/runs.py:update_status).
    page.goto(f"{base_url}/runs/{demo['problem']}")
    page.get_by_role("button", name="Mark Ready").click()
    page.wait_for_selector("#ready-message .ready-refused")
    banner = page.locator(".ready-refused")
    assert "Cannot mark ready" in banner.text_content()
    snap(page, "ready/mark-ready-refused", banner, region=page.locator("#ready-message"))
    # Refusing must not have moved the run out of Draft.
    assert page.locator("#run-status-bar .status-draft").count() == 1


def test_ready_mark_ready(demo_page, base_url, demo):
    page = demo_page
    # Build a brand-new, real Draft run through the wizard -- not one of
    # docs_world's seeded ids -- so promoting it to Ready is a genuine
    # DRAFT->READY transition, not a fake status written into the DB.
    page.goto(f"{base_url}/")
    with page.expect_navigation(url=re.compile(r"/runs/new/step/1")):
        page.get_by_role("button", name="New Run").click()
    run_id = re.search(r"run_id=([^&]+)", page.url).group(1)
    _CLEAN_RUN["id"] = run_id

    page.fill("#run_name", "DEMO-RUN-06")
    # Continue's own POST /runs/{id}/setup (hx-include="#run-setup-fields")
    # saves whatever is currently in #run_name, so no separate change event
    # is needed before it (templates/wizard/_navigation.html).
    with page.expect_navigation(url=f"{base_url}/runs/{run_id}"):
        page.get_by_role("button", name="Continue to Run").click()

    # Add 4 samples with a real test_id and version -- WGS 1.0.0 is the one
    # test profile docs_world seeds, and prerequisite_run_name /
    # prerequisite_no_samples / prerequisite_missing_indexes /
    # missing_test_id / missing_test_version are all real, error-severity
    # checks (services/validation.py) that would otherwise block Mark Ready
    # below.
    page.fill("#paste_data", "sample_id\ttest_id\ttest_version\n" + "\n".join(
        f"SAMPLE-C0{n}\tWGS\t1" for n in range(1, 5)
    ))
    page.get_by_role("button", name="Preview").click()
    page.wait_for_selector("#paste-area .paste-counts")
    page.get_by_role("button", name="Add 4 samples").click()
    page.wait_for_selector('tr.sample-row:has-text("SAMPLE-C04")')

    # UDI0005-UDI0008: the same four pairs demo['archived'] (DEMO-RUN-04)
    # uses, the proven collision- and dark-cycle-clean set -- UDI0001 and
    # UDI0018 are the kit's two bad pairs and are not used here.
    for n in range(1, 5):
        chip = _pair_chip(page, f"UDI000{4 + n}")
        row = page.locator("tr.sample-row").filter(has_text=f"SAMPLE-C0{n}")
        _drag_index(page, chip, row.locator(".drop-zone.i7-drop"))
        page.wait_for_selector(f'tr.sample-row:has-text("SAMPLE-C0{n}") .assigned-index.i7')

    # Wait for the Check panel's OWN refresh (htmx:afterRequest, delay:300ms
    # -- templates/runs/_validate_panel.html), not just the last row's
    # assigned-index class: the panel refreshes on a separate request from
    # the row swap, and photographing (or trusting) it before that refresh
    # lands would show stale data. Wait on "Indexes: 4/4" specifically (only
    # true post-refresh, once every sample is indexed), not on status_cls
    # == "ok": four distinct real 8bp sequences can still trip a lane's
    # color-balance check at some position (a real, separate, non-error
    # finding -- see color_balance_issue_count, models/validation.py -- which
    # is never added into error_count/has_errors, so it does not refuse Mark
    # Ready below; a color-balance *error* instead makes Mark Ready ask, and
    # this test answers that question), which alone keeps status_cls at
    # "has-warnings" and never "ok"
    # (templates/runs/_validate_panel.html) even with zero errors.
    page.wait_for_selector('#validate-panel .validate-status-badges:has-text("Indexes: 4/4")')
    badges = page.locator("#validate-panel .validate-status-badges")
    assert badges.locator(".status-error").count() == 0
    assert "Samples: 4" in badges.text_content()
    assert "Indexes: 4/4" in badges.text_content()
    assert page.locator("#validate-panel .validate-error-list").count() == 0

    page.get_by_role("button", name="Mark Ready").click()
    # DEMO-RUN-06's four pairs leave color-balance errors (i7 positions 4
    # and 6, in every lane the samples are in), so Mark Ready asks first
    # (spec 2026-09-27, F13).
    question = page.locator("#ready-message .ready-confirm")
    expect(question).to_be_visible()
    snap(page, "ready/mark-ready-color-balance", question, region=page.locator("#ready-message"))
    question.get_by_role("button", name="Mark Ready anyway").click()
    page.wait_for_selector("#run-status-bar .run-status-badge.status-ready")
    snap(page, "ready/mark-ready", page.locator("#run-status-bar .run-status-badge"),
         region=page.locator("#run-status-bar"))


def test_export_panel_ready(demo_page, base_url, demo):
    page = demo_page
    # test_ready_mark_ready (above) left this run genuinely Ready, with
    # exports pre-generated by the real DRAFT->READY route -- the export
    # panel came along for free in that same response (hx-swap-oob on
    # #export-panel, routes/runs.py:update_status), so nothing further is
    # needed to reach it here on a fresh page load.
    page.goto(f"{base_url}/runs/{_CLEAN_RUN['id']}")
    assert page.locator("#run-status-bar .status-ready").count() == 1
    buttons = page.locator("#export-panel .export-buttons")
    assert buttons.locator("a.export-btn.disabled").count() == 0
    snap(page, "export/panel-ready", buttons, region=page.locator("#export-panel"))


def test_ready_back_to_draft(demo_page, base_url, demo):
    page = demo_page
    page.goto(f"{base_url}/runs/{_CLEAN_RUN['id']}")
    page.get_by_role("button", name="Return to Draft").click()
    page.wait_for_selector("#run-status-bar .status-draft")
    snap(page, "ready/back-to-draft", page.locator("#run-status-bar .run-status-badge"),
         region=page.locator("#run-status-bar"))
    # READY->DRAFT clears the pre-generated exports (routes/runs.py:
    # update_status, the elif new_status == RunStatus.DRAFT branch) -- the
    # panel goes back to the one-line "Downloads open..." message.
    page.wait_for_selector("#export-panel .export-waiting")


def test_archive_button(demo_page, base_url, demo):
    page = demo_page
    page.goto(f"{base_url}/runs/{_CLEAN_RUN['id']}")
    # Nothing about the samples or indexes changed since test_ready_mark_
    # ready, so this re-promotion is still a genuine, error-free
    # DRAFT->READY transition, not a repeat of a stale check.
    page.get_by_role("button", name="Mark Ready").click()
    # Same four pairs, so the same color-balance errors as in
    # test_ready_mark_ready: answer the question again (spec 2026-09-27, F13).
    page.locator("#ready-message .ready-confirm").get_by_role(
        "button", name="Mark Ready anyway").click()
    page.wait_for_selector("#run-status-bar .status-ready")
    snap(page, "archive/archive-button", page.get_by_role("button", name="Archive"),
         region=page.locator("#run-status-bar"))


# ---------------------------------------------------------------------------
# Run templates and change history.
# ---------------------------------------------------------------------------


def test_templates_save_as_template(demo_page, base_url, demo):
    page = demo_page
    # Save as template (routes/run_templates.py:103) depends on
    # get_archivable_run, not get_editable_run (routes/run_templates.py:106)
    # -- it works on a run of any status because it only reads the run. The
    # only UI entry point for this form is this fieldset
    # (templates/runs/edit.html:44-50); its hidden scaffold_sample_ids input
    # is hard-coded to "[]", so this never captures the run's samples.
    page.goto(f"{base_url}/runs/{demo['draft']}")
    fieldset = page.locator("fieldset:has(#template-name)")
    page.fill("#template-name", "Nightly QC Batch")
    snap(page, "templates/save-as-template",
         fieldset.get_by_role("button", name="Save as template"),
         region=fieldset)
    with page.expect_navigation(url=re.compile(r"/templates$")):
        fieldset.get_by_role("button", name="Save as template").click()


def test_templates_manage(demo_page, base_url, demo):
    page = demo_page
    # test_templates_save_as_template (above) already redirected here; go
    # explicitly so this test does not depend on that navigation happening.
    page.goto(f"{base_url}/templates")
    row = page.locator("div[id^='template-item-']").filter(has_text="Nightly QC Batch")
    snap(page, "templates/manage", row.get_by_role("button", name="Delete"),
         region=page.locator(".border.rounded"))


def test_templates_new_run_from_template(demo_page, base_url, demo):
    page = demo_page
    page.goto(f"{base_url}/templates")
    row = page.locator("div[id^='template-item-']").filter(has_text="Nightly QC Batch")
    # POST /runs/new/from-template/{id} (routes/run_templates.py:212) is a
    # plain <form method="post"> (templates/run_templates/list.html:20) --
    # a real navigation, not HTMX -- straight to the fresh Draft, whose
    # run_name is the template's name (services/run_builder.py:143).
    with page.expect_navigation(url=re.compile(r"/runs/[0-9a-f-]{36}$")):
        row.get_by_role("button", name="New run").click()
    title = page.locator("h1.run-title")
    assert title.text_content().strip() == "Nightly QC Batch"
    snap(page, "templates/new-run-from-template", title, region=page.locator(".run-header"))


def test_history_change_history(demo_page, base_url, demo):
    page = demo_page
    # _CLEAN_RUN (test_ready_mark_ready, above) is DEMO-RUN-06 -- a real run
    # driven through the wizard, sample paste, index drag, and two Mark
    # Ready promotions with a Return to Draft in between. Every one of
    # those saves went through `with saving_run(...)` (routes/
    # dependencies.py), so each is already in its change history.
    # test_archive_button (above) re-promoted it to Ready and stopped just
    # short of clicking Archive; finish that here so the trail covers this
    # run's whole life, start to finish, including its "created" entry.
    page.goto(f"{base_url}/runs/{_CLEAN_RUN['id']}")
    assert page.locator("#run-status-bar .status-ready").count() == 1
    page.get_by_role("button", name="Archive").click()
    page.wait_for_selector("#run-status-bar .status-archived")

    panel = page.locator(".run-history-panel")
    panel.scroll_into_view_if_needed()
    # hx-trigger="revealed" (templates/runs/edit.html:56-61) swaps this
    # element's entire innerHTML once the history loads. Wait for a real
    # entry row (".border-t", templates/runs/_history_list.html:6), which
    # exists only after that swap -- the pre-load "Loading history..." text
    # would otherwise satisfy a weaker wait and photograph the wrong state.
    page.wait_for_selector(".run-history-panel .border-t")
    fieldset = page.locator("fieldset:has(.run-history-panel)")
    # The times of day differ per run; fixed example times keep the picture
    # the same (newest first, one per entry).
    replace_text(panel, r"\d{4}-\d{2}-\d{2} \d{2}:\d{2} [A-Z]{3,4}", [
        "2026-03-10 10:17 CET", "2026-03-10 10:16 CET", "2026-03-10 10:15 CET",
        "2026-03-10 10:15 CET", "2026-03-10 10:14 CET", "2026-03-10 10:14 CET",
        "2026-03-10 10:14 CET", "2026-03-10 10:14 CET", "2026-03-10 10:13 CET",
        "2026-03-10 10:12 CET", "2026-03-10 10:12 CET"])
    snap(page, "history/change-history", panel, region=fieldset)


# ---------------------------------------------------------------------------
# Admin: local users, authentication, API tokens, and application logs.
# ---------------------------------------------------------------------------


def test_admin_users_list(demo_page, base_url, demo):
    page = demo_page
    # local_users.router is admin-only (routes/local_users.py:36-39); the
    # create form posts to /admin/users/create (routes/local_users.py:118),
    # which swaps the whole #local-users-page (local_users.html:23-26).
    page.goto(f"{base_url}/admin/users")
    page.fill("#new_username", "taylor.audit")
    page.fill("#new_display_name", "Taylor Audit")
    page.fill("#new_email", "taylor.audit@example.org")
    page.fill("#new_password", "Taylor-Docs-2026!")
    page.get_by_role("button", name="Create User").click()
    # user-row-{{ username }} (local_users.html:86) contains a literal '.',
    # which an ID selector would misparse as a class -- use an attribute
    # selector instead.
    row = page.locator('tr[id="user-row-taylor.audit"]')
    row.wait_for()
    table = page.locator("table:has(tr[id='user-row-taylor.audit'])")
    # The new user's Created time differs per run; a fixed example keeps the
    # picture the same.
    replace_text(row, r"\d{4}-\d{2}-\d{2} \d{2}:\d{2} [A-Z]{3,4}", ["2026-03-10 10:20 CET"])
    snap(page, "admin/users-list", row.get_by_role("button", name="Edit"), region=table)


def test_admin_user_edit(demo_page, base_url, demo):
    page = demo_page
    # Fresh page/session per test (demo_page is function-scoped) -- the user
    # created above persists in the shared demo world's database.
    page.goto(f"{base_url}/admin/users")
    row = page.locator('tr[id="user-row-taylor.audit"]')
    row.get_by_role("button", name="Edit").click()
    # editing=true is a client-side Alpine toggle within the same <tr>
    # (local_users.html:86,107-113) -- no network round trip, so wait on
    # the now-visible role <select> rather than assuming the click landed.
    role_select = row.locator("select[name='role']")
    role_select.wait_for(state="visible")
    snap(page, "admin/user-edit", row.get_by_role("button", name="Save"), region=row)


def test_admin_auth_settings(demo_page, base_url, demo):
    page = demo_page
    # admin_authentication.router is admin-only (routes/admin/
    # authentication.py:54-57). Selecting LDAP auto-saves via hx-post
    # (authentication.html:26-36) and swaps in the whole #ldap-config-form,
    # which now reveals the LDAP connection fieldset (routes/admin/
    # authentication.py:133-159; authentication.html:57-63).
    page.goto(f"{base_url}/admin/authentication")
    page.check("#auth_method_ldap")
    # The connection-settings heading exists ONLY after the swap reveals it
    # -- a stronger wait than the radio's own `checked` state, which is
    # already true before the network round trip completes.
    page.wait_for_selector("h3:has-text('LDAP/AD Connection Settings')")
    fieldset = page.locator("fieldset", has_text="Authentication Method")
    snap(page, "admin/auth-settings",
         fieldset.locator("label:has(input[name='allow_local_fallback'])"),
         region=fieldset)


def test_admin_api_tokens(demo_page, base_url, demo):
    page = demo_page
    # api_tokens.router is admin-only (routes/api_tokens.py:35-38). No
    # token is seeded by docs_world.seed_demo, so this is the true empty
    # state; the form is filled in but not submitted, so it stays empty
    # for this test only.
    page.goto(f"{base_url}/admin/api-tokens")
    fieldset = page.locator("fieldset", has_text="Create New Token")
    fieldset.locator("#token_name").fill("Docs LIMS Reader")
    snap(page, "admin/api-tokens", fieldset.get_by_role("button", name="Create Token"),
         region=fieldset)


def test_admin_api_token_created(demo_page, base_url, demo):
    page = demo_page
    # create_api_token (routes/api_tokens.py:72-118) returns the plaintext
    # ONLY in this response -- new_token is always "" on a plain GET
    # (routes/api_tokens.py:65) -- so the reveal has to be captured in the
    # same request/response as the create, not a fresh page load.
    page.goto(f"{base_url}/admin/api-tokens")
    page.fill("#token_name", "Docs LIMS Reader")
    page.get_by_role("button", name="Create Token").click()
    reveal = page.locator("div.bg-amber-50", has_text="Token Created")
    reveal.wait_for()
    # The token is random; a fixed made-up one of the same length keeps the
    # picture the same.
    replace_text(reveal.locator(".font-mono"), r"\S+",
                 ["q7Rk2VbN9xLw4sTz8MfH3cJd6pYa1GeU5nKo0WiQ-tE"])
    snap(page, "admin/api-token-created", reveal)


@contextmanager
def _logs_table_unclipped(page):
    """.table-scroll's overflow-x:auto (components.css:3626) computes
    overflow-y to auto too, clipping the outline on any descendant flush
    with its box -- the same mechanism as _sample_section_unclipped above.
    The entries <table> sits directly inside it with no padding, so every
    row is flush against its left/right edges. Neutralise for the moment
    of capture only, the same way shoot() itself neutralises the outline
    style: set + revert an inline style, no src/ or docs_shots.py change."""
    wrap = page.locator("#logs-page .table-scroll")
    previous = wrap.evaluate(
        "(e) => { const old = e.style.overflow; e.style.overflow = 'visible'; return old; }"
    )
    try:
        yield
    finally:
        wrap.evaluate("(e, old) => { e.style.overflow = old; }", previous)


def test_admin_logs(demo_page, base_url, demo):
    page = demo_page
    # admin_logs.router is admin-only (routes/admin/logs.py:27-30).
    #
    # This buffer holds SeqSetup's warnings and errors. Audit events are kept
    # out of it on purpose (log_capture._not_audit_record) -- they are on the
    # Audit trail page, pictured in test_admin_audit_trail -- so a picture
    # of this page needs a genuine WARNING.
    #
    # A real WARNING-level event that DOES pass the default threshold:
    # OriginCheckMiddleware (csrf.py:96-135) rejects any POST/PUT/PATCH/
    # DELETE with no Origin header, logging the rejection at WARNING
    # (csrf.py:130) before the request ever reaches routing -- so the path
    # doesn't need to exist. Playwright's request client (unlike a real
    # browser fetch) sends no Origin header, so this POST is rejected for
    # exactly that reason, producing a genuine, safe log line with no secret
    # or patient-like content in it. Two distinct paths are probed below so
    # the buffer holds two distinguishable entries, not one.
    probe_path = "/admin/csrf-probe-for-docs"
    resp = page.request.post(f"{base_url}{probe_path}")
    assert resp.status == 403

    # A second, NON-matching WARNING line, planted by the same technique with
    # a different path -- BEFORE filtering. Without it, the buffer holds
    # exactly one entry at the point Refresh is exercised below, so an
    # unfiltered reload and a filtered reload would both render 1 row and the
    # Refresh assertion could not tell "kept the filter" from "cleared it".
    # With a second, distinguishable entry present, only an unfiltered view
    # shows both -- the paths share no substring, so the Search filter below
    # (which matches on probe_path) still excludes this one.
    other_probe_path = "/admin/other-warning-for-docs"
    other_resp = page.request.post(f"{base_url}{other_probe_path}")
    assert other_resp.status == 403

    page.goto(f"{base_url}/admin/logs")
    page.select_option("#level", "WARNING")
    page.fill("#search", probe_path)
    page.get_by_role("button", name="Filter").click()
    # Waiting merely for a row containing this text would be satisfied by
    # the PRE-filter page too, if it were already within the default
    # unfiltered view -- wait instead for the row COUNT to drop to exactly
    # the one match, which only the filtered result can satisfy (the second
    # probe's message does not contain probe_path, so it stays excluded).
    page.wait_for_function(
        "document.querySelectorAll('#logs-page tbody tr').length === 1"
    )
    row = page.locator("#logs-page tbody tr").filter(has_text=probe_path)
    # The log time differs per run; a fixed example keeps the picture the
    # same. Refresh, below, reloads the table, so the check there is unaffected.
    replace_text(row, r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [A-Z]{3,4}", ["2026-03-10 10:21:08 CET"])
    with _logs_table_unclipped(page):
        snap(page, "admin/logs", row, region=page.locator("#logs-page .table-scroll"))

    # Behavioural check (not a picture): does Refresh (logs.html:64-68,
    # hx-get with no explicit hx-include) keep the applied filters, or
    # clear them? Refresh is a bare <button type="button" hx-get="/admin/logs">
    # with no hx-include of its own and no level/search query params in its
    # hx-get URL -- htmx does not include an enclosing form's inputs on a GET
    # unless told to. Confirm the real behaviour here rather than assuming.
    #
    # hx-swap="outerHTML" (logs.html:45,67) replaces the whole #logs-page
    # node -- .table-scroll included -- with a brand-new one carrying the
    # same selector, so waiting on "#logs-page .table-scroll" alone can be
    # satisfied by the PRE-refresh node that is still in the DOM the instant
    # .click() returns (.click() does not await htmx's request). Capture a
    # handle to the current node before clicking and wait for THAT node to
    # be detached, which can only happen once the outerHTML swap has
    # actually completed.
    old_table = page.locator("#logs-page .table-scroll").element_handle()
    page.get_by_role("button", name="Refresh").click()
    page.wait_for_function("(el) => !document.contains(el)", arg=old_table)
    page.wait_for_selector("#logs-page .table-scroll")

    # If Refresh kept the applied filters, the Level select and Search box
    # would still read WARNING / probe_path and only the 1 filtered row would
    # be showing. It does not: both fields reset to "All Levels" / empty, and
    # BOTH planted entries are now visible -- proof Refresh reloads
    # unfiltered, not "with the same filters still applied".
    level_value = page.locator("#level").input_value()
    search_value = page.locator("#search").input_value()
    refreshed_rows = page.locator("#logs-page tbody tr").count()
    assert (level_value, search_value, refreshed_rows) == ("", "", 2), (
        "Refresh was expected to reset both filters and reload unfiltered, "
        f"showing both planted entries, but got level={level_value!r} "
        f"search={search_value!r} rows={refreshed_rows}"
    )


def test_admin_audit_trail(demo_page, base_url, demo):
    page = demo_page
    # Mark Ready, Back to Draft and Archive were done through the UI by the
    # pictures above, so the trail holds real run.status.changed events.
    page.goto(f"{base_url}/admin/audit")
    page.fill("#event", "run.status")
    page.get_by_role("button", name="Search").click()
    # The unfiltered page also lists login and sample events; wait until
    # every row is a run.status one, which only the filtered result shows.
    page.wait_for_function(
        "(() => { const cells = [...document.querySelectorAll("
        "'#audit-page tbody tr td:nth-child(3)')];"
        " return cells.length > 0 && cells.every("
        "td => td.textContent.trim().startsWith('run.status')); })()"
    )
    table = page.locator("#audit-page .table-scroll")
    # The times of day (the change history's, to the second) and the random
    # ID of the run made in the wizard differ per run; fixed examples keep
    # the picture the same (newest first, one per event).
    replace_text(table, r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [A-Z]{3,4}", [
        "2026-03-10 10:17:04 CET", "2026-03-10 10:16:41 CET", "2026-03-10 10:16:38 CET",
        "2026-03-10 10:15:52 CET", "2026-03-10 10:15:20 CET", "2026-03-10 10:15:17 CET",
        "2026-03-10 10:11:30 CET"])
    replace_text(table, r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                 ["3f2b8c1e-5a47-4d0e-9b6a-7c1d2e8f4a60"] * 6)
    snap(page, "admin/audit-trail", table, region=page.locator("#audit-page"))


# DEMO-RUN-06 and -07 are used by earlier pictures; this made-up deleted run
# is DEMO-RUN-08. Fixed times, so the pictures do not drift.
DELETED_COPY_ID = "demo-deleted-copy-01"


def _seed_deleted_run(app_ctx):
    if app_ctx.deleted_run_repo.get(DELETED_COPY_ID) is not None:
        return
    run_id = "demo-run-08"
    run = _run(run_id, "DEMO-RUN-08", RunStatus.ARCHIVED,
               samples=[_sample(run_id, n, _pair(n)) for n in range(9, 13)])
    app_ctx.run_history_repo.append(RunHistoryEntry(
        run_id=run_id, timestamp=datetime(2026, 3, 2, 9, 0), actor=DEMO_ADMIN["username"],
        kind="created", provenance={"source": "blank", "ref": None}))
    for when, before, after in ((datetime(2026, 3, 3, 10, 0), "draft", "ready"),
                                (datetime(2026, 3, 5, 16, 0), "ready", "archived")):
        app_ctx.run_history_repo.append(RunHistoryEntry(
            run_id=run_id, timestamp=when, actor=DEMO_ADMIN["username"], kind="updated",
            field_changes=[{"field": "status", "before": before, "after": after}]))
    copy = DeletedRun.of(run, DEMO_ADMIN["username"], datetime(2026, 3, 9, 14, 30))
    copy.copy_id = DELETED_COPY_ID
    app_ctx.deleted_run_repo.start(copy)
    app_ctx.deleted_run_repo.mark_completed(DELETED_COPY_ID, datetime(2026, 3, 9, 14, 30))


def test_admin_deleted_runs(demo_page, base_url, demo, app_ctx):
    page = demo_page
    _seed_deleted_run(app_ctx)
    page.goto(f"{base_url}/admin/deleted-runs")
    table = page.locator("#deleted-runs-page .table-scroll")
    expect(table).to_contain_text("DEMO-RUN-08")
    snap(page, "admin/deleted-runs", table, region=page.locator("#deleted-runs-page"))


def test_admin_deleted_run(demo_page, base_url, demo, app_ctx):
    page = demo_page
    _seed_deleted_run(app_ctx)
    page.goto(f"{base_url}/admin/deleted-runs/{DELETED_COPY_ID}")
    panel = page.locator("#deleted-run-page .run-history-panel")
    panel.scroll_into_view_if_needed()
    # hx-trigger="revealed": wait for a real entry row, not "Loading history…".
    page.wait_for_selector("#deleted-run-page .run-history-panel .border-t")
    samples = page.locator("#deleted-run-page fieldset").filter(has_text="Sample IDs")
    snap(page, "admin/deleted-run", samples, region=page.locator("#deleted-run-page"))


def test_admin_index_kits_list(demo_page, base_url, demo):
    page = demo_page
    # index_kits_page has no admin dependency at all (routes/indexes.py:
    # 108-119) -- every authenticated user can see the kit list. Only the
    # "+ Import Index Kit" link is admin-gated, in the template itself
    # (indexes/list.html:12-14); the upload routes are separately admin-only
    # (routes/indexes.py:122,134). The demo world seeds exactly one kit
    # (DEMO_KIT_NAME), and nothing before this test in the module adds
    # another, so this is still the single-kit view.
    page.goto(f"{base_url}/indexes")
    assert DEMO_KIT_NAME in page.locator("#indexes-page").text_content()
    # region was just the header div -- a crop with no kit in it, though the
    # page is about the list. Widen it to the whole page container so the
    # single seeded kit's card is in frame too.
    snap(page, "admin/index-kits-list",
         page.get_by_role("link", name="+ Import Index Kit"),
         region=page.locator("#indexes-page"))


def test_admin_index_kit_upload(demo_page, base_url, demo):
    page = demo_page
    # /indexes/import (the form page) and /indexes/upload (the handler) are
    # both admin-only (routes/indexes.py:122,134). Upload a made-up kit
    # through the real form, in the simple CSV format the file-format-help
    # <details> on this page documents (name,index,index2 -- parsed by
    # IndexParser._parse_csv, services/index_parser.py:503-505).
    page.goto(f"{base_url}/indexes/import")
    csv_content = (
        "name,index,index2\n"
        "DP01,ACGTGCAT,TGCATACG\n"
        "DP02,GGCTAACG,CATGGTAC\n"
        "DP03,TACGGATC,AGCTTGCA\n"
        "DP04,CTGATCGA,GTACCTAG\n"
    )
    # A real filename, not tempfile's random name -- it shows in the
    # browser's own file input and ends up in the picture.
    tmp_dir = tempfile.mkdtemp()
    tmp_path = os.path.join(tmp_dir, "docs-demo-panel.csv")
    with open(tmp_path, "w", newline="") as f:
        f.write(csv_content)
    try:
        page.set_input_files("#index_file", tmp_path)
        page.fill("#kit_name", "Docs Demo Panel")
        page.fill("#kit_version", "2.0")
        page.fill("#kit_description", "Made-up panel kit for the admin guide screenshots")
        form = page.locator("form[hx-post='/indexes/upload']")
        snap(page, "admin/index-kit-upload",
             form.get_by_role("button", name="Upload Index Kit"), region=form)
        # A successful upload responds with HX-Redirect: /indexes (indexes.py:
        # 251-252), which htmx turns into a real navigation.
        with page.expect_navigation(url=re.compile(r"/indexes$")):
            form.get_by_role("button", name="Upload Index Kit").click()
    finally:
        os.unlink(tmp_path)
        os.rmdir(tmp_dir)
    assert "Docs Demo Panel" in page.locator("#indexes-page").text_content()


def test_admin_index_kit_detail(demo_page, base_url, demo):
    page = demo_page
    # Navigate the way a user would: from the list, into the kit just
    # uploaded above. can_delete is true for dana.demo both as admin and as
    # the kit's own uploader (indexes/detail.html:92, routes/indexes.py:
    # 271-279) -- Delete is admin-only-or-owner, not admin-only.
    page.goto(f"{base_url}/indexes")
    card = page.locator("div.bg-white.border.rounded-lg").filter(has_text="Docs Demo Panel")
    with page.expect_navigation(url=re.compile(r"/indexes/detail/")):
        card.get_by_role("link", name="View").click()
    delete_button = page.get_by_role("button", name="Delete")
    # Region: the whole page's content container (indexes/detail.html:6),
    # not just the button row -- the caption promises the kit's name,
    # settings, and index pairs are visible, not only the buttons.
    panel = page.locator("div.space-y-6").filter(has=delete_button)
    snap(page, "admin/index-kit-detail", delete_button, region=panel)


def test_admin_instruments(demo_page, base_url, demo, app_ctx):
    page = demo_page
    # /admin/instruments is admin-only (routes/admin/instruments.py:31-34)
    # and manages only SYNCED instrument definitions. config/instruments.yaml
    # ships no synced instruments and no reagent_kit_max_cycles for any
    # instrument at all (see that file's own closing comment) -- with none
    # synced, the page shows the "Using local configuration file as
    # fallback" note instead of the enable/disable table (admin/
    # instruments.html:16-23). Seed two directly through the repository,
    # the same way docs_world.py and test_new_run_cycle_limit_exceeded above
    # do, so this is the real toggle table, not the fallback note.
    definitions = [
        InstrumentDefinition(
            name="Docs Demo NovaSeq", samplesheet_name="DocsDemoNovaSeq",
            chemistry_type="2-color", has_dragen_onboard=True,
            i5_workflows=[{"name": "Standard", "i5_read_orientation": "reverse-complement"}],
            runinfo_marks_i5_reversed=True,
            flowcells=[FlowcellDefinition(name="10B", lanes=8, reads=10_000_000_000)],
            enabled=True,
        ),
        InstrumentDefinition(
            name="Docs Demo MiniSeq", samplesheet_name="DocsDemoMiniSeq",
            chemistry_type="4-color", has_dragen_onboard=False,
            i5_workflows=[{"name": "Standard", "i5_read_orientation": "forward"}],
            runinfo_marks_i5_reversed=False,
            flowcells=[FlowcellDefinition(name="Standard", lanes=1, reads=25_000_000)],
            enabled=False,
        ),
    ]
    for definition in definitions:
        app_ctx.instrument_definition_repo.save(definition)
    clear_synced_instruments_cache()
    try:
        page.goto(f"{base_url}/admin/instruments")
        enabled_row = page.locator("tr").filter(has_text="Docs Demo NovaSeq")
        section = page.locator("#synced-instruments-section")
        snap(page, "admin/instruments", enabled_row.locator("input[type=checkbox]"), region=section)
    finally:
        app_ctx.instrument_definition_repo.delete_all()
        clear_synced_instruments_cache()


def test_admin_config_sync(demo_page, base_url, demo):
    page = demo_page
    # admin_config_sync.router is admin-only (routes/admin/config_sync.py:
    # 27-30). Saving this form never touches the network (routes/admin/
    # config_sync.py:77-113); only the separate "Run Manual Sync" button
    # does (config_sync.py:116-144), which this test never clicks.
    page.goto(f"{base_url}/admin/config-sync")
    page.fill("#github_repo_url", "https://github.com/example-org/seqsetup-config")
    page.fill("#github_branch", "main")
    form = page.locator("form[hx-post='/admin/config-sync/config']")
    form.get_by_role("button", name="Save Configuration").click()
    # hx-swap="outerHTML" on #config-sync-page replaces the whole node
    # (config_sync.py:108-113); wait for the success banner that only the
    # swapped-in fragment carries before re-querying it.
    page.wait_for_selector("text=Configuration saved")
    form = page.locator("form[hx-post='/admin/config-sync/config']")
    snap(page, "admin/config-sync",
         form.get_by_role("button", name="Save Configuration"), region=form)


def test_admin_lims_settings(demo_page, base_url, demo):
    page = demo_page
    # The demo world seeds no LIMS config, so sample_api_enabled = bool(cfg
    # and cfg.enabled and cfg.base_url) (routes/runs.py:534) is False and the
    # run-editing page's "Load Worklists" panel (wizard/
    # _fetch_from_api_section.html:17-19) does not render at all -- confirm
    # that directly, since it is the reason this test photographs the ADMIN
    # settings page instead.
    page.goto(f"{base_url}/runs/{demo['draft']}")
    assert page.get_by_role("button", name="Load Worklists").count() == 0

    # admin_sample_api.router is admin-only (routes/admin/sample_api.py:
    # 36-39); ctx.sample_api_config_repo is never None in the running app
    # (startup.py:174-175,197), so this page always renders, unlike the
    # run-page panel above. Fill but do not submit: submitting with
    # enabled=True would call check_connection() (routes/admin/
    # sample_api.py:107-109), a real network request this suite must not
    # make.
    page.goto(f"{base_url}/admin/sample-api")
    page.fill("#base_url", "https://lims.example.org/api")
    page.check("input[name=enabled]")
    form = page.locator("#sample-api-config-form")
    snap(page, "admin/lims-settings",
         form.get_by_role("button", name="Save Configuration"), region=form)
