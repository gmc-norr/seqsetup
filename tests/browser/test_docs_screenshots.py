"""Documentation screenshots: drive the real app in a made-up demo world and
save outlined crops into docs/_static/screenshots/.

Skipped unless SEQSETUP_DOCS_SCREENSHOTS=1 (`pixi run docs-screenshots`).
Tests run in file order; later tests may rely on what earlier ones did.
The browser-test database is snapshotted before and restored after, so
other browser tests never see the demo world.
"""

import os
import re
from contextlib import contextmanager
from pathlib import Path

import pytest

from seqsetup.data.instruments import clear_synced_instruments_cache
from seqsetup.models.instrument_definition import FlowcellDefinition, InstrumentDefinition
from seqsetup.services import database

from .docs_shots import shoot
from .docs_world import DEMO_ADMIN, DEMO_KIT_NAME, clear, reset_caches, restore, seed_demo, snapshot

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
    page.goto(f"{base_url}/runs/{demo['problem']}/validation")
    # A01 and A02 are both indexed (A03 is not), so every lane has two
    # indexed samples and the Heatmaps tab is enabled, not disabled.
    page.get_by_role("button", name="Heatmaps").click()
    lane = page.locator(".lane-heatmap-simple").first
    # region=lane (the table plus its own "Lane 1 (2 samples)" header) is
    # only 12px above the sibling .heatmap-legend row that follows
    # .lane-heatmaps in the DOM (components.css: .heatmap-legend's 0.75rem
    # margin-top) -- shoot()'s default 16px pad overshoots that gap and
    # slices the legend's colour swatches into the bottom of the crop.
    # Measured live: shrinking .lane-heatmap-simple's own padding does not
    # help -- the flex layout just pulls the legend up by the same amount,
    # so the gap to it stays 12px regardless. A smaller pad is what
    # actually keeps the crop inside that gap.
    with _overflow_visible(lane.locator(".table-scroll").first):
        snap(page, "check/heatmaps", lane.locator(".heatmap-table").first, region=lane, pad=6)


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
    page.wait_for_selector("#error-banner .ready-refused")
    banner = page.locator(".ready-refused")
    assert "Cannot mark ready" in banner.text_content()
    snap(page, "ready/mark-ready-refused", banner, region=page.locator("#error-banner"))
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

    # Add 4 samples with a real test_id -- WGS is the one test profile
    # docs_world seeds, and prerequisite_run_name / prerequisite_no_samples
    # / prerequisite_missing_indexes / missing_test_id are all real,
    # error-severity checks (services/validation.py:280-314,836-862) that
    # would otherwise block Mark Ready below.
    page.fill("#paste_data", "sample_id\ttest_id\n" + "\n".join(
        f"SAMPLE-C0{n}\tWGS" for n in range(1, 5)
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
    # finding -- see color_balance_issue_count, models/validation.py:313-
    # 316 -- which is never added into error_count/has_errors,
    # models/validation.py:286-304, so it cannot block Mark Ready below),
    # which alone keeps status_cls at "has-warnings" and never "ok"
    # (templates/runs/_validate_panel.html:27-34) even with zero errors.
    page.wait_for_selector('#validate-panel .validate-status-badges:has-text("Indexes: 4/4")')
    badges = page.locator("#validate-panel .validate-status-badges")
    assert badges.locator(".status-error").count() == 0
    assert "Samples: 4" in badges.text_content()
    assert "Indexes: 4/4" in badges.text_content()
    assert page.locator("#validate-panel .validate-error-list").count() == 0

    page.get_by_role("button", name="Mark Ready").click()
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
    snap(page, "history/change-history", panel, region=fieldset)
