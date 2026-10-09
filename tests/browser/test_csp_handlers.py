"""CSP delegation tests — prove every run-editor handler works under the real
app CSP (script-src 'self' 'unsafe-eval', no 'unsafe-inline').

The DRAFT_RUN_ID run has:
  - 3 indexed samples (SAMPLE-01/02/03 with pair kit UDP0001/02/03)
  - 3 unindexed samples (SAMPLE-04/05/06)
  - bulk-action panel (show_bulk_actions=True)
  - index panel sidebar with pair-kit chips (UDP0001..0004)

Mutation tests (test_bulk_apply_testid_updates_samples) create a SEPARATE
run via the app so they do not corrupt the session-scoped seeded state used
by the screenshot tests.

All tests use the real app (with the real CSP headers) — they would fail
if any of the tested interactions still relied on blocked inline on* handlers.
"""

import pytest


@pytest.mark.browser
def test_sample_checkbox_select_adds_selected_class(logged_in_page, base_url, seeded_ids):
    """Clicking a .sample-checkbox adds class 'selected' to the parent .sample-row.

    Proves handleSampleCheckboxClick delegation fires via the new document
    click listener (not the removed inline onclick).
    """
    page = logged_in_page
    run_id = seeded_ids["draft_run_id"]
    page.goto(f"{base_url}/runs/{run_id}")
    page.wait_for_load_state("networkidle")

    # Click the first sample checkbox
    first_checkbox = page.locator(".sample-checkbox").first
    first_checkbox.click()

    # The parent sample-row should gain class 'selected'
    first_row = page.locator(".sample-row").first
    assert "selected" in (first_row.get_attribute("class") or ""), (
        "Expected .sample-row to have class 'selected' after clicking .sample-checkbox"
    )


@pytest.mark.browser
def test_select_all_checkbox_checks_all_samples(logged_in_page, base_url, seeded_ids):
    """Clicking .select-all-checkbox checks every .sample-checkbox.

    Proves toggleSelectAllSamples delegation fires via the document click
    listener (not the removed inline onclick).
    """
    page = logged_in_page
    run_id = seeded_ids["draft_run_id"]
    page.goto(f"{base_url}/runs/{run_id}")
    page.wait_for_load_state("networkidle")

    # Get count of sample checkboxes before clicking select-all
    checkbox_count = page.locator(".sample-checkbox").count()
    assert checkbox_count > 0, "No .sample-checkbox elements found — seeded run has no samples?"

    # Click the select-all checkbox
    page.locator(".select-all-checkbox").click()

    # Every .sample-checkbox should now be checked
    unchecked = page.locator(".sample-checkbox:not(:checked)").count()
    assert unchecked == 0, (
        f"{unchecked} sample checkboxes still unchecked after clicking select-all"
    )


@pytest.mark.browser
def test_bulk_apply_testid_updates_samples(logged_in_page, base_url, mutable_run_id):
    """Navigate to a self-cleaning mutable run, select a sample, pick a test
    ID, click Apply — assert the sample row reflects the new test ID after the
    HTMX swap.

    Uses a function-scoped mutable run (created + deleted per test via the
    repo) so the session-scoped screenshot baseline is never touched.

    Proves data-action='bulk-apply-testid' delegation triggers the real
    HTMX bulk-set-test-id request end-to-end.
    """
    page = logged_in_page
    run_id = mutable_run_id

    # ---- Navigate the browser to the run editor ----
    page.goto(f"{base_url}/runs/{run_id}")
    page.wait_for_load_state("networkidle")

    # Verify samples loaded (checkboxes visible)
    page.wait_for_selector(".sample-checkbox", timeout=5000)

    # Select the first sample checkbox
    page.locator(".sample-checkbox").first.click()

    # Wait for the bulk panel count to update
    page.wait_for_function(
        "document.getElementById('selected-sample-count') && "
        "parseInt(document.getElementById('selected-sample-count').textContent) > 0"
    )

    # Select WGS from the test-id dropdown, with its version (set together)
    page.select_option("#bulk-test-id-input", value="WGS")
    page.locator("#bulk-test-version-input").fill("1")

    # Click [data-action="bulk-apply-testid"] and capture the HTMX round-trip
    with page.expect_response(lambda r: "set-test-id" in r.url) as response_info:
        page.locator('[data-action="bulk-apply-testid"]').click()
    resp = response_info.value
    assert resp.status == 200, f"set-test-id returned HTTP {resp.status}"

    # After the HTMX swap, the test-id cell (td 3) should contain "WGS"
    page.wait_for_selector(".sample-row td:nth-child(3):has-text('WGS')", timeout=5000)


@pytest.mark.browser
def test_drag_drop_assigns_index_to_sample(logged_in_page, base_url, mutable_run_id):
    """Drag an index chip onto a sample drop zone and assert a REAL assignment.

    Proves the delegated dragstart/dragover/drop handlers in app.js are wired
    (the inline ondragstart/ondrop were removed because the CSP blocks them).

    Robustness:
      * Playwright can't drive a native HTML5 drag, so the drag is synthesized.
        We return the payload ``handleDragStart`` wrote into the DataTransfer and
        assert it carried — a browser that no-ops ``setData`` then fails with a
        clear message instead of a mystery DOM timeout.
      * We wait on the ``assign-index`` POST the drop triggers (deterministic)
        rather than polling the DOM, then confirm the row became indexed.
    """
    page = logged_in_page
    page.goto(f"{base_url}/runs/{mutable_run_id}")
    page.wait_for_load_state("networkidle")

    assert page.locator(".draggable-index-compact").count() >= 1, "seed must render an index chip"
    assert page.locator(".drop-zone").count() >= 1, "seed must render an unindexed sample's drop zone"
    before = page.locator(".sample-row.has-index").count()

    # Synthesize dragstart→dragover→drop with one shared DataTransfer, and wait
    # for the assignment request the drop fires (a hard assertion — the delegated
    # path must actually assign, or it is a real regression; no skip fallback).
    with page.expect_response(
        lambda r: "assign-index" in r.url and r.request.method == "POST",
        timeout=5000,
    ) as resp_info:
        carried = page.evaluate("""() => {
            const chip = document.querySelector('.draggable-index-compact');
            const zone = document.querySelector('.drop-zone');
            const dt = new DataTransfer();
            chip.dispatchEvent(new DragEvent('dragstart', {dataTransfer: dt, bubbles: true}));
            const payload = dt.getData('text/plain');   // written by handleDragStart
            zone.dispatchEvent(new DragEvent('dragover', {dataTransfer: dt, bubbles: true, cancelable: true}));
            zone.dispatchEvent(new DragEvent('drop',     {dataTransfer: dt, bubbles: true, cancelable: true}));
            return payload;
        }""")
    assert carried, (
        "dragstart did not populate the DataTransfer (handleDragStart.setData was a "
        "no-op in this browser), so the drag path could not be exercised"
    )
    assert resp_info.value.status == 200, f"assign-index returned HTTP {resp_info.value.status}"

    page.wait_for_function(
        f"document.querySelectorAll('.sample-row.has-index').length >= {before + 1}",
        timeout=5000,
    )
    assert page.locator(".sample-row.has-index").count() >= before + 1, (
        "drag-drop did not produce an indexed sample row"
    )


@pytest.mark.browser
def test_index_filter_input_hides_chips(logged_in_page, base_url, seeded_ids):
    """Typing into .index-filter-input reduces the visible chip count.

    Proves filterIndexesWizard delegation fires via the document 'input'
    listener (not the removed inline oninput).
    """
    page = logged_in_page
    run_id = seeded_ids["draft_run_id"]
    page.goto(f"{base_url}/runs/{run_id}")
    page.wait_for_load_state("networkidle")

    # Count total chips before filtering
    total = page.locator(".draggable-index-compact").count()
    assert total > 1, "Need at least 2 chips to test filtering"

    # Type a filter that matches only one entry (e.g., "UDP0001")
    filter_input = page.locator(".index-filter-input").first
    filter_input.fill("UDP0001")
    # Trigger the input event explicitly (fill() may or may not fire it)
    filter_input.dispatch_event("input")

    # Wait for the DOM to reflect the filter
    page.wait_for_function(
        "Array.from(document.querySelectorAll('.draggable-index-compact'))"
        ".filter(el => el.style.display !== 'none' && el.offsetParent !== null).length < "
        f"{total}"
    )

    visible = page.evaluate(
        "Array.from(document.querySelectorAll('.draggable-index-compact'))"
        ".filter(el => el.style.display !== 'none' && el.offsetParent !== null).length"
    )
    assert visible < total, (
        f"Expected fewer than {total} chips after filtering, got {visible}"
    )
    assert visible >= 1, "Filter should show at least 1 matching chip (UDP0001 exists)"
