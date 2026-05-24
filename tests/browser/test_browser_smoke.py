"""Browser smoke gate — ~3 assertions that catch the entire class of
"client-side script wiring is broken" failures (which the current
HTMX-not-loaded bug demonstrated server-side tests cannot detect).

Asserts:
  1. window.htmx and window.Alpine are defined on a loaded page.
  2. The toast Alpine component is reactive (dispatch a synthetic
     event, see the DOM update).
  3. One real HTMX swap round-trips on the dashboard (which uses
     hx-get for tab switching).

The toast/HTMX-swap tests both use ``logged_in_page`` because the
toast slot lives in ``_app_shell.html`` (auth-required) — login pages
extend ``_base.html`` directly without the shell.
"""

import pytest


@pytest.mark.browser
def test_htmx_and_alpine_globals_present(logged_in_page, base_url):
    """The vendor scripts load and define their globals.

    Uses logged_in_page (which lands on /, the dashboard) because that
    page extends _app_shell.html — the place all the components live.
    """
    page = logged_in_page
    page.wait_for_load_state("networkidle")

    htmx_defined = page.evaluate("typeof window.htmx !== 'undefined'")
    alpine_defined = page.evaluate("typeof window.Alpine !== 'undefined'")
    assert htmx_defined, "window.htmx is not defined — HTMX script failed to load"
    assert alpine_defined, "window.Alpine is not defined — Alpine script failed to load"


@pytest.mark.browser
def test_toast_alpine_component_reacts_to_event(logged_in_page, base_url):
    """Dispatch a synthetic 'toast' CustomEvent on window; assert the
    toast renders. This proves the toast_stack.js component registered
    and Alpine processed it.

    Requires logged_in_page — the toast slot lives in _app_shell.html,
    which only renders for authenticated pages.
    """
    page = logged_in_page
    page.wait_for_load_state("networkidle")

    # Wait for Alpine to fully bind the x-data on #toast-stack.
    page.wait_for_function("document.querySelector('#toast-stack') && window.Alpine !== undefined")

    # Dispatch the same event HTMX would dispatch from HX-Trigger.
    page.evaluate("""
        window.dispatchEvent(new CustomEvent('toast', {
            detail: {kind: 'success', message: 'Smoke test toast'}
        }));
    """)
    # Wait for Alpine to react and render the toast.
    page.wait_for_selector("text=Smoke test toast", timeout=2000)


@pytest.mark.browser
def test_htmx_swap_round_trips_via_dashboard_tab(logged_in_page, base_url):
    """Click a dashboard tab — a real hx-get swap that exists today
    (existing route ``GET /dashboard/tab/{tab}`` returns the tab
    fragment, swapped into ``#dashboard``).

    This test proves HTMX is wired and a real swap works end-to-end.
    Doesn't require any data to be present — the dashboard renders
    empty-state when there are no runs.
    """
    page = logged_in_page
    page.wait_for_load_state("networkidle")

    # Capture the network request HTMX will make.
    with page.expect_response(lambda r: "/dashboard/tab/" in r.url) as response_info:
        # Click the "Ready" tab. Selector should match the tab button
        # in the Tailwind-styled dashboard — adjust after Phase 2.2.
        page.click('button:has-text("Ready")')

    response = response_info.value
    assert response.status == 200, f"HTMX swap response status {response.status}"
    # HTMX requests include the HX-Request header — the route would have
    # rendered just the block. Body should NOT include <html>.
    body = response.text()
    assert "<html" not in body, "HTMX swap response should be a fragment, not a full page"
