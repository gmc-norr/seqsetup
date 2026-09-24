"""Failed HTMX requests must be visible to the operator.

htmx 2 never swaps a 4xx/5xx response by default, and HX-Retarget/HX-Reswap
only choose WHERE a swap goes, not WHETHER. Without the app.js hook every
rejected save (400 bad input, 403 run not editable, 409 edit conflict, 500
export failure) left the page unchanged, as if it had worked.
"""

import pytest
from playwright.sync_api import expect


def _error_toast(page):
    return page.locator("#toast-stack .toast--error")


@pytest.mark.browser
def test_rejected_override_cycles_shows_banner_and_toast(logged_in_page, base_url, mutable_run_id):
    """A malformed per-sample OverrideCycles is refused with a 400 whose
    fragment the server aims at #error-banner: it must appear there, and as
    an error toast."""
    page = logged_in_page
    page.goto(f"{base_url}/runs/{mutable_run_id}")
    page.wait_for_load_state("networkidle")

    box = page.locator('td.override-cell input[name="override_cycles"]').first
    with page.expect_response(lambda r: r.url.endswith("/settings") and r.status == 400):
        box.fill("Y*Q;I8;I8;Y*")
        box.dispatch_event("change")

    expect(page.locator("#error-banner")).to_contain_text("not valid OverrideCycles")
    expect(_error_toast(page)).to_contain_text("not valid OverrideCycles")


@pytest.mark.browser
def test_plain_text_error_shows_banner_and_toast(logged_in_page):
    """Some routes return a bare text error with no HX-Retarget. Its text
    goes into #error-banner (as text) and a toast, and the request's own
    target is left alone."""
    page = logged_in_page
    page.wait_for_load_state("networkidle")
    page.route(
        "**/test-plain-error",
        lambda route: route.fulfill(status=403, body="Run is already archived",
                                    content_type="text/plain"),
    )

    page.evaluate("htmx.ajax('POST', '/test-plain-error', {target: '#main'})")

    expect(page.locator("#error-banner")).to_have_text("Run is already archived")
    expect(_error_toast(page)).to_have_text("Run is already archived")
    # The error body was not swapped over the page content.
    expect(page.locator("#main #error-banner")).to_have_count(1)


@pytest.mark.browser
def test_error_html_is_shown_as_text(logged_in_page):
    """Markup in an error body must never be rendered."""
    page = logged_in_page
    page.wait_for_load_state("networkidle")
    page.route(
        "**/test-html-error",
        lambda route: route.fulfill(
            status=500, content_type="text/html",
            body='<html><body><div class="error-message">Export failed '
                 '<img src=x id="injected"></div></body></html>'),
    )

    page.evaluate("htmx.ajax('POST', '/test-html-error', {target: '#main'})")

    expect(_error_toast(page)).to_have_text("Export failed")
    expect(page.locator("#injected")).to_have_count(0)


@pytest.mark.browser
def test_unreachable_server_shows_toast(logged_in_page):
    page = logged_in_page
    page.wait_for_load_state("networkidle")
    page.route("**/test-offline", lambda route: route.abort())

    # htmx.ajax's promise rejects on a network error; only the toast matters.
    page.evaluate("() => { htmx.ajax('POST', '/test-offline', {target: '#main'}).catch(() => {}); }")

    expect(_error_toast(page)).to_have_text(
        "Could not reach the server. The change was not saved.")


@pytest.mark.browser
def test_unreachable_server_on_read_does_not_claim_unsaved_change(logged_in_page):
    page = logged_in_page
    page.wait_for_load_state("networkidle")
    page.route("**/test-offline-get", lambda route: route.abort())

    page.evaluate("() => { htmx.ajax('GET', '/test-offline-get', {target: '#main'}).catch(() => {}); }")

    expect(_error_toast(page)).to_have_text("Could not reach the server.")


@pytest.mark.browser
def test_error_shown_when_sending_element_was_replaced(logged_in_page):
    """htmx fires a response's events on the element that sent it. If an
    earlier swap replaced that element (two quick edits in one sample row),
    those events never reach the page — the error must still be shown."""
    page = logged_in_page
    page.wait_for_load_state("networkidle")
    page.route(
        "**/test-detached-error",
        lambda route: route.fulfill(status=409, body="Run was changed by someone else",
                                    content_type="text/plain"),
    )

    # Like a sample-row input: the request targets its own row, and the row
    # (with the input) is replaced before this response arrives.
    page.evaluate("""() => {
        const row = document.createElement('div');
        row.id = 'test-detached-row';
        const btn = document.createElement('button');
        btn.setAttribute('hx-post', '/test-detached-error');
        btn.setAttribute('hx-target', '#test-detached-row');
        btn.setAttribute('hx-swap', 'outerHTML');
        row.appendChild(btn);
        document.querySelector('#main').appendChild(row);
        htmx.process(btn);
        btn.click();
        row.remove();
    }""")

    expect(_error_toast(page)).to_have_text("Run was changed by someone else")
    expect(page.locator("#error-banner")).to_have_text("Run was changed by someone else")


def _override_box(page, row):
    return page.locator('td.override-cell input[name="override_cycles"]').nth(row)


def _set_override(page, box, value, status):
    with page.expect_response(lambda r: r.url.endswith("/settings") and r.status == status):
        box.fill(value)
        box.dispatch_event("change")


@pytest.mark.browser
def test_banner_cleared_when_same_input_then_saves(logged_in_page, base_url, mutable_run_id):
    page = logged_in_page
    page.goto(f"{base_url}/runs/{mutable_run_id}")
    page.wait_for_load_state("networkidle")

    box = _override_box(page, 0)
    _set_override(page, box, "Y*Q;I8;I8;Y*", 400)
    expect(page.locator("#error-banner")).to_contain_text("not valid OverrideCycles")

    _set_override(page, box, "Y151;I8;I8;Y151", 200)
    expect(page.locator("#error-banner")).to_be_empty()


@pytest.mark.browser
def test_banner_kept_when_a_different_input_saves(logged_in_page, base_url, mutable_run_id):
    """A later success elsewhere must not hide a failure that still shows
    its unsaved value in the first row."""
    page = logged_in_page
    page.goto(f"{base_url}/runs/{mutable_run_id}")
    page.wait_for_load_state("networkidle")

    _set_override(page, _override_box(page, 0), "Y*Q;I8;I8;Y*", 400)
    _set_override(page, _override_box(page, 1), "Y151;I8;I8;Y151", 200)

    expect(page.locator("#error-banner")).to_contain_text("not valid OverrideCycles")
