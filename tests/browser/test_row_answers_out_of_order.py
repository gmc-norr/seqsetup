"""Two answers about one sample row that come back in the other order than
the server stored them (fresh review of 38ca108, P2; design note
docs/design/2026-10-17-row-version-design.md).

A box's save and a redraw of its row (an index clear here) can be on their
way at once. When the server stores the redraw first and the save second,
but the save's answer comes back first, the redraw's answer then puts back
a row drawn from before the save: the screen shows the old value, the
database the new one, and nothing said so. The other way round, a save
stored first and answered last named a value the redrawn row had already
replaced, and asked for a reload the row did not need.

Every row says which version of the run it was drawn from
(data-run-version), and app.js keeps the newest version the page has shown
for each row. The answers are held at the browser (page.route) to put
them in the order each test needs."""

import pytest
from playwright.sync_api import expect

TYPED_OVERRIDE = "Y150N1;I8;I8;Y151"


def _row(page, run_id, n=1):
    return page.locator(f"#sample-row-{run_id}-s{n}")


def _open(page, base_url, run_id):
    page.goto(f"{base_url}/runs/{run_id}")
    page.wait_for_load_state("networkidle")


def _a_settings_request(request):
    return request.url.endswith("/settings")


def _handled(page):
    """Every request of the page has been answered and its answer handled."""
    page.wait_for_function("() => !document.querySelector('.htmx-request')")


def _hold(page, pattern, *, reach_the_server):
    """Hold the requests to ``pattern`` at the browser. With
    ``reach_the_server`` each is sent on, so the server stores it, and only
    its answer waits; without, the request itself waits. Each held one is
    (route, answer or None)."""
    held = []

    def handle(route):
        held.append((route, route.fetch() if reach_the_server else None))

    page.route(pattern, handle)
    return held


def _until_held(page, held, n=1):
    for _ in range(200):
        if len(held) >= n:
            return
        page.wait_for_timeout(25)
    raise AssertionError("the request was never sent")


def _send_clear(page, run_id):
    """The row's index Clear button, as test_row_save_keeps_typing sends it,
    without waiting for its answer."""
    page.evaluate("""([run, sample]) => {
        const row = document.getElementById(`sample-row-${sample}`);
        htmx.ajax('POST', `/runs/${run}/samples/${sample}/clear-index`,
            {target: `#sample-row-${sample}`, swap: 'outerHTML',
             values: {target_indexes: JSON.stringify([[row.dataset.i7, row.dataset.i5]])}});
    }""", [run_id, f"{run_id}-s1"])


def _type(page, box, value):
    box.click()
    page.keyboard.press("Control+A")
    page.keyboard.type(value)
    page.keyboard.press("Tab")              # change: the box's save starts


def _stored(app_ctx, run_id):
    return app_ctx.run_repo.get_by_id(run_id).samples[0]


@pytest.mark.browser
class TestARowDrawnBeforeASaveAnsweredFirst:
    """The clear is stored first and answered last; the save of the i7
    mismatch is stored second and answered first."""

    def _cross(self, page, base_url, run_id):
        _open(page, base_url, run_id)
        saves = _hold(page, "**/samples/**/settings", reach_the_server=False)
        clears = _hold(page, "**/clear-index*", reach_the_server=True)
        i7 = _row(page, run_id).locator('input[name="barcode_mismatches_index1"]')
        _type(page, i7, "0")
        _until_held(page, saves)            # the save waits at the browser
        _send_clear(page, run_id)
        _until_held(page, clears)           # the server stored the clear
        saves[0][0].continue_()             # ... and then the save
        page.wait_for_function("""(id) => document.querySelector(
            `#${id} input[name="barcode_mismatches_index1"]`).defaultValue === '0'""",
            arg=f"sample-row-{run_id}-s1")  # the save's answer is handled
        route, answer = clears[0]
        route.fulfill(response=answer)      # the clear's answer comes last
        page.unroute("**/samples/**/settings")
        page.unroute("**/clear-index*")
        return i7

    def test_the_older_row_asks_for_a_reload(
            self, logged_in_page, base_url, mutable_run_id, app_ctx):
        page = logged_in_page
        i7 = self._cross(page, base_url, mutable_run_id)

        expect(i7).to_have_value("1")       # drawn before the save
        assert _stored(app_ctx, mutable_run_id).barcode_mismatches_index1 == 0
        notes = page.locator("#row-setting-notes")
        expect(notes).to_contain_text("MUT-01")
        expect(notes).to_contain_text("reload the page")

    def test_the_note_goes_once_the_row_is_drawn_from_newer_data(
            self, logged_in_page, base_url, mutable_run_id, app_ctx):
        page = logged_in_page
        self._cross(page, base_url, mutable_run_id)
        notes = page.locator("#row-setting-notes")
        expect(notes).to_contain_text("MUT-01")

        with page.expect_response(lambda r: r.url.endswith("/clear-index") and r.status == 200):
            _send_clear(page, mutable_run_id)
        _handled(page)

        i7 = _row(page, mutable_run_id).locator('input[name="barcode_mismatches_index1"]')
        expect(i7).to_have_value("0")
        expect(notes).not_to_contain_text("MUT-01")


@pytest.mark.browser
class TestASaveAnsweredAfterARowDrawnLater:
    """The save of a typed Override Cycles is stored first and answered
    last; the clear is stored second, which wipes the Override Cycles, and
    answered first. The row on screen is the newer one."""

    def test_the_late_answer_says_nothing(
            self, logged_in_page, base_url, mutable_run_id, app_ctx):
        page = logged_in_page
        _open(page, base_url, mutable_run_id)
        saves = _hold(page, "**/samples/**/settings", reach_the_server=True)
        override = _row(page, mutable_run_id).locator('input[name="override_cycles"]')
        _type(page, override, TYPED_OVERRIDE)
        _until_held(page, saves)            # the server stored the save
        assert _stored(app_ctx, mutable_run_id).override_cycles == TYPED_OVERRIDE

        with page.expect_response(lambda r: r.url.endswith("/clear-index") and r.status == 200):
            _send_clear(page, mutable_run_id)
        expect(override).to_have_value("")  # the clear, drawn after the save
        route, answer = saves[0]
        with page.expect_request_finished(_a_settings_request):
            route.fulfill(response=answer)  # the save's answer comes last
        page.unroute("**/samples/**/settings")

        assert _stored(app_ctx, mutable_run_id).override_cycles is None
        expect(override).to_have_value("")
        expect(page.locator("#row-setting-notes")).to_be_empty()


@pytest.mark.browser
class TestAnswersInOrder:

    def test_control_a_bulk_apply_after_a_save_says_nothing(
            self, logged_in_page, base_url, mutable_run_id, app_ctx):
        page = logged_in_page
        _open(page, base_url, mutable_run_id)
        i7 = _row(page, mutable_run_id).locator('input[name="barcode_mismatches_index1"]')
        with page.expect_response(lambda r: r.url.endswith("/settings")):
            _type(page, i7, "0")
        _handled(page)

        _row(page, mutable_run_id, 2).locator(".sample-checkbox").check()
        page.locator('.bulk-lane-checkbox[value="2"]').check()
        with page.expect_response(lambda r: r.url.endswith("/samples/set-lanes")):
            page.locator('[data-action="bulk-apply-lanes"]').click()
        _handled(page)

        expect(_row(page, mutable_run_id, 2).locator(".lanes-display")).to_contain_text("2")
        expect(i7).to_have_value("0")
        expect(page.locator("#row-setting-notes")).to_be_empty()
