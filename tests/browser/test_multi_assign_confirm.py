"""Dropping one index while other samples are ticked asks first.

The drop gives the index to every ticked sample as well as the drop
target. That is only right when those samples are in different lanes; a
box ticked for some other reason used to receive the index silently.
"""

import pytest

_DROP = """([chipSel, zoneSel]) => {
    const chip = document.querySelector(chipSel);
    const zone = document.querySelector(zoneSel);
    const dt = new DataTransfer();
    chip.dispatchEvent(new DragEvent('dragstart', {dataTransfer: dt, bubbles: true}));
    zone.dispatchEvent(new DragEvent('dragover', {dataTransfer: dt, bubbles: true, cancelable: true}));
    zone.dispatchEvent(new DragEvent('drop', {dataTransfer: dt, bubbles: true, cancelable: true}));
}"""


def _open(page, base_url, run_id):
    page.goto(f"{base_url}/runs/{run_id}")
    page.wait_for_load_state("networkidle")


def _drop_on_s4(page, run_id):
    page.evaluate(_DROP, [".draggable-index-compact", f"#sample-row-{run_id}-s4 .drop-zone"])


@pytest.mark.browser
def test_cancel_assigns_nothing(logged_in_page, base_url, mutable_run_id):
    page = logged_in_page
    _open(page, base_url, mutable_run_id)
    page.locator(f"#sample-row-{mutable_run_id}-s1 .sample-checkbox").check()

    dialogs, posts = [], []
    page.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))
    page.on("request", lambda r: posts.append(r.url) if "assign-index" in r.url else None)

    _drop_on_s4(page, mutable_run_id)
    page.wait_for_timeout(500)

    assert len(dialogs) == 1
    assert "2 samples" in dialogs[0]
    assert posts == []
    assert page.locator(f"#sample-row-{mutable_run_id}-s4 .drop-zone").count() >= 1


@pytest.mark.browser
def test_ok_assigns_to_all(logged_in_page, base_url, mutable_run_id):
    page = logged_in_page
    _open(page, base_url, mutable_run_id)
    page.locator(f"#sample-row-{mutable_run_id}-s1 .sample-checkbox").check()
    page.on("dialog", lambda d: d.accept())

    with page.expect_response(lambda r: "assign-index-to-selected" in r.url) as resp:
        _drop_on_s4(page, mutable_run_id)
    assert resp.value.status == 200


@pytest.mark.browser
def test_only_the_drop_target_ticked_does_not_ask(logged_in_page, base_url, mutable_run_id):
    page = logged_in_page
    _open(page, base_url, mutable_run_id)
    page.locator(f"#sample-row-{mutable_run_id}-s4 .sample-checkbox").check()
    dialogs = []
    page.on("dialog", lambda d: (dialogs.append(d.message), d.accept()))

    with page.expect_response(lambda r: "assign-index" in r.url) as resp:
        _drop_on_s4(page, mutable_run_id)
    assert resp.value.status == 200
    assert dialogs == []
