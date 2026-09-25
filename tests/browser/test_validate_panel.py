"""The Validate box follows changes without a page reload.

It used to keep its page-load counts, so after deleting or adding samples
it showed stale numbers until the user reloaded.
"""

import pytest
from playwright.sync_api import expect


@pytest.mark.browser
def test_validate_box_updates_after_sample_deletes(logged_in_page, base_url, mutable_run_id):
    page = logged_in_page
    page.goto(f"{base_url}/runs/{mutable_run_id}")
    page.wait_for_load_state("networkidle")
    panel = page.locator("#validate-panel")
    expect(panel).to_contain_text("Samples: 4")
    expect(panel).to_contain_text("Indexes: 3/4")

    refreshes = []
    page.on("request", lambda r: refreshes.append(r.url) if r.url.endswith("/validate-panel") else None)
    page.on("dialog", lambda d: d.accept())

    # Two deletes in a row: the box must end on the latest state.
    for sample in ("s4", "s3"):
        with page.expect_response(lambda r: r.request.method == "DELETE" and r.status == 200):
            page.locator(f"#sample-row-{mutable_run_id}-{sample} button[title='Delete sample']").click()

    expect(panel).to_contain_text("Samples: 2")
    expect(panel).to_contain_text("Indexes: 2/2")

    # Its own GET does not set off another refresh.
    page.wait_for_timeout(1000)
    count = len(refreshes)
    page.wait_for_timeout(1000)
    assert len(refreshes) == count
    assert 1 <= count <= 2
