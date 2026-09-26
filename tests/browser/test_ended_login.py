"""An ended login during a background action keeps the page and the typed
text; after logging in again in another tab, the same action works."""

import pytest
from playwright.sync_api import expect

PASTE = "LATE-01,WGS\nLATE-02,WGS"


def _preview(page, status):
    with page.expect_response(
            lambda r: r.url.endswith("/samples/preview") and r.status == status):
        page.click(".paste-form button[type=submit]")


@pytest.mark.browser
def test_paste_survives_an_ended_login(logged_in_page, base_url, admin_creds, app_ctx,
                                       mutable_run_id):
    page = logged_in_page
    page.goto(f"{base_url}/runs/{mutable_run_id}")
    page.wait_for_load_state("networkidle")
    page.click("summary.paste-section-summary")
    page.fill("#paste_data", PASTE)
    url = page.url

    app_ctx.web_session_repo.delete_for_user(admin_creds["username"])
    _preview(page, 401)

    banner = page.locator("#error-banner")
    expect(banner).to_contain_text("Your login has ended, so this was not saved.")
    expect(banner.locator('a[href="/login"][target="_blank"]')).to_have_text("Log in again")
    expect(page.locator("#paste_data")).to_have_value(PASTE)
    assert page.url == url

    other = page.context.new_page()
    other.goto(f"{base_url}/login")
    other.fill('input[name="username"]', admin_creds["username"])
    other.fill('input[name="password"]', admin_creds["password"])
    other.click('button[type="submit"]')
    other.wait_for_url(f"{base_url}/")
    other.close()

    _preview(page, 200)
    page.click("text=Add 2 samples")
    expect(page.locator("#error-banner")).to_contain_text("Added 2 samples")
    ids = {s.sample_id for s in app_ctx.run_repo.get_by_id(mutable_run_id).samples}
    assert {"LATE-01", "LATE-02"} <= ids
