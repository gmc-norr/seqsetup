"""Admin → Authentication: ticking Allow local user fallback saves it on its
own and keeps the sign-in method (2b handback, ESCALATE E1)."""

import pytest
from playwright.sync_api import expect

from seqsetup.models.auth_config import AuthMethod


@pytest.mark.browser
def test_ticking_fallback_saves_it_and_keeps_the_method(logged_in_page, base_url, app_ctx):
    repo = app_ctx.auth_config_repo
    before = repo.get()
    # The app is shared by every browser test: stay on Local sign-in, and
    # put the setting back afterwards.
    assert before.auth_method is AuthMethod.LOCAL
    page = logged_in_page
    try:
        page.goto(f"{base_url}/admin/authentication")
        box = page.locator("input[name='allow_local_fallback']")
        want = not box.is_checked()
        with page.expect_response(
            lambda r: r.url.endswith("/admin/settings/auth-method") and r.status == 200,
            timeout=5000,
        ):
            box.click()
        saved = repo.get()
        assert (saved.auth_method, saved.allow_local_fallback) == (AuthMethod.LOCAL, want)
        page.reload()
        expect(page.locator("input[name='allow_local_fallback']")).to_be_checked(checked=want)
        expect(page.locator("#auth_method_local")).to_be_checked()
    finally:
        config = repo.get()
        config.auth_method = before.auth_method
        config.allow_local_fallback = before.allow_local_fallback
        repo.save(config)
