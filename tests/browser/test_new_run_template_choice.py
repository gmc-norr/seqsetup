"""New Run → "Start from a template" opens a run made from the template,
and the blank run the page had made is gone."""

import pytest
from playwright.sync_api import expect


@pytest.mark.browser
def test_start_new_run_from_template(logged_in_page, base_url, app_ctx, mutable_run_id):
    page = logged_in_page
    made_runs = []
    template_ids_before = {t.id for t in app_ctx.run_template_repo.list_all()}
    try:
        page.goto(f"{base_url}/runs/{mutable_run_id}")
        page.fill("#template-name", "Browser template choice")
        page.click("text=Save as template >> nth=-1")
        page.wait_for_url(f"{base_url}/templates")

        page.click("button.sidebar-btn")
        page.wait_for_url("**/runs/new/step/1?new=1&run_id=*")
        blank_id = page.url.split("run_id=", 1)[1]
        made_runs.append(blank_id)

        page.select_option("#template_id", label="Browser template choice")
        page.click("text=Use template")
        page.wait_for_url(f"{base_url}/runs/*")
        new_id = page.url.rsplit("/", 1)[1]
        made_runs.append(new_id)

        expect(page.locator("h1.run-title")).to_have_text("Browser template choice")
        assert app_ctx.run_repo.get_by_id(blank_id) is None
    finally:
        for run_id in made_runs:
            app_ctx.run_repo.delete(run_id)
        for t in app_ctx.run_template_repo.list_all():
            if t.id not in template_ids_before:
                app_ctx.run_template_repo.delete(t.id)
