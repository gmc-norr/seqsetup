"""One person edits a Draft run at a time, in two real browsers (the user's
decision, 2026-10-13): Edit run, Take over editing after a confirmation,
the red line on the page whose lock was taken, and Done editing."""

from datetime import datetime

import pytest
from playwright.sync_api import expect

from seqsetup.models.local_user import LocalUser
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun
from seqsetup.models.user import UserRole

STAFF = {"username": "browser-staff", "password": "Br0wser-St4ff!", "display_name": "Browser Staff"}
BAR = "#run-status-bar"


@pytest.fixture
def run_id(app_ctx):
    """A draft nobody is editing, and a second user to edit it."""
    t = datetime(2026, 1, 10, 9, 0, 0)
    staff = LocalUser(username=STAFF["username"], display_name=STAFF["display_name"],
                      email="staff@test.local", role=UserRole.STANDARD, created_at=t, updated_at=t)
    staff.set_password(STAFF["password"])
    app_ctx.local_user_repo.save(staff)
    run = SequencingRun(id="edit-lock-run", run_name="Edit lock run",
                        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
                        run_cycles=RunCycles(151, 151, 8, 8), status=RunStatus.DRAFT,
                        created_at=t, updated_at=t)
    run.add_sample(Sample(id="edit-lock-s1", sample_id="LOCK-01", lanes=[1]))
    app_ctx.run_repo.save(run)
    yield run.id
    app_ctx.run_repo.collection.delete_one({"_id": run.id})
    app_ctx.edit_lock_repo.delete(run.id)
    app_ctx.local_user_repo.collection.delete_one({"_id": STAFF["username"]})


def _staff_page(browser, base_url):
    page = browser.new_context().new_page()
    page.goto(f"{base_url}/login")
    page.fill('input[name="username"]', STAFF["username"])
    page.fill('input[name="password"]', STAFF["password"])
    page.click('button[type="submit"]')
    page.wait_for_url(f"{base_url}/", timeout=5000)
    return page


@pytest.mark.browser
def test_edit_take_over_and_done(logged_in_page, browser, base_url, run_id):
    admin = logged_in_page
    admin.goto(f"{base_url}/runs/{run_id}")
    expect(admin.locator(BAR)).to_contain_text("Nobody is editing this run")
    expect(admin.locator(".locked-message")).to_have_text("Press Edit run to make changes.")
    expect(admin.get_by_role("button", name="Mark Ready")).to_have_count(0)

    admin.get_by_role("button", name="Edit run").click()
    expect(admin.locator(BAR)).to_contain_text("You are editing this run")
    expect(admin.get_by_role("button", name="Mark Ready")).to_be_visible()
    expect(admin.locator(".locked-message")).to_have_count(0)

    staff = _staff_page(browser, base_url)
    staff.goto(f"{base_url}/runs/{run_id}")
    expect(staff.locator(BAR)).to_contain_text("Browser Admin is editing this run (since ")
    expect(staff.get_by_role("button", name="Mark Ready")).to_have_count(0)
    asked = []
    staff.once("dialog", lambda d: (asked.append(d.message), d.accept()))
    staff.get_by_role("button", name="Take over editing").click()
    expect(staff.locator(BAR)).to_contain_text("You are editing this run")
    assert asked and "If you take over, Browser Admin can no longer save changes to it." in asked[0]

    # The admin's page learns at its next "still here"; call it now rather
    # than wait a minute. It must not re-run the Check panel.
    checks = []
    admin.on("request", lambda r: checks.append(r.url) if "/validate-panel" in r.url else None)
    admin.evaluate("() => Alpine.$data(document.querySelector('.edit-lock-lost')).beat()")
    expect(admin.locator(".edit-lock-lost")).to_contain_text(
        "Browser Staff is editing this run now (since ")
    expect(admin.locator(".edit-lock-lost")).to_contain_text("your changes are no longer saved")
    admin.wait_for_timeout(1000)
    assert checks == []

    staff.get_by_role("button", name="Done editing").click()
    expect(staff.locator(BAR)).to_contain_text("Nobody is editing this run")
    staff.context.close()


def _beat(page):
    page.evaluate("() => Alpine.$data(document.querySelector('.edit-lock-lost')).beat()")


@pytest.mark.browser
def test_the_page_says_when_the_run_can_no_longer_be_edited(logged_in_page, base_url, run_id, app_ctx):
    page = logged_in_page
    page.goto(f"{base_url}/runs/{run_id}")
    page.get_by_role("button", name="Edit run").click()
    expect(page.locator(BAR)).to_contain_text("You are editing this run")

    run = app_ctx.run_repo.get_by_id(run_id)
    run.status = RunStatus.READY  # marked Ready from another tab, say
    app_ctx.run_repo.save(run)
    _beat(page)

    expect(page.locator(".edit-lock-lost")).to_have_text(
        "This run can no longer be edited here. Reload the page.")


@pytest.mark.browser
def test_the_page_says_when_the_sign_in_has_ended(browser, base_url, run_id, app_ctx):
    page = _staff_page(browser, base_url)
    page.goto(f"{base_url}/runs/{run_id}")
    page.get_by_role("button", name="Edit run").click()
    expect(page.locator(BAR)).to_contain_text("You are editing this run")

    app_ctx.web_session_repo.delete_for_user(STAFF["username"])
    _beat(page)

    expect(page.locator(".edit-lock-lost")).to_have_text(
        "Your sign-in has ended, so your changes are no longer saved. Reload the page and sign in again.")
    page.context.close()
