"""A delete question names what it deletes.

The row's x asked "Delete this sample?" and Delete Selected asked "Delete
selected samples?". On a 96-row table a misclicked x one row off was confirmed
with nothing to catch it, and Delete Selected did not even say how many rows
were ticked (review EDITING-5). The replace-on-drop question already names the
sample and its index; these say the same.
"""

from datetime import datetime

import pytest

from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun

from .conftest import hold_edit_lock

RUN_ID = "delete-questions"


@pytest.fixture
def run_id(app_ctx):
    t = datetime(2026, 1, 10, 9, 0, 0)
    run = SequencingRun(
        id=RUN_ID, run_name="Delete questions",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=RunStatus.DRAFT,
        created_at=t, updated_at=t)
    for n in range(1, 9):
        run.add_sample(Sample(id=f"{RUN_ID}-s{n}", sample_id=f"DC-0{n}", lanes=[1]))
    app_ctx.run_repo.save(run)
    hold_edit_lock(app_ctx, RUN_ID)
    yield RUN_ID
    app_ctx.run_repo.collection.delete_one({"_id": RUN_ID})


def _asks(page, do):
    asked = []
    page.on("dialog", lambda d: (asked.append(d.message), d.dismiss()))
    do()
    page.wait_for_timeout(300)
    return asked


@pytest.mark.browser
class TestTheRowsDeleteQuestion:

    def test_the_check_has_flagged_every_row(self, logged_in_page, base_url, run_id):
        """So the questions below are read off rows carrying the Check's
        badge, which is prepended into the Sample ID cell."""
        page = logged_in_page
        page.goto(f"{base_url}/runs/{RUN_ID}")
        page.wait_for_load_state("networkidle")
        page.wait_for_timeout(500)

        badges = page.locator(".row-error-badge")

        assert badges.count() == 8, badges.count()

    def test_it_names_the_sample(self, logged_in_page, base_url, run_id):
        page = logged_in_page
        page.goto(f"{base_url}/runs/{RUN_ID}")
        page.wait_for_load_state("networkidle")

        asked = _asks(page, lambda: page.locator(f"#sample-row-{RUN_ID}-s2 .btn-danger").click())

        # The whole question, so the Check's "!" badge in the Sample ID cell
        # (every sample here has no index, so every row carries one) cannot
        # creep into the name.
        assert asked == ["Delete sample DC-02?"], asked


@pytest.mark.browser
class TestDeleteSelected:

    def test_it_says_how_many_and_names_them(self, logged_in_page, base_url, run_id):
        page = logged_in_page
        page.goto(f"{base_url}/runs/{RUN_ID}")
        page.wait_for_load_state("networkidle")
        for n in (1, 3):
            page.locator(f"#sample-row-{RUN_ID}-s{n} .sample-checkbox").check()

        asked = _asks(page, lambda: page.locator('[data-action="bulk-delete"]').click())

        assert asked == ["Delete 2 samples: DC-01, DC-03?"], asked

    def test_one_ticked_sample_is_named_alone(self, logged_in_page, base_url, run_id):
        page = logged_in_page
        page.goto(f"{base_url}/runs/{RUN_ID}")
        page.wait_for_load_state("networkidle")
        page.locator(f"#sample-row-{RUN_ID}-s4 .sample-checkbox").check()

        asked = _asks(page, lambda: page.locator('[data-action="bulk-delete"]').click())

        assert asked == ["Delete sample DC-04?"], asked

    def test_many_are_counted_and_the_first_few_named(self, logged_in_page, base_url, run_id):
        page = logged_in_page
        page.goto(f"{base_url}/runs/{RUN_ID}")
        page.wait_for_load_state("networkidle")
        page.locator(".select-all-checkbox").first.check()

        asked = _asks(page, lambda: page.locator('[data-action="bulk-delete"]').click())

        assert asked == ["Delete 8 samples: DC-01, DC-02, DC-03, DC-04, DC-05 and 3 more?"], asked
