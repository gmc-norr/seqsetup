"""The index-kit dropdown keeps the kit the user picked after an edit.

A bulk lane change re-renders the whole #sample-section server-side. That
render used to draw the dropdown with the first kit selected, so the kit
the user had chosen — and the indexes in the panel next to it — silently
jumped back to kit #1. app.js sends the dropdown's kit on every HTMX
request as X-Selected-Kit, so the re-render keeps it.
"""

from datetime import datetime

import pytest
from playwright.sync_api import expect

from seqsetup.models.index import Index, IndexKit, IndexMode, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun


@pytest.fixture
def kit_choice_run_id(app_ctx):
    """A draft with two un-indexed samples on lane 1; deleted afterwards."""
    t = datetime(2026, 1, 10, 9, 0, 0)
    run = SequencingRun(
        id="kit-choice-run", run_name="Kit choice run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=RunStatus.DRAFT,
        created_at=t, updated_at=t,
    )
    for n in (1, 2):
        run.add_sample(Sample(id=f"{run.id}-s{n}", sample_id=f"KC-0{n}", lanes=[1]))
    app_ctx.run_repo.save(run)
    yield run.id
    app_ctx.run_repo.delete(run.id)


@pytest.fixture
def second_kit_id(app_ctx):
    """A second kit, so the kit dropdown can change; deleted afterwards."""
    kit = IndexKit(
        name="Kit-Choice-Second-Kit", version="1.0", index_mode=IndexMode.UNIQUE_DUAL,
        index_pairs=[IndexPair(
            id="kit-choice-second-p1", name="SK0001",
            index1=Index(name="sk-i7", sequence="GGACTCCT", index_type=IndexType.I7),
            index2=Index(name="sk-i5", sequence="TAGATCGC", index_type=IndexType.I5),
        )],
    )
    app_ctx.index_kit_repo.save(kit)
    yield kit.kit_id
    app_ctx.index_kit_repo.delete(kit.name, kit.version)


@pytest.mark.browser
def test_bulk_lane_change_keeps_the_chosen_kit(
    logged_in_page, base_url, app_ctx, kit_choice_run_id, second_kit_id
):
    page = logged_in_page
    page.goto(f"{base_url}/runs/{kit_choice_run_id}")
    page.wait_for_load_state("networkidle")

    dropdown = page.locator("#index-kit-dropdown")
    # The page opens on some other kit, so the fallback is visible if it wins.
    assert dropdown.input_value() != second_kit_id

    with page.expect_response(lambda r: "/indexes/kit-content" in r.url and r.status == 200):
        page.select_option("#index-kit-dropdown", second_kit_id)
    expect(page.locator("#index-list-container")).to_contain_text("SK0001")

    page.locator(f"#sample-row-{kit_choice_run_id}-s1 .sample-checkbox").check()
    page.locator(f"#sample-row-{kit_choice_run_id}-s2 .sample-checkbox").check()
    page.locator('.bulk-lane-checkbox[value="2"]').check()
    with page.expect_response(lambda r: r.url.endswith("/samples/set-lanes")) as resp_info:
        page.locator('[data-action="bulk-apply-lanes"]').click()
    assert resp_info.value.status == 200

    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(300)

    # The edit landed, and the re-rendered section still shows the chosen kit.
    run = app_ctx.run_repo.get_by_id(kit_choice_run_id)
    assert all(sample.lanes == [2] for sample in run.samples)
    expect(page.locator("#index-kit-dropdown")).to_have_value(second_kit_id)
    expect(page.locator("#index-list-container")).to_contain_text("SK0001")
