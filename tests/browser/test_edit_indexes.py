"""Edit indexes on the run page, and the change history folded away.

Once every sample in a draft had an index, the run page offered no way to
change one. "Edit indexes" opens the index list and a clear button on each
index; "Done editing indexes" closes them. The open state lives outside
the sample section, so it stays open while rows and the section are
swapped. The change history is folded away and loads when opened.
"""

from datetime import datetime

import pytest
from playwright.sync_api import expect

from seqsetup.models.index import Index, IndexKit, IndexMode, IndexPair, IndexType
from seqsetup.models.run_history import RunHistoryEntry
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun

KIT = "Edit-Indexes-Kit"
I7 = ["ACGTACGT", "CAGTCAGT", "TGCATGCA"]
I5 = ["AACCGGTT", "TTGGCCAA", "CATGCATG"]


@pytest.fixture
def kit(app_ctx):
    """One unique-dual kit with three pairs; deleted afterwards."""
    from seqsetup.services.validation import clear_validation_cache

    kit = IndexKit(
        name=KIT, version="1.0", index_mode=IndexMode.UNIQUE_DUAL,
        index_pairs=[
            IndexPair(
                id=f"{KIT}_EI{k}", name=f"EI{k}",
                index1=Index(name=f"EI{k}", sequence=I7[k], index_type=IndexType.I7),
                index2=Index(name=f"EI{k}", sequence=I5[k], index_type=IndexType.I5),
            )
            for k in range(3)
        ],
    )
    app_ctx.index_kit_repo.save(kit)
    clear_validation_cache()
    yield kit
    app_ctx.index_kit_repo.delete(kit.name, kit.version)
    clear_validation_cache()


@pytest.fixture
def run_id(app_ctx, kit):
    """A draft whose two samples both have an index pair; deleted afterwards."""
    t = datetime(2026, 1, 10, 9, 0, 0)
    run = SequencingRun(
        id="edit-indexes-run", run_name="Fold run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=RunStatus.DRAFT,
        created_at=t, updated_at=t,
    )
    for n in (1, 2):
        sample = Sample(id=f"{run.id}-s{n}", sample_id=f"EI-0{n}", lanes=[1])
        sample.assign_index(kit.index_pairs[n - 1])
        sample.index_kit_name = KIT
        run.add_sample(sample)
    app_ctx.run_repo.save(run)
    app_ctx.run_history_repo.append(RunHistoryEntry(
        run_id=run.id, timestamp=t, actor="alice", kind="created"))
    yield run.id
    # Other browser tests share this database; the app itself has no way
    # to remove history, on purpose.
    app_ctx.run_repo.collection.delete_one({"_id": run.id})
    app_ctx.run_history_repo.collection.delete_many({"run_id": run.id})


def _open(page, base_url, run_id):
    page.goto(f"{base_url}/runs/{run_id}")
    page.wait_for_load_state("networkidle")


def _clear(page, run_id, n):
    """The sample's one clear button: its indexes are a pair."""
    return page.locator(f'#sample-row-{run_id}-s{n} button[title="Clear index pair"]')


def _sample(app_ctx, run_id, n):
    return app_ctx.run_repo.get_by_id(run_id).get_sample(f"{run_id}-s{n}")


@pytest.mark.browser
def test_edit_indexes_opens_and_closes(logged_in_page, base_url, run_id):
    page = logged_in_page
    _open(page, base_url, run_id)
    panel = page.locator(".wizard-index-panel")

    expect(panel).to_be_hidden()
    expect(_clear(page, run_id, 1)).to_be_hidden()

    page.get_by_role("button", name="Edit indexes").click()
    expect(panel).to_be_visible()
    for n in (1, 2):
        expect(_clear(page, run_id, n)).to_be_visible()
    expect(page.get_by_role("button", name="Edit indexes")).to_be_hidden()

    page.get_by_role("button", name="Done editing indexes").click()
    expect(panel).to_be_hidden()
    expect(_clear(page, run_id, 1)).to_be_hidden()
    expect(page.get_by_role("button", name="Edit indexes")).to_be_visible()


@pytest.mark.browser
def test_swap_one_sample_index_pair(logged_in_page, base_url, app_ctx, kit, run_id):
    """Clear one sample's index pair, drop another pair on it."""
    page = logged_in_page
    _open(page, base_url, run_id)
    page.get_by_role("button", name="Edit indexes").click()

    with page.expect_response(lambda r: "/clear-index" in r.url) as resp:
        _clear(page, run_id, 1).click()
    assert resp.value.status == 200
    assert _sample(app_ctx, run_id, 1).index1_sequence is None
    assert _sample(app_ctx, run_id, 1).index2_sequence is None
    # The swapped row and its neighbour are still in edit mode.
    expect(_clear(page, run_id, 2)).to_be_visible()

    with page.expect_response(lambda r: "/indexes/kit-content" in r.url and r.status == 200):
        page.select_option("#index-kit-dropdown", kit.kit_id)
    chip = page.locator(f'#index-list-container [data-index-pair-id="{KIT}_EI2"]')
    zone = page.locator(f"#sample-row-{run_id}-s1 .drop-zone").first
    with page.expect_response(lambda r: "/assign-index" in r.url) as resp:
        chip.drag_to(zone)
    assert resp.value.status == 200

    sample = _sample(app_ctx, run_id, 1)
    assert (sample.index1_sequence, sample.index2_sequence) == (I7[2], I5[2])
    assert _sample(app_ctx, run_id, 2).index1_sequence == I7[1]
    expect(_clear(page, run_id, 1)).to_be_visible()


@pytest.mark.browser
def test_edit_mode_survives_a_section_swap(logged_in_page, base_url, app_ctx, run_id):
    """A bulk action swaps the whole sample section; edit mode stays on."""
    page = logged_in_page
    _open(page, base_url, run_id)
    page.get_by_role("button", name="Edit indexes").click()

    page.locator(f"#sample-row-{run_id}-s1 .sample-checkbox").check()
    page.locator('.bulk-lane-checkbox[value="2"]').check()
    with page.expect_response(lambda r: r.url.endswith("/samples/set-lanes")) as resp:
        page.locator('[data-action="bulk-apply-lanes"]').click()
    assert resp.value.status == 200
    expect(page.locator(f"#sample-row-{run_id}-s1 .lanes-display")).to_have_text("2")

    expect(page.locator(".wizard-index-panel")).to_be_visible()
    expect(_clear(page, run_id, 1)).to_be_visible()


@pytest.mark.browser
def test_change_history_loads_when_opened(logged_in_page, base_url, run_id):
    page = logged_in_page
    history_requests = []
    page.on("request", lambda r: history_requests.append(r.url) if r.url.endswith("/history") else None)
    _open(page, base_url, run_id)

    panel = page.locator(".run-history-panel")
    expect(panel).to_be_hidden()
    assert history_requests == []

    with page.expect_response(lambda r: r.url.endswith(f"/runs/{run_id}/history")) as resp:
        page.get_by_text("Show change history").click()
    assert resp.value.status == 200
    expect(panel).to_be_visible()
    expect(panel).to_contain_text("Created")
    assert len(history_requests) == 1
