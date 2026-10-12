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


# Dropping straight onto an assigned index replaces it, while editing.

COMBI = "Edit-Indexes-Combi"


@pytest.fixture
def combi_kit(app_ctx):
    """A combinatorial kit with one i7 and one i5; deleted afterwards."""
    from seqsetup.services.validation import clear_validation_cache

    kit = IndexKit(
        name=COMBI, version="1.0", index_mode=IndexMode.COMBINATORIAL,
        i7_indexes=[Index(name="CI7", sequence="GGTTAACC", index_type=IndexType.I7)],
        i5_indexes=[Index(name="CI5", sequence="CCAATTGG", index_type=IndexType.I5)],
    )
    app_ctx.index_kit_repo.save(kit)
    clear_validation_cache()
    yield kit
    app_ctx.index_kit_repo.delete(kit.name, kit.version)
    clear_validation_cache()


@pytest.fixture
def half_run_id(app_ctx, kit):
    """A draft whose first sample has a pair and second has none, so the
    index list shows without editing; deleted afterwards."""
    t = datetime(2026, 1, 10, 9, 0, 0)
    run = SequencingRun(
        id="edit-indexes-half-run", run_name="Half run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=RunStatus.DRAFT,
        created_at=t, updated_at=t,
    )
    first = Sample(id=f"{run.id}-s1", sample_id="EI-01", lanes=[1])
    first.assign_index(kit.index_pairs[0])
    first.index_kit_name = KIT
    run.add_sample(first)
    run.add_sample(Sample(id=f"{run.id}-s2", sample_id="EI-02", lanes=[1]))
    app_ctx.run_repo.save(run)
    yield run.id
    app_ctx.run_repo.collection.delete_one({"_id": run.id})


def _pick_kit(page, kit):
    """Show ``kit`` in the index list and wait until htmx has put it in place:
    a drag started while the new chips are still being swapped in does not
    start at all (seen under load: no dragstart event)."""
    with page.expect_response(lambda r: "/indexes/kit-content" in r.url and r.status == 200):
        page.select_option("#index-kit-dropdown", kit.kit_id)
    page.wait_for_function(
        "() => !document.querySelector('.htmx-request, .htmx-swapping, .htmx-settling, .htmx-added')")


def _wait_for_dialog(page, seen):
    """A confirm opens during the drop; wait for it rather than a fixed time."""
    for _ in range(100):
        if seen["dialogs"]:
            return
        page.wait_for_timeout(100)


def _cell(page, run_id, n, slot):
    """The assigned-index cell of sample n: i7 first, then i5."""
    return page.locator(f"#sample-row-{run_id}-s{n} .index-assigned").nth(0 if slot == "i7" else 1)


def _watch(page):
    """Record confirm messages and assign requests; answer each confirm with ``answer``."""
    seen = {"dialogs": [], "assigns": [], "answer": True}
    page.on("dialog", lambda d: (seen["dialogs"].append(d.message),
                                 d.accept() if seen["answer"] else d.dismiss()))
    page.on("request", lambda r: seen["assigns"].append(r.url) if "assign-index" in r.url else None)
    return seen


@pytest.mark.browser
def test_a_drop_on_an_index_replaces_it_after_asking(logged_in_page, base_url, app_ctx, kit, run_id):
    page = logged_in_page
    _open(page, base_url, run_id)
    page.get_by_role("button", name="Edit indexes").click()
    _pick_kit(page, kit)
    seen = _watch(page)

    chip = page.locator(f'#index-list-container [data-index-pair-id="{KIT}_EI2"]')
    with page.expect_response(lambda r: "/assign-index" in r.url) as resp:
        chip.drag_to(_cell(page, run_id, 1, "i5"))

    assert resp.value.status == 200
    assert seen["dialogs"] == ["EI-01 already has an index (EI0). Replace it with the one you dropped?"]
    sample = _sample(app_ctx, run_id, 1)
    assert (sample.index1_sequence, sample.index2_sequence) == (I7[2], I5[2])
    assert _sample(app_ctx, run_id, 2).index1_sequence == I7[1]


@pytest.mark.browser
def test_saying_no_keeps_the_index(logged_in_page, base_url, app_ctx, kit, run_id):
    page = logged_in_page
    _open(page, base_url, run_id)
    page.get_by_role("button", name="Edit indexes").click()
    _pick_kit(page, kit)
    seen = _watch(page)
    seen["answer"] = False

    chip = page.locator(f'#index-list-container [data-index-pair-id="{KIT}_EI2"]')
    chip.drag_to(_cell(page, run_id, 1, "i7"))
    _wait_for_dialog(page, seen)
    page.wait_for_timeout(500)

    assert len(seen["dialogs"]) == 1
    assert seen["assigns"] == []
    assert _sample(app_ctx, run_id, 1).index1_sequence == I7[0]


@pytest.mark.browser
def test_a_single_index_on_a_pair_says_the_pair_goes(logged_in_page, base_url, app_ctx, combi_kit, run_id):
    page = logged_in_page
    _open(page, base_url, run_id)
    page.get_by_role("button", name="Edit indexes").click()
    _pick_kit(page, combi_kit)
    seen = _watch(page)
    seen["answer"] = False

    chip = page.locator(f'#index-list-container [data-index-id="{COMBI}_i7_CI7"]')
    chip.drag_to(_cell(page, run_id, 1, "i7"))
    _wait_for_dialog(page, seen)
    page.wait_for_timeout(500)

    [message] = seen["dialogs"]
    assert message.startswith("EI-01 already has an index (EI0). Replace it with the one you dropped?")
    assert "pair" in message and "i5" in message
    assert seen["assigns"] == []
    assert _sample(app_ctx, run_id, 1).index_pair is not None


@pytest.mark.browser
def test_an_index_is_no_drop_target_outside_editing(logged_in_page, base_url, app_ctx, kit, half_run_id):
    page = logged_in_page
    _open(page, base_url, half_run_id)
    _pick_kit(page, kit)
    seen = _watch(page)

    chip = page.locator(f'#index-list-container [data-index-pair-id="{KIT}_EI2"]')
    chip.drag_to(_cell(page, half_run_id, 1, "i7"))
    page.wait_for_timeout(500)

    assert seen["dialogs"] == []
    assert seen["assigns"] == []
    assert _sample(app_ctx, half_run_id, 1).index1_sequence == I7[0]


@pytest.mark.browser
def test_several_dropped_on_an_index_warn_once_and_fill_down(logged_in_page, base_url, app_ctx, kit, run_id):
    page = logged_in_page
    _open(page, base_url, run_id)
    page.get_by_role("button", name="Edit indexes").click()
    _pick_kit(page, kit)
    seen = _watch(page)

    first = page.locator(f'#index-list-container [data-index-pair-id="{KIT}_EI1"]')
    last = page.locator(f'#index-list-container [data-index-pair-id="{KIT}_EI2"]')
    first.click()
    last.click(modifiers=["Shift"])
    with page.expect_response(lambda r: "assign-indexes-bulk" in r.url) as resp:
        first.drag_to(_cell(page, run_id, 1, "i7"))

    assert resp.value.status == 200
    [message] = seen["dialogs"]
    assert "This will replace the index on 2 sample(s) that already have one: EI-01, EI-02." in message
    assert _sample(app_ctx, run_id, 1).index1_sequence == I7[1]
    assert _sample(app_ctx, run_id, 2).index1_sequence == I7[2]
