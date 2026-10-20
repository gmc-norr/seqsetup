"""The index safety net through the real page, so ``app.js`` is in the loop.

The integration net (``tests/integration/test_index_safety_net.py``) drives
the routes. This one drives the page: it picks a kit in the dropdown, drags a
chip, shift-clicks a range backwards and drags it, ticks rows and drops,
assigns from the keyboard, uses the fill dialog and the lane panel's Apply,
marks the run Ready, downloads the stored Sample Sheet from the Export panel,
and compares every row to the same map the integration net uses
(``tests/index_safety_net.py``).

The audit's first bug lived in ``app.js``: several chips dragged at once were
sent in click order, so a shift-click made backwards gave the first row the
last chip's index (index mix-up audit, 2026-10-14). Only a browser can see
that, which is why this net exists beside the other one.
"""

import json
import re
from datetime import datetime
from urllib.parse import parse_qs

import pytest
from playwright.sync_api import expect

from seqsetup.models.index import Index, IndexKit, IndexMode, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import (InstrumentPlatform, RunCycles, RunStatus,
                                            SequencingRun)

from tests.index_safety_net import (I5_SHEET_DIRECTION, INDEX_LENGTH, Expected,
                                    Sequences, reverse_complement)

from .conftest import hold_edit_lock

RUN_ID = "browser-safety-net-run"
DROP_KIT = "Net-Browser-Drop"
FILL_KIT = "Net-Browser-Fill"
VERSION = "1.0"
# The seeded WGS test profile lists a BCLConvert profile with a Lane column
# (tests/browser/conftest.py), so Mark Ready writes the sections a sequencer
# really reads.
TEST_ID, TEST_VERSION = "WGS", "1"
INSTRUMENT, FLOWCELL, WORKFLOW = InstrumentPlatform.NOVASEQ_X, "10B", ""
DIRECTION = I5_SHEET_DIRECTION[(INSTRUMENT.value, WORKFLOW)]

SAMPLES = [f"B-{n:02d}" for n in range(1, 11)]

_SEQUENCES = Sequences()
DROP_PAIRS = _SEQUENCES.pairs(6)   # what the drop kit's chips hold, in panel order
FILL_PAIRS = _SEQUENCES.pairs(6)   # what the fill kit holds, in panel order

# Which rows each path fills, and with which of the drop kit's pairs. The
# names are the sample IDs the fixture seeds, in table order.
ONE_CHIP = SAMPLES[0]              # dragged on its own -> DROP_PAIRS[0]
A_RANGE = SAMPLES[1:4]             # shift-clicked backwards -> DROP_PAIRS[1..3]
TICKED = SAMPLES[4:6]              # one chip on two ticked rows -> DROP_PAIRS[4]
BY_KEYBOARD = SAMPLES[6]           # Enter on a chip, Enter on a zone -> DROP_PAIRS[5]
BY_FILL = SAMPLES[7:]              # the fill dialog, from the fill kit's second


def _pair_kit(name, pairs):
    return IndexKit(
        name=name, version=VERSION, index_mode=IndexMode.UNIQUE_DUAL,
        index_pairs=[
            IndexPair(
                id=f"{name}_P{k}", name=f"P{k}",
                index1=Index(name=f"P{k}", sequence=i7, index_type=IndexType.I7),
                index2=Index(name=f"P{k}", sequence=i5, index_type=IndexType.I5),
            )
            for k, (i7, i5) in enumerate(pairs)
        ],
    )


@pytest.fixture
def kits(app_ctx):
    """One kit the net drops from and one it fills from -- no sequence in
    common, so the fill never skips an index as already used."""
    from seqsetup.services.validation import clear_validation_cache
    for name, pairs in ((DROP_KIT, DROP_PAIRS), (FILL_KIT, FILL_PAIRS)):
        app_ctx.index_kit_repo.save(_pair_kit(name, pairs))
    clear_validation_cache()
    yield
    for name in (DROP_KIT, FILL_KIT):
        app_ctx.index_kit_repo.delete(name, VERSION)
    clear_validation_cache()


@pytest.fixture
def run_id(app_ctx):
    """A draft of ten un-indexed samples, all on lane 1; deleted afterwards."""
    when = datetime(2026, 1, 10, 9, 0, 0)
    run = SequencingRun(
        id=RUN_ID, run_name="Index safety net (browser)",
        instrument_platform=INSTRUMENT, flowcell_type=FLOWCELL, i5_workflow=WORKFLOW,
        run_cycles=RunCycles(151, 151, INDEX_LENGTH, INDEX_LENGTH),
        status=RunStatus.DRAFT, created_at=when, updated_at=when,
    )
    for name in SAMPLES:
        run.add_sample(Sample(id=f"{RUN_ID}-{name}", sample_id=name, test_id=TEST_ID,
                              test_version=TEST_VERSION, lanes=[1]))
    app_ctx.run_repo.save(run)
    hold_edit_lock(app_ctx, RUN_ID)
    yield RUN_ID
    app_ctx.run_repo.collection.delete_one({"_id": RUN_ID})


# --------------------------------------------------------------------------
# Reading the page the way app.js reads it
# --------------------------------------------------------------------------

_READ_ROWS = """() => Array.from(document.querySelectorAll('#sample-table .sample-row'))
    .map(row => ({
        row_id: row.id.slice('sample-row-'.length),
        // The cell's text without Check's "!" mark, which it holds while
        // Check lists an error for the row.
        sample_id: (cell => {
            if (!cell) return '';
            const copy = cell.cloneNode(true);
            copy.querySelectorAll('.row-error-badge').forEach(badge => badge.remove());
            return copy.textContent;
        })(row.querySelector('td.sample-id-cell')),
        i7: row.dataset.i7 || '',
        i5: row.dataset.i5 || '',
        lanes: (row.querySelector('.lanes-display') || {}).textContent || '',
    }))"""

_READ_CHIPS = """() => Array.from(document.querySelectorAll(
        '#index-list-container .draggable-index-compact')).map(chip => ({
    id: chip.dataset.indexPairId || chip.dataset.indexId,
    kit_id: chip.dataset.kitId || '',
    kit_fingerprint: chip.dataset.kitFingerprint || '',
    title: chip.getAttribute('title') || '',
}))"""


def shown_rows(page) -> dict:
    """``sample_id -> {"i7", "i5", "lanes"}``, from each row's own data
    attributes and its lanes cell. Each sample is read from one row, its
    own: the row's id names the sample the run seeded under that ID."""
    rows = page.evaluate(_READ_ROWS)
    shown = {
        row["sample_id"].strip(): {
            "i7": row["i7"], "i5": row["i5"],
            "lanes": [] if row["lanes"].strip() in ("", "All")
                     else row["lanes"].strip().split(","),
        }
        for row in rows
    }
    assert len(shown) == len(rows), f"a sample is drawn twice: {[r['sample_id'] for r in rows]}"
    for row in rows:
        assert row["row_id"] == f"{RUN_ID}-{row['sample_id'].strip()}", \
            f"row {row['row_id']} shows the ID {row['sample_id'].strip()!r}"
    return shown


def shown_chips(page) -> list[dict]:
    """The panel's chips in the order it shows them -- the panel order a
    several-chip drag must fill rows in."""
    chips = page.evaluate(_READ_CHIPS)
    assert chips, "the index panel shows no chip"
    return chips


def _row(run_id, sample_id):
    return f"#sample-row-{run_id}-{sample_id}"


def _chip(page, kit, k):
    return page.locator(f'#index-list-container [data-index-pair-id="{kit}_P{k}"]')


def _zone(page, run_id, sample_id):
    return page.locator(f"{_row(run_id, sample_id)} .drop-zone").first


def _open_on_kit(page, base_url, run_id, kit):
    page.goto(f"{base_url}/runs/{run_id}")
    page.wait_for_load_state("networkidle")
    with page.expect_response(lambda r: "/indexes/kit-content" in r.url and r.status == 200):
        page.select_option("#index-kit-dropdown", f"{kit}:{VERSION}")
    expect(page.locator("#index-list-container")).to_contain_text("P0")


def _apply_lanes(page, run_id, sample_ids, lanes):
    """The lane panel: tick the rows, tick the lanes, press Apply."""
    page.evaluate("""() => document.querySelectorAll('.sample-checkbox')
        .forEach(box => { box.checked = false; })""")
    for sample_id in sample_ids:
        page.locator(f"{_row(run_id, sample_id)} .sample-checkbox").check()
    boxes = page.locator(".bulk-lane-checkbox")
    for k in range(boxes.count()):
        box = boxes.nth(k)
        if box.input_value() in [str(lane) for lane in lanes]:
            box.check()
        else:
            box.uncheck()
    with page.expect_response(lambda r: r.url.endswith("/samples/set-lanes")) as answer:
        page.locator('[data-action="bulk-apply-lanes"]').click()
    assert answer.value.status == 200, answer.value.text()
    page.wait_for_load_state("networkidle")


# One chip dragged onto one row, with the drag events app.js listens for.
# Playwright's own drag_to needs the chip and the row on screen together, and
# once the table is full of samples they are not: the page has one scrollbar
# (tests/browser/test_multi_assign_confirm.py dispatches the events for the
# same reason). The handlers are the real ones -- handleDragStart, then the
# delegated drop listener -- so app.js is still in the loop.
_DISPATCH_DROP = """([chipSel, zoneSel]) => {
    const chip = document.querySelector(chipSel);
    const zone = document.querySelector(zoneSel);
    if (!chip || !zone) throw new Error('no chip or no drop zone: ' + chipSel + ' / ' + zoneSel);
    const dt = new DataTransfer();
    chip.dispatchEvent(new DragEvent('dragstart', {dataTransfer: dt, bubbles: true}));
    zone.dispatchEvent(new DragEvent('dragover', {dataTransfer: dt, bubbles: true, cancelable: true}));
    zone.dispatchEvent(new DragEvent('drop', {dataTransfer: dt, bubbles: true, cancelable: true}));
}"""


def _drop_chip(page, run_id, kit, k, sample_id):
    page.evaluate(_DISPATCH_DROP, [
        f'#index-list-container [data-index-pair-id="{kit}_P{k}"]',
        f"{_row(run_id, sample_id)} .drop-zone",
    ])


def _untick_all(page):
    page.evaluate("""() => document.querySelectorAll('.sample-checkbox')
        .forEach(box => { box.checked = false; box.dispatchEvent(
            new Event('change', {bubbles: true})); })""")


@pytest.mark.browser
def test_a_row_is_read_without_its_error_mark(logged_in_page, base_url, run_id):
    """Check marks a row it lists an error for with a "!" in its Sample ID
    cell (``markSampleErrors`` in ``app.js``) and refreshes after every
    change. Read before the refresh landed, the net once took "!B-08" for
    B-08's ID and failed on a busy machine. A sample with no index is an
    error, so every seeded row carries the mark here."""
    page = logged_in_page
    page.goto(f"{base_url}/runs/{run_id}")
    page.wait_for_load_state("networkidle")
    expect(page.locator("#sample-table td.sample-id-cell .row-error-badge")).to_have_count(
        len(SAMPLES))

    assert sorted(shown_rows(page)) == SAMPLES


@pytest.mark.browser
def test_a_row_is_read_only_as_its_own_sample(logged_in_page, base_url, run_id):
    """The reader keys rows by the ID they show: a sample drawn twice would
    fold into one entry, the last winning, and a row showing another
    sample's ID would be read as that sample (fresh review of 017950b,
    P3-3)."""
    page = logged_in_page
    page.goto(f"{base_url}/runs/{run_id}")
    page.wait_for_load_state("networkidle")
    page.evaluate("""() => { const row = document.querySelector('#sample-table .sample-row');
        row.after(row.cloneNode(true)); }""")
    with pytest.raises(AssertionError):
        shown_rows(page)

    page.reload()
    page.wait_for_load_state("networkidle")
    page.evaluate(f"""() => {{ document.querySelector(
        '#sample-row-{run_id}-{SAMPLES[0]} td.sample-id-cell').textContent = '{SAMPLES[1]}x'; }}""")
    with pytest.raises(AssertionError):
        shown_rows(page)


# --------------------------------------------------------------------------
# The net
# --------------------------------------------------------------------------

@pytest.mark.browser
def test_no_sample_gets_another_samples_index_on_the_page(
        logged_in_page, base_url, app_ctx, kits, run_id):
    page = logged_in_page
    expected = Expected("browser net")
    for name in SAMPLES:
        expected.add(name, [1], "seeded")

    # -- lanes first: the two rows that will share one index need a lane each
    page.goto(f"{base_url}/runs/{run_id}")
    page.wait_for_load_state("networkidle")
    for offset, name in enumerate(TICKED):
        lanes = [2 + offset]
        _apply_lanes(page, run_id, [name], lanes)
        expected.set_lanes(name, lanes, "the lane panel's Apply")
    # And a sample in two lanes, so the sheet must hold two rows for it.
    _apply_lanes(page, run_id, [ONE_CHIP], [1, 4])
    expected.set_lanes(ONE_CHIP, [1, 4], "the lane panel's Apply")
    _untick_all(page)

    # -- the panel's chips carry the kit's fingerprint and its order
    _open_on_kit(page, base_url, run_id, DROP_KIT)
    chips = shown_chips(page)
    assert [chip["id"] for chip in chips] == \
        [f"{DROP_KIT}_P{k}" for k in range(len(DROP_PAIRS))], \
        "the panel does not show the drop kit's pairs in the kit's own order"
    assert all(chip["kit_id"] == f"{DROP_KIT}:{VERSION}" for chip in chips)
    assert all(len(chip["kit_fingerprint"]) == 64 for chip in chips), \
        "every chip must carry its kit's fingerprint for the drop to send"
    for k, (i7, i5) in enumerate(DROP_PAIRS):
        assert f"i7: {i7}" in chips[k]["title"] and f"i5: {i5}" in chips[k]["title"], \
            f"chip P{k} does not show the sequences this test built it from"

    # -- one chip dragged onto one row
    with page.expect_response(lambda r: "/assign-index" in r.url) as answer:
        _chip(page, DROP_KIT, 0).drag_to(_zone(page, run_id, ONE_CHIP))
    assert answer.value.status == 200
    expected.set_pair(ONE_CHIP, "one chip dragged", *DROP_PAIRS[0])
    page.wait_for_load_state("networkidle")

    # -- a range shift-clicked BACKWARDS, then dragged: the rows take the
    # chips in the panel's order, not the click order (the audit's first bug)
    last = len(A_RANGE)  # chips P1..P3; click P3 first, then shift-click P1
    _chip(page, DROP_KIT, last).click()
    _chip(page, DROP_KIT, 1).click(modifiers=["Shift"])
    with page.expect_request(lambda r: "assign-indexes-bulk" in r.url) as asked:
        with page.expect_response(lambda r: "assign-indexes-bulk" in r.url) as answer:
            _chip(page, DROP_KIT, 1).drag_to(_zone(page, run_id, A_RANGE[0]))
    assert answer.value.status == 200
    # What app.js SENT, in order: the chips were clicked P3 first, so a page
    # that sent click order would send P3, P1, P2 here. This is the audit's
    # first bug and the reason this net runs in a browser at all -- the server
    # sorts into panel order as well, so only the request itself can show it.
    sent = json.loads(parse_qs(asked.value.post_data)["indexes_json"][0])
    assert [entry["id"] for entry in sent] == \
        [f"{DROP_KIT}_P{k}" for k in (1, 2, 3)], sent
    assert all(len(entry["kit_fingerprint"]) == 64 for entry in sent)
    for offset, name in enumerate(A_RANGE):
        expected.set_pair(name, "a range shift-clicked backwards",
                          *DROP_PAIRS[1 + offset])

    # -- one chip on two ticked rows: they are in different lanes
    page.wait_for_load_state("networkidle")
    for name in TICKED:
        page.locator(f"{_row(run_id, name)} .sample-checkbox").check()
    page.on("dialog", lambda dialog: dialog.accept())
    with page.expect_response(lambda r: "assign-index-to-selected" in r.url) as answer:
        _drop_chip(page, run_id, DROP_KIT, 4, TICKED[0])
    assert answer.value.status == 200
    for name in TICKED:
        expected.set_pair(name, "a drop on ticked rows", *DROP_PAIRS[4])
    page.wait_for_load_state("networkidle")
    _untick_all(page)

    # -- from the keyboard: Enter on a chip, Enter on a drop target
    _chip(page, DROP_KIT, 5).focus()
    _chip(page, DROP_KIT, 5).press("Enter")
    zone = _zone(page, run_id, BY_KEYBOARD)
    zone.focus()
    with page.expect_response(lambda r: "/assign-index" in r.url) as answer:
        zone.press("Enter")
    assert answer.value.status == 200
    expected.set_pair(BY_KEYBOARD, "assigned from the keyboard", *DROP_PAIRS[5])

    # -- the fill dialog, from a non-default Start at
    page.wait_for_load_state("networkidle")
    with page.expect_response(lambda r: "/indexes/kit-content" in r.url and r.status == 200):
        page.select_option("#index-kit-dropdown", f"{FILL_KIT}:{VERSION}")
    with page.expect_response(lambda r: r.url.endswith("/index-fill/preview")
                              and r.status == 200):
        page.click(".index-fill-start button")
    second = page.locator("#index-fill-start option").filter(
        has_text=re.compile(r"^P1$")).get_attribute("value")
    with page.expect_response(lambda r: r.url.endswith("/index-fill/preview")
                              and r.status == 200):
        page.select_option("#index-fill-start", second)
    shown_fill = page.locator(".index-fill-table tbody tr")
    expect(shown_fill).to_have_count(len(BY_FILL))
    for offset, name in enumerate(BY_FILL):
        expect(shown_fill.nth(offset)).to_contain_text(name)
        expect(shown_fill.nth(offset)).to_contain_text(FILL_PAIRS[1 + offset][0])
    with page.expect_response(lambda r: r.url.endswith("/index-fill") and r.status == 200):
        page.click(".index-fill-actions button[type=submit]")
    for offset, name in enumerate(BY_FILL):
        expected.set_pair(name, "the fill dialog", *FILL_PAIRS[1 + offset])

    # -- what the page shows must be the map, before anything is marked Ready
    page.wait_for_load_state("networkidle")
    expected.check_page(shown_rows(page))
    expected.assert_no_lane_shares_an_index()

    # -- Mark Ready, then read the sheet the Export panel downloads. A run of
    # few samples over several lanes gets the colour-balance question, and
    # the lanes no sample is on get one of their own; answer each the way
    # its button does.
    with page.expect_response(lambda r: r.url.endswith("/status/ready")):
        page.get_by_role("button", name="Mark Ready").click()
    page.wait_for_load_state("networkidle")
    for _question in range(2):
        question = page.locator("#ready-message .ready-confirm")
        if not question.count():
            break
        with page.expect_response(lambda r: r.url.endswith("/status/ready")):
            question.get_by_role("button", name="Mark Ready anyway").click()
        page.wait_for_load_state("networkidle")
    expect(page.locator("#ready-message .ready-confirm")).to_have_count(0)
    expect(page.locator("#run-status-bar .status-ready")).to_be_visible(timeout=60_000)
    assert app_ctx.run_repo.get_by_id(run_id).status == RunStatus.READY

    with page.expect_download() as downloaded:
        page.click("text=Download Sample Sheet v2")
    download = downloaded.value
    with open(download.path(), encoding="utf-8") as handle:
        sheet = handle.read()

    checked = expected.check_sheet(sheet, "v2", DIRECTION["v2"])

    # Vacuity guards: the rows really were compared, every path was walked,
    # one sample has two lanes, and some i5 could tell the two directions
    # apart.
    assert checked == sum(expected.rows_with_a_lane().values()) \
        + sum(expected.rows_without_a_lane().values()) > 0, checked
    assert set(expected.paths) == {
        "seeded", "the lane panel's Apply", "one chip dragged",
        "a range shift-clicked backwards", "a drop on ticked rows",
        "assigned from the keyboard", "the fill dialog",
    }, sorted(expected.paths)
    assert any(len(row["lanes"]) > 1 for row in expected.samples.values())
    assert any(reverse_complement(row["i5"]) != row["i5"]
               for row in expected.samples.values())
