"""The run page's index list scrolls in one place, and stays beside the table.

The panel, the kit area inside it and the list inside that each had their
own height cap and scrollbar (800, 700 and 600 px), so a long kit showed
scrollbars inside scrollbars. Now only the list area scrolls. On a wide
screen the panel sticks beside the table while the page scrolls, so the
indexes stay in reach for a sample far down the table.
"""

from datetime import datetime

import pytest
from playwright.sync_api import expect

from seqsetup.models.index import Index, IndexKit, IndexMode, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun

KIT = "Scroll-Kit"
BASES = "ACGT"


def _seq(n, salt):
    """An 8-base sequence made from n, different for each n."""
    return "".join(BASES[(n >> (2 * k) ^ salt) & 3] for k in range(8))


def _kit(app_ctx, name):
    from seqsetup.services.validation import clear_validation_cache

    kit = IndexKit(
        name=name, version="1.0", index_mode=IndexMode.UNIQUE_DUAL,
        index_pairs=[
            IndexPair(
                id=f"{name}_S{k:03d}", name=f"S{k:03d}",
                index1=Index(name=f"S{k:03d}", sequence=_seq(k, 1), index_type=IndexType.I7),
                index2=Index(name=f"S{k:03d}", sequence=_seq(k, 2), index_type=IndexType.I5),
            )
            for k in range(96)
        ],
    )
    app_ctx.index_kit_repo.save(kit)
    clear_validation_cache()
    return kit


def _drop_kit(app_ctx, kit):
    from seqsetup.services.validation import clear_validation_cache

    app_ctx.index_kit_repo.delete(kit.name, kit.version)
    clear_validation_cache()


@pytest.fixture
def big_kit(app_ctx):
    """A 96-pair kit, long enough to need a scrollbar; deleted afterwards."""
    kit = _kit(app_ctx, KIT)
    yield kit
    _drop_kit(app_ctx, kit)


@pytest.fixture
def other_kit(app_ctx):
    """A second 96-pair kit to switch to; deleted afterwards."""
    kit = _kit(app_ctx, "Scroll-Kit-B")
    yield kit
    _drop_kit(app_ctx, kit)


@pytest.fixture
def long_run_id(app_ctx, big_kit):
    """A draft with 40 samples and no indexes, so the page is long and the
    list shows; deleted afterwards."""
    t = datetime(2026, 1, 10, 9, 0, 0)
    run = SequencingRun(
        id="index-scroll-run", run_name="Scroll run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=RunStatus.DRAFT,
        created_at=t, updated_at=t,
    )
    for n in range(40):
        run.add_sample(Sample(id=f"{run.id}-s{n}", sample_id=f"SC-{n:02d}", lanes=[1]))
    app_ctx.run_repo.save(run)
    yield run.id
    app_ctx.run_repo.collection.delete_one({"_id": run.id})


SCROLLING = """() => {
    const panel = document.querySelector('.wizard-index-panel');
    return [panel, ...panel.querySelectorAll('*')]
        .filter(e => {
            const s = getComputedStyle(e);
            return (s.overflowY === 'auto' || s.overflowY === 'scroll') && e.scrollHeight > e.clientHeight + 1;
        })
        .map(e => e.id || e.className);
}"""


def _open(page, base_url, run_id, kit, width, height=900):
    page.set_viewport_size({"width": width, "height": height})
    page.goto(f"{base_url}/runs/{run_id}")
    page.wait_for_load_state("networkidle")
    with page.expect_response(lambda r: "/indexes/kit-content" in r.url and r.status == 200):
        page.select_option("#index-kit-dropdown", kit.kit_id)
    page.wait_for_function(
        "() => !document.querySelector('.htmx-request, .htmx-swapping, .htmx-settling, .htmx-added')")
    expect(page.locator(f'#index-list-container [data-index-pair-id="{KIT}_S095"]')).to_be_attached()


@pytest.mark.browser
@pytest.mark.parametrize("width,height", [(1600, 900), (1600, 700), (1280, 900)])
def test_the_index_list_has_one_scrollbar(logged_in_page, base_url, big_kit, long_run_id, width, height):
    """At 700 px tall the panel is shorter than the list's own 600 px cap
    plus the kit picker above it, so a cap left on the list shows a second
    scrollbar."""
    page = logged_in_page
    _open(page, base_url, long_run_id, big_kit, width, height)
    assert len(page.evaluate(SCROLLING)) == 1, page.evaluate(SCROLLING)


@pytest.mark.browser
def test_another_kit_opens_at_the_top(logged_in_page, base_url, big_kit, other_kit, long_run_id):
    """The list area stays while its content is swapped, so it would keep
    the old kit's scroll position, with the filter box out of view."""
    page = logged_in_page
    _open(page, base_url, long_run_id, big_kit, 1600)
    box = page.locator("#index-list-container")
    box.evaluate("e => { e.scrollTop = e.scrollHeight; }")
    assert box.evaluate("e => e.scrollTop") > 500

    with page.expect_response(lambda r: "/indexes/kit-content" in r.url and r.status == 200):
        page.select_option("#index-kit-dropdown", other_kit.kit_id)
    page.wait_for_function(
        "() => !document.querySelector('.htmx-request, .htmx-swapping, .htmx-settling, .htmx-added')")
    expect(page.locator('#index-list-container [data-index-pair-id="Scroll-Kit-B_S000"]')).to_be_attached()
    assert box.evaluate("e => e.scrollTop") == 0


@pytest.mark.browser
def test_the_last_index_can_be_scrolled_to(logged_in_page, base_url, big_kit, long_run_id):
    page = logged_in_page
    _open(page, base_url, long_run_id, big_kit, 1600)
    last = page.locator(f'#index-list-container [data-index-pair-id="{KIT}_S095"]')
    last.scroll_into_view_if_needed()
    expect(last).to_be_in_viewport()


@pytest.mark.browser
def test_the_panel_stays_beside_the_table_on_a_wide_screen(logged_in_page, base_url, big_kit, long_run_id):
    """Scrolled so that sample 10 of 40 is at the top of the window, the
    table fills the window and the panel is held at the top of it. (Near
    the end of the table the panel ends with the table, as a sticky box
    does.)"""
    page = logged_in_page
    _open(page, base_url, long_run_id, big_kit, 1600)
    page.evaluate("id => window.scrollBy(0, document.getElementById(id).getBoundingClientRect().top)",
                  f"sample-row-{long_run_id}-s10")
    assert page.evaluate("() => window.scrollY") > 500
    panel = page.locator(".wizard-index-panel").bounding_box()
    assert 0 <= panel["y"] <= 20
    assert panel["y"] + panel["height"] <= 900
    expect(page.locator(f'#index-list-container [data-index-pair-id="{KIT}_S000"]')).to_be_in_viewport()
