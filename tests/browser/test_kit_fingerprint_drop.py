"""A drop from a page loaded before its kit changed is refused and says why
(index mix-up audit #6, 2026-10-14; the user's choice "Drop + sync"). The
kit changed under the same name and version -- a sync, say -- and the drop
used to give the sample the new sequences, which the chip never showed."""

from datetime import datetime

import pytest
from playwright.sync_api import expect

from seqsetup.models.index import Index, IndexKit, IndexMode, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun
from .conftest import hold_edit_lock

KIT = "Kit-Fingerprint-Test"
SHOWN = ["ACGTACGT", "CAGTCAGT"]
CHANGED = "The index kit changed since this page was loaded. Nothing was assigned. Reload the page."


def _kit(i7):
    return IndexKit(name=KIT, version="1.0", index_mode=IndexMode.UNIQUE_DUAL, index_pairs=[
        IndexPair(id=f"{KIT}_KF{k}", name=f"KF{k}",
                  index1=Index(f"KF{k}", i7[k], IndexType.I7),
                  index2=Index(f"KF{k}", ["AACCGGTT", "TTGGCCAA"][k], IndexType.I5))
        for k in range(2)
    ])


@pytest.fixture
def kit(app_ctx):
    from seqsetup.services.validation import clear_validation_cache
    app_ctx.index_kit_repo.save(_kit(SHOWN))
    clear_validation_cache()
    yield
    app_ctx.index_kit_repo.delete(KIT, "1.0")
    clear_validation_cache()


@pytest.fixture
def run_id(app_ctx):
    """A draft with two un-indexed samples; deleted afterwards."""
    t = datetime(2026, 1, 10, 9, 0, 0)
    run = SequencingRun(
        id="kit-fingerprint-run", run_name="Kit fingerprint run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=RunStatus.DRAFT,
        created_at=t, updated_at=t,
    )
    for n in (1, 2):
        run.add_sample(Sample(id=f"{run.id}-s{n}", sample_id=f"KF-0{n}", lanes=[n]))
    app_ctx.run_repo.save(run)
    hold_edit_lock(app_ctx, run.id)
    yield run.id
    app_ctx.run_repo.collection.delete_one({"_id": run.id})


def _open(page, base_url, run_id):
    page.goto(f"{base_url}/runs/{run_id}")
    page.wait_for_load_state("networkidle")
    with page.expect_response(lambda r: "/indexes/kit-content" in r.url and r.status == 200):
        page.select_option("#index-kit-dropdown", f"{KIT}:1.0")
    expect(page.locator("#index-list-container")).to_contain_text("KF0")


def _chip(page, k):
    return page.locator(f'#index-list-container [data-index-pair-id="{KIT}_KF{k}"]')


def _zone(page, run_id, n):
    return page.locator(f"#sample-row-{run_id}-s{n} .drop-zone").first


def _i7s(app_ctx, run_id):
    return [s.index1_sequence for s in app_ctx.run_repo.get_by_id(run_id).samples]


def _change_the_kit(app_ctx):
    app_ctx.index_kit_repo.save(_kit(["GGGGGGGG", "CAGTCAGT"]))


def _sent_the_shown_fingerprint(resp):
    """The drop sent the fingerprint of the kit the page showed: refused for
    that, not for sending none (review P3-5, 2026-10-14)."""
    return _kit(SHOWN).fingerprint() in resp.value.request.post_data


@pytest.mark.browser
def test_one_dragged_chip(logged_in_page, base_url, app_ctx, kit, run_id):
    page = logged_in_page
    _open(page, base_url, run_id)
    _change_the_kit(app_ctx)

    with page.expect_response(lambda r: "/assign-index" in r.url) as resp:
        _chip(page, 0).drag_to(_zone(page, run_id, 1))

    assert resp.value.status == 409
    assert _sent_the_shown_fingerprint(resp)
    expect(page.locator("#error-banner")).to_contain_text(CHANGED)
    assert _i7s(app_ctx, run_id) == [None, None]


@pytest.mark.browser
def test_several_dragged_chips(logged_in_page, base_url, app_ctx, kit, run_id):
    page = logged_in_page
    _open(page, base_url, run_id)
    _change_the_kit(app_ctx)

    _chip(page, 0).click()
    _chip(page, 1).click(modifiers=["Shift"])
    with page.expect_response(lambda r: "assign-indexes-bulk" in r.url) as resp:
        _chip(page, 0).drag_to(_zone(page, run_id, 1))

    assert resp.value.status == 409
    assert _sent_the_shown_fingerprint(resp)
    expect(page.locator("#error-banner")).to_contain_text(CHANGED)
    assert _i7s(app_ctx, run_id) == [None, None]


@pytest.mark.browser
def test_after_a_reload_the_new_kit_is_dropped(logged_in_page, base_url, app_ctx, kit, run_id):
    page = logged_in_page
    _change_the_kit(app_ctx)
    _open(page, base_url, run_id)

    with page.expect_response(lambda r: "/assign-index" in r.url) as resp:
        _chip(page, 0).drag_to(_zone(page, run_id, 1))

    assert resp.value.status == 200
    assert _i7s(app_ctx, run_id) == ["GGGGGGGG", None]
