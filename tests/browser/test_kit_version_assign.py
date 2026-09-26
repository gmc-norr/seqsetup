"""An index dragged, dropped or keyboard-assigned from a kit version lands
with that version's sequences.

Two versions of one kit hold the same index ids. Each chip carries its
kit_id and app.js sends it with the assign request, so the server takes
the index from the version the user was looking at. A selection made in
one kit version is cleared when the kit picker changes, so a drag in the
new version never carries chips left over from the old one.
"""

from datetime import datetime

import pytest
from playwright.sync_api import expect

from seqsetup.models.index import Index, IndexKit, IndexMode, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun

KIT = "Kit-Version-Test"
V1_I7 = ["ACGTACGT", "CAGTCAGT"]
V2_I7 = ["TGCATGCA", "GTCAGTCA"]
I5 = ["AACCGGTT", "TTGGCCAA"]


def _kit(version, i7):
    return IndexKit(
        name=KIT, version=version, index_mode=IndexMode.UNIQUE_DUAL,
        index_pairs=[
            IndexPair(
                id=f"{KIT}_KV{k}", name=f"KV{k}",
                index1=Index(name=f"KV{k}", sequence=i7[k], index_type=IndexType.I7),
                index2=Index(name=f"KV{k}", sequence=I5[k], index_type=IndexType.I5),
            )
            for k in range(2)
        ],
    )


@pytest.fixture
def two_versions(app_ctx):
    """Versions 1.0 and 2.0 of one kit, same ids, different i7s; deleted afterwards."""
    from seqsetup.services.validation import clear_validation_cache

    kits = [_kit("1.0", V1_I7), _kit("2.0", V2_I7)]
    for kit in kits:
        app_ctx.index_kit_repo.save(kit)
    clear_validation_cache()
    yield kits
    for kit in kits:
        app_ctx.index_kit_repo.delete(kit.name, kit.version)
    clear_validation_cache()


@pytest.fixture
def run_id(app_ctx):
    """A draft with two un-indexed samples; deleted afterwards."""
    t = datetime(2026, 1, 10, 9, 0, 0)
    run = SequencingRun(
        id="kit-version-run", run_name="Kit version run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=RunStatus.DRAFT,
        created_at=t, updated_at=t,
    )
    for n in (1, 2):
        run.add_sample(Sample(id=f"{run.id}-s{n}", sample_id=f"KV-0{n}", lanes=[n]))
    app_ctx.run_repo.save(run)
    yield run.id
    app_ctx.run_repo.delete(run.id)


def _open_on_kit(page, base_url, run_id, kit_id):
    page.goto(f"{base_url}/runs/{run_id}")
    page.wait_for_load_state("networkidle")
    with page.expect_response(lambda r: "/indexes/kit-content" in r.url and r.status == 200):
        page.select_option("#index-kit-dropdown", kit_id)
    expect(page.locator("#index-list-container")).to_contain_text("KV0")


def _chip(page, k):
    return page.locator(f'#index-list-container [data-index-pair-id="{KIT}_KV{k}"]')


def _zone(page, run_id, n):
    return page.locator(f"#sample-row-{run_id}-s{n} .drop-zone").first


def _i7(app_ctx, run_id, n):
    return app_ctx.run_repo.get_by_id(run_id).get_sample(f"{run_id}-s{n}").index1_sequence


@pytest.mark.browser
def test_dragged_chip_uses_its_kit_version(logged_in_page, base_url, app_ctx, two_versions, run_id):
    page = logged_in_page
    _open_on_kit(page, base_url, run_id, two_versions[1].kit_id)

    with page.expect_response(lambda r: "/assign-index" in r.url) as resp:
        _chip(page, 0).drag_to(_zone(page, run_id, 1))

    assert resp.value.status == 200
    assert _i7(app_ctx, run_id, 1) == V2_I7[0]


@pytest.mark.browser
def test_keyboard_assign_uses_the_chip_kit_version(logged_in_page, base_url, app_ctx, two_versions, run_id):
    page = logged_in_page
    _open_on_kit(page, base_url, run_id, two_versions[1].kit_id)

    _chip(page, 1).click()
    zone = _zone(page, run_id, 1)
    zone.focus()
    with page.expect_response(lambda r: "/assign-index" in r.url) as resp:
        zone.press("Enter")

    assert resp.value.status == 200
    assert _i7(app_ctx, run_id, 1) == V2_I7[1]


@pytest.mark.browser
def test_several_dragged_chips_use_their_kit_version(logged_in_page, base_url, app_ctx, two_versions, run_id):
    page = logged_in_page
    _open_on_kit(page, base_url, run_id, two_versions[1].kit_id)

    _chip(page, 0).click()
    _chip(page, 1).click(modifiers=["Shift"])
    with page.expect_response(lambda r: "assign-indexes-bulk" in r.url) as resp:
        _chip(page, 0).drag_to(_zone(page, run_id, 1))

    assert resp.value.status == 200
    assert _i7(app_ctx, run_id, 1) == V2_I7[0]
    assert _i7(app_ctx, run_id, 2) == V2_I7[1]


@pytest.mark.browser
def test_changing_the_kit_drops_the_old_selection(logged_in_page, base_url, app_ctx, two_versions, run_id):
    """Select both chips in v1.0, switch to v2.0, drag v2.0's first chip:
    only that chip lands, from v2.0 — nothing from the v1.0 selection."""
    page = logged_in_page
    v1, v2 = two_versions
    _open_on_kit(page, base_url, run_id, v1.kit_id)
    _chip(page, 0).click()
    _chip(page, 1).click(modifiers=["Shift"])

    with page.expect_response(lambda r: "/indexes/kit-content" in r.url and r.status == 200):
        page.select_option("#index-kit-dropdown", v2.kit_id)
    expect(_chip(page, 0)).to_be_visible()

    with page.expect_response(lambda r: "/assign-index" in r.url) as resp:
        _chip(page, 0).drag_to(_zone(page, run_id, 1))

    assert resp.value.status == 200
    assert "assign-indexes-bulk" not in resp.value.url
    assert _i7(app_ctx, run_id, 1) == V2_I7[0]
    assert _i7(app_ctx, run_id, 2) is None


@pytest.mark.browser
def test_drop_on_ticked_rows_uses_the_chip_kit_version(logged_in_page, base_url, app_ctx, two_versions, run_id):
    page = logged_in_page
    _open_on_kit(page, base_url, run_id, two_versions[1].kit_id)
    page.on("dialog", lambda d: d.accept())
    page.locator(f"#sample-row-{run_id}-s1 .sample-checkbox").check()
    page.locator(f"#sample-row-{run_id}-s2 .sample-checkbox").check()

    with page.expect_response(lambda r: "assign-index-to-selected" in r.url) as resp:
        _chip(page, 1).drag_to(_zone(page, run_id, 1))

    assert resp.value.status == 200
    assert _i7(app_ctx, run_id, 1) == V2_I7[1]
    assert _i7(app_ctx, run_id, 2) == V2_I7[1]
