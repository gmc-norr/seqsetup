"""Group A1 through the real routes: every sample gets the right index
(spec docs/superpowers/specs/2026-10-03-group-a1-design.md)."""

import json

import pytest

from seqsetup.models.index import Index, IndexKit, IndexMode, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, SequencingRun
from seqsetup.services.index_fill import build_fill_plan

from .conftest import disable_repos, mark_ready

ORIGIN = {"Origin": "http://testserver"}
RUN = "a1-run"


def _pair_kit(ctx, name, pairs, **defaults):
    """Save a unique-dual kit; ``pairs`` is a list of (i7, i5). Pair k has
    the id f"{name}_P{k}" and the name f"P{k}"."""
    kit = IndexKit(
        name=name, version="1", index_mode=IndexMode.UNIQUE_DUAL,
        index_pairs=[
            IndexPair(
                id=f"{name}_P{k}", name=f"P{k}",
                index1=Index(name=f"P{k}", sequence=i7, index_type=IndexType.I7),
                index2=Index(name=f"P{k}", sequence=i5, index_type=IndexType.I5),
            )
            for k, (i7, i5) in enumerate(pairs)
        ],
        **defaults,
    )
    ctx.index_kit_repo.save(kit)
    return kit


def _run(ctx, sample_ids, cycles=(151, 151, 10, 10)):
    """Save a NovaSeq X draft with one sample per Sample ID given; their
    internal ids (Sample.id) are s1, s2, ..."""
    run = SequencingRun(
        id=RUN, run_name="A1", instrument_platform=InstrumentPlatform.NOVASEQ_X,
        flowcell_type="10B", run_cycles=RunCycles(*cycles),
    )
    for k, sample_id in enumerate(sample_ids, start=1):
        run.add_sample(Sample(id=f"s{k}", sample_id=sample_id, lanes=[1]))
    ctx.run_repo.save(run)


def _stored(ctx):
    return ctx.run_repo.get_by_id(RUN)


def _settings(sample):
    return (sample.index1_cycles, sample.index2_cycles,
            sample.read1_override_pattern, sample.read2_override_pattern)


# --- spec §2: a new kit replaces the old kit's settings ---------------------

UMI_PAIRS = [("ACGTACGTAC", "TTGGCCAATT"), ("TGCATGCATG", "AACCTTGGAA")]
PLAIN_PAIRS = [("CATGCATGCA", "GACTGACTGA"), ("ATCGATCGAT", "CTAGCTAGCT")]
SINGLE_I7 = ["CTGACTGACT", "TCAGTCAGTC"]


def _umi_kit(ctx):
    return _pair_kit(
        ctx, "UmiKit", UMI_PAIRS, default_index1_cycles=8, default_index2_cycles=8,
        default_read1_override="U8Y*", default_read2_override="U8Y*",
    )


def _single_kit(ctx):
    kit = IndexKit(
        name="SingleKit", version="1", index_mode=IndexMode.SINGLE,
        i7_indexes=[
            Index(name=f"A{k}", sequence=seq, index_type=IndexType.I7)
            for k, seq in enumerate(SINGLE_I7)
        ],
    )
    ctx.index_kit_repo.save(kit)
    return kit


def _combo_kit(ctx, name, i7s, i5s, **defaults):
    """Save a combinatorial kit; its i7s and i5s are named A0, A1, ..."""
    kit = IndexKit(
        name=name, version="1", index_mode=IndexMode.COMBINATORIAL,
        i7_indexes=[Index(name=f"A{k}", sequence=s, index_type=IndexType.I7) for k, s in enumerate(i7s)],
        i5_indexes=[Index(name=f"A{k}", sequence=s, index_type=IndexType.I5) for k, s in enumerate(i5s)],
        **defaults,
    )
    ctx.index_kit_repo.save(kit)
    return kit


def _new_kit(ctx, kind):
    """The kit assigned second, with no defaults: (slot, kit, the
    OverrideCycles its samples must end with on a 151+10+10+151 run)."""
    if kind == "plain-pair":
        return "pair", _pair_kit(ctx, "PlainKit", PLAIN_PAIRS), "Y151;I10;I10;Y151"
    return "i7", _single_kit(ctx), "Y151;I10;N10;Y151"


def _entry_id(kit, slot, k):
    return f"{kit.name}_P{k}" if slot == "pair" else f"{kit.name}_{slot}_A{k}"


def _assign(client, route, slot, kit):
    """Give s1 and s2 the kit's first two indexes through ``route``: "one"
    (drop on one row), "selected" (drop on ticked rows) or "drop" (a
    multi-index drop)."""
    if route == "drop":
        entries = [{"id": _entry_id(kit, slot, k), "type": slot, "kit_id": kit.kit_id} for k in range(2)]
        resp = client.post(f"/runs/{RUN}/samples/assign-indexes-bulk", data={
            "start_sample_id": "s1", "indexes_json": json.dumps(entries),
            "target_sample_ids": json.dumps(["s1", "s2"]),
        }, headers=ORIGIN)
        assert resp.status_code == 200, resp.text[:300]
        return
    for k, sid in enumerate(["s1", "s2"]):
        data = {"kit_id": kit.kit_id}
        if slot == "pair":
            data["index_pair_id"] = _entry_id(kit, slot, k)
        else:
            data.update(index_id=_entry_id(kit, slot, k), index_type=slot)
        if route == "one":
            url = f"/runs/{RUN}/samples/{sid}/assign-index"
        else:
            url = f"/runs/{RUN}/samples/assign-index-to-selected"
            data["sample_ids"] = json.dumps([sid])
        resp = client.post(url, data=data, headers=ORIGIN)
        assert resp.status_code == 200, resp.text[:300]


class TestANewKitReplacesTheOldKitsSettings:
    """A UMI kit's 8-cycle indexes and U8Y* reads must not stay on a sample
    that now holds another kit's index (review DI-09 and F1; spec
    2026-10-03 group A1, §2)."""

    @pytest.mark.parametrize("route", ["one", "selected", "drop"])
    @pytest.mark.parametrize("kind", ["plain-pair", "single-i7"])
    def test_the_new_kits_settings_replace_the_old(self, logged_in_client, fresh_app, route, kind):
        _app, ctx, _db = fresh_app
        umi = _umi_kit(ctx)
        slot, new, override_cycles = _new_kit(ctx, kind)
        _run(ctx, ["PAT1", "PAT2"])
        _assign(logged_in_client, "one", "pair", umi)
        assert [s.override_cycles for s in _stored(ctx).samples] == ["U8Y143;I8N2;I8N2;U8Y143"] * 2

        _assign(logged_in_client, route, slot, new)

        for sample in _stored(ctx).samples:
            assert sample.index_kit_name == new.name
            assert _settings(sample) == (None, None, None, None)
            assert sample.override_cycles == override_cycles

    def test_fill_in_order_replaces_settings_left_on_an_empty_sample(self, logged_in_client, fresh_app):
        """Fill in order fills only samples with no index. A sample saved
        before this change can have no index and still hold an old kit's
        settings (an old clear left them); Fill must replace them too."""
        _app, ctx, _db = fresh_app
        plain = _pair_kit(ctx, "PlainKit", PLAIN_PAIRS)
        _run(ctx, ["PAT1", "PAT2"])
        run = _stored(ctx)
        for sample in run.samples:
            sample.index1_cycles = sample.index2_cycles = 8
            sample.read1_override_pattern = sample.read2_override_pattern = "U8Y*"
        ctx.run_repo.save(run)
        plan = build_fill_plan(_stored(ctx), plain)

        resp = logged_in_client.post(f"/runs/{RUN}/index-fill", data={
            "selected_kit": plain.kit_id, "start_id": plan.start.id, "plan": plan.signature(),
        }, headers=ORIGIN)

        assert resp.status_code == 200, resp.text[:300]
        for sample in _stored(ctx).samples:
            assert sample.index_kit_name == "PlainKit"
            assert _settings(sample) == (None, None, None, None)
            assert sample.override_cycles == "Y151;I10;I10;Y151"

    @pytest.mark.parametrize("kind", ["plain-pair", "single-i7"])
    def test_mark_ready_writes_the_new_kits_override_cycles(self, logged_in_client, fresh_app, kind):
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        umi = _umi_kit(ctx)
        slot, new, override_cycles = _new_kit(ctx, kind)
        _run(ctx, ["PAT1", "PAT2"])
        _assign(logged_in_client, "one", "pair", umi)
        _assign(logged_in_client, "drop", slot, new)

        resp = mark_ready(logged_in_client, RUN, ORIGIN)

        assert resp.status_code == 200, resp.text[:400]
        run = _stored(ctx)
        assert run.status.value == "ready", resp.text[:400]
        sheet = run.generated_samplesheet_v2
        assert override_cycles in sheet
        assert "U8Y" not in sheet and "I8N2" not in sheet


COMBO_A_I7 = ["ACGTACGTAC", "TGCATGCATG"]
COMBO_A_I5 = ["TTGGCCAATT", "AACCTTGGAA"]
COMBO_B_I7 = ["CATGCATGCA", "ATCGATCGAT"]
COMBO_B_I5 = ["GACTGACTGA", "CTAGCTAGCT"]


class TestReplacingOneIndexKeepsTheOthersSettings:
    """With an i7 and an i5 assigned separately (a combinatorial kit),
    replacing one takes the new kit's cycles for that one and keeps the
    other's. Each route must pass the slot it assigned: with the wrong slot
    the old 8 cycles stay on the new index, or the other index loses its
    own (plan review F-1; spec 2026-10-03 group A1, §2)."""

    @pytest.mark.parametrize("route", ["one", "selected", "drop"])
    @pytest.mark.parametrize("side,settings,override_cycles", [
        pytest.param("i5", (8, 7, None, None), "Y151;I8N2;I7N3;Y151", id="i5"),
        pytest.param("i7", (7, 8, None, None), "Y151;I7N3;I8N2;Y151", id="i7"),
    ])
    def test_the_other_index_keeps_its_cycles(
        self, logged_in_client, fresh_app, route, side, settings, override_cycles
    ):
        _app, ctx, _db = fresh_app
        umi = _combo_kit(
            ctx, "UmiCombo", COMBO_A_I7, COMBO_A_I5, default_index1_cycles=8,
            default_index2_cycles=8, default_read1_override="U8Y*", default_read2_override="U8Y*",
        )
        short = _combo_kit(
            ctx, "ShortCombo", COMBO_B_I7, COMBO_B_I5, default_index1_cycles=7, default_index2_cycles=7,
        )
        _run(ctx, ["PAT1", "PAT2"])
        _assign(logged_in_client, "one", "i7", umi)
        _assign(logged_in_client, "one", "i5", umi)
        assert [_settings(s) for s in _stored(ctx).samples] == [(8, 8, "U8Y*", "U8Y*")] * 2

        _assign(logged_in_client, route, side, short)

        for sample in _stored(ctx).samples:
            assert _settings(sample) == settings
            assert sample.override_cycles == override_cycles


# --- spec §1: a multi-index drop fills only the rows the page showed --------

DROP_REFUSED = "The sample list changed since this page was loaded. Reload the page and drag again."
OUT_OF_DATE = "This page is out of date. Reload the page and drag again."
DROP_PAIRS = [("AAAAAAAA", "ACACACAC"), ("CCCCCCCC", "AGAGAGAG"),
              ("GGGGGGGG", "CTCTCTCT"), ("TTTTTTTT", "GTGTGTGT")]


def _drop(client, kit, start, count, targets):
    """A multi-index drop of the kit's first ``count`` pairs on ``start``.
    ``targets`` is what the page sends as target_sample_ids: a list (sent
    as JSON), a raw string, or None (not sent)."""
    data = {
        "start_sample_id": start,
        "indexes_json": json.dumps([
            {"id": f"{kit.name}_P{k}", "type": "pair", "kit_id": kit.kit_id} for k in range(count)
        ]),
    }
    if targets is not None:
        data["target_sample_ids"] = targets if isinstance(targets, str) else json.dumps(targets)
    return client.post(f"/runs/{RUN}/samples/assign-indexes-bulk", data=data, headers=ORIGIN)


def _given(ctx):
    """(Sample ID, the name of its i7 or None), in run order."""
    return [(s.sample_id, s.index1_name) for s in _stored(ctx).samples]


def _add_behind_the_page(ctx, sid, sample_id):
    """Another tab adds a sample; it goes at the end of the run."""
    run = _stored(ctx)
    run.add_sample(Sample(id=sid, sample_id=sample_id, lanes=[1]))
    ctx.run_repo.save(run)


class TestMultiIndexDropFillsOnlyTheRowsShown:
    """A multi-index drop names the rows the page showed; the server refuses
    it when the run would now fill other rows, and assigns nothing (review
    DI-02; spec 2026-10-03 group A1, §1)."""

    def test_a_row_deleted_since_the_page_loaded_is_refused(self, logged_in_client, fresh_app):
        """The page shows PAT1-PAT4 and three indexes are dropped on PAT1.
        Another tab deleted PAT2: today PAT3 and PAT4 would get P1 and P2."""
        _app, ctx, _db = fresh_app
        kit = _pair_kit(ctx, "K", DROP_PAIRS)
        _run(ctx, ["PAT1", "PAT2", "PAT3", "PAT4"])
        assert logged_in_client.delete(f"/runs/{RUN}/samples/s2", headers=ORIGIN).status_code == 200
        before = _stored(ctx).to_dict()

        resp = _drop(logged_in_client, kit, "s1", 3, ["s1", "s2", "s3"])

        assert resp.status_code == 409
        assert resp.text == DROP_REFUSED
        assert _stored(ctx).to_dict() == before

    def test_a_row_added_inside_the_drop_is_refused(self, logged_in_client, fresh_app):
        """The page shows PAT1-PAT3 and three indexes are dropped on PAT2:
        it fills PAT2 and PAT3 and leaves one unused. PAT4 was added since,
        a patient the page never showed; today it would get the third."""
        _app, ctx, _db = fresh_app
        kit = _pair_kit(ctx, "K", DROP_PAIRS)
        _run(ctx, ["PAT1", "PAT2", "PAT3"])
        _add_behind_the_page(ctx, "s4", "PAT4")
        before = _stored(ctx).to_dict()

        resp = _drop(logged_in_client, kit, "s2", 3, ["s2", "s3"])

        assert resp.status_code == 409
        assert resp.text == DROP_REFUSED
        assert _stored(ctx).to_dict() == before

    def test_a_row_added_after_the_drop_still_assigns(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        kit = _pair_kit(ctx, "K", DROP_PAIRS)
        _run(ctx, ["PAT1", "PAT2", "PAT3", "PAT4"])
        _add_behind_the_page(ctx, "s5", "PAT5")

        resp = _drop(logged_in_client, kit, "s1", 2, ["s1", "s2"])

        assert resp.status_code == 200, resp.text[:300]
        assert _given(ctx) == [
            ("PAT1", "P0"), ("PAT2", "P1"), ("PAT3", None), ("PAT4", None), ("PAT5", None),
        ]

    def test_an_unchanged_page_assigns_as_today(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        kit = _pair_kit(ctx, "K", DROP_PAIRS)
        _run(ctx, ["PAT1", "PAT2", "PAT3", "PAT4"])

        resp = _drop(logged_in_client, kit, "s2", 3, ["s2", "s3", "s4"])

        assert resp.status_code == 200, resp.text[:300]
        assert _given(ctx) == [("PAT1", None), ("PAT2", "P0"), ("PAT3", "P1"), ("PAT4", "P2")]

    def test_a_confirmed_drop_past_the_last_row_still_assigns(self, logged_in_client, fresh_app):
        """The page shows PAT1-PAT3 and three indexes are dropped on PAT2;
        the lab confirmed that the third will not be used, so the page sends
        two rows for three indexes. Nothing changed: assigned as today
        (plan review F-2)."""
        _app, ctx, _db = fresh_app
        kit = _pair_kit(ctx, "K", DROP_PAIRS)
        _run(ctx, ["PAT1", "PAT2", "PAT3"])

        resp = _drop(logged_in_client, kit, "s2", 3, ["s2", "s3"])

        assert resp.status_code == 200, resp.text[:300]
        assert _given(ctx) == [("PAT1", None), ("PAT2", "P0"), ("PAT3", "P1")]

    def test_rows_in_another_order_are_refused(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        kit = _pair_kit(ctx, "K", DROP_PAIRS)
        _run(ctx, ["PAT1", "PAT2", "PAT3"])
        before = _stored(ctx).to_dict()

        resp = _drop(logged_in_client, kit, "s1", 2, ["s2", "s1"])

        assert resp.status_code == 409
        assert resp.text == DROP_REFUSED
        assert _stored(ctx).to_dict() == before

    @pytest.mark.parametrize("targets", [
        pytest.param(None, id="missing"),
        pytest.param("not json", id="not-json"),
        pytest.param('{"s1": 1}', id="object"),
        pytest.param("[1, 2]", id="numbers"),
    ])
    def test_without_the_rows_is_400(self, logged_in_client, fresh_app, targets):
        _app, ctx, _db = fresh_app
        kit = _pair_kit(ctx, "K", DROP_PAIRS)
        _run(ctx, ["PAT1", "PAT2"])
        before = _stored(ctx).to_dict()

        resp = _drop(logged_in_client, kit, "s1", 2, targets)

        assert resp.status_code == 400
        assert resp.text == OUT_OF_DATE
        assert _stored(ctx).to_dict() == before
