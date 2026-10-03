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
