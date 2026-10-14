"""Several indexes dragged at once go to the rows in the order the index
panel shows them, whatever order they were clicked in (index mix-up audit,
2026-10-14; the user's choice "Panel order").

The page sent them in click order. Click A05, then shift-click A01, and the
drop sent A05, A01, A02, A03, A04: the first sample got A05 and the second
A01. Every index was still unique, so no check could see the swap. The
server now puts the indexes in the kit's own order before it fills the rows.
"""

import json

from seqsetup.models.index import Index, IndexKit, IndexMode, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, SequencingRun

from .conftest import hold_edit_lock

ORIGIN = {"Origin": "http://testserver"}
I7 = ["AACCGGTT", "CCGGTTAA", "GGTTAACC", "TTAACCGG", "ACACGTGT"]
I5 = ["TGTGCACA", "GTGTACAC", "CACAGTGT", "ATATCGCG", "CGCGATAT"]


def _dual_kit(name="Order-Kit"):
    return IndexKit(name=name, version="1.0", index_mode=IndexMode.UNIQUE_DUAL, index_pairs=[
        IndexPair(id=f"{name}_A0{k + 1}", name=f"A0{k + 1}",
                  index1=Index(name=f"A0{k + 1}", sequence=I7[k], index_type=IndexType.I7),
                  index2=Index(name=f"A0{k + 1}", sequence=I5[k], index_type=IndexType.I5))
        for k in range(5)])


def _combinatorial_kit(name="Order-Comb"):
    return IndexKit(name=name, version="1.0", index_mode=IndexMode.COMBINATORIAL,
                    i7_indexes=[Index(name=f"N70{k + 1}", sequence=I7[k], index_type=IndexType.I7)
                                for k in range(5)],
                    i5_indexes=[Index(name=f"S50{k + 1}", sequence=I5[k], index_type=IndexType.I5)
                                for k in range(5)])


def _pair(kit, n):
    return {"id": f"{kit.name}_A0{n}", "type": "pair", "kit_id": kit.kit_id}


def _i7(kit, n):
    return {"id": f"{kit.name}_i7_N70{n}", "type": "i7", "kit_id": kit.kit_id}


def _i5(kit, n):
    return {"id": f"{kit.name}_i5_S50{n}", "type": "i5", "kit_id": kit.kit_id}


def _run(ctx, *kits, rows=5):
    for kit in kits:
        ctx.index_kit_repo.save(kit)
    run = SequencingRun(id="panel-order", run_name="panel-order",
                        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
                        run_cycles=RunCycles(151, 151, 8, 8))
    for n in range(1, rows + 1):
        run.add_sample(Sample(id=f"panel-order-s{n}", sample_id=f"P{n}", lanes=[1]))
    ctx.run_repo.save(run)
    hold_edit_lock(ctx, run.id)
    return ctx.run_repo.get_by_id(run.id)


def _drop(client, run, entries, start=0):
    rows = run.samples[start:start + len(entries)]
    return client.post(f"/runs/{run.id}/samples/assign-indexes-bulk", data={
        "start_sample_id": rows[0].id,
        "indexes_json": json.dumps(entries),
        "target_sample_ids": json.dumps([s.id for s in rows]),
        "target_indexes": json.dumps([["", ""] for _ in rows]),
    }, headers=ORIGIN)


def _stored(ctx, run_id):
    return [(s.sample_id, s.index1_sequence, s.index2_sequence)
            for s in ctx.run_repo.get_by_id(run_id).samples]


class TestTheRowsAreFilledInPanelOrder:

    def test_a_shift_click_made_backwards(self, logged_in_client, fresh_app):
        """Click A05, then shift-click A01."""
        _app, ctx, _db = fresh_app
        kit = _dual_kit()
        run = _run(ctx, kit)

        resp = _drop(logged_in_client, run, [_pair(kit, n) for n in (5, 1, 2, 3, 4)])

        assert resp.status_code == 200
        assert _stored(ctx, run.id) == [(f"P{k + 1}", I7[k], I5[k]) for k in range(5)]

    def test_chips_ctrl_clicked_out_of_order(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        kit = _dual_kit()
        run = _run(ctx, kit)

        resp = _drop(logged_in_client, run, [_pair(kit, n) for n in (3, 1, 2)])

        assert resp.status_code == 200
        assert _stored(ctx, run.id)[:3] == [(f"P{k + 1}", I7[k], I5[k]) for k in range(3)]

    def test_single_indexes_too(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        kit = _combinatorial_kit()
        run = _run(ctx, kit)

        resp = _drop(logged_in_client, run, [_i7(kit, n) for n in (4, 2, 1, 3)])

        assert resp.status_code == 200
        assert [i7 for _id, i7, _i5 in _stored(ctx, run.id)[:4]] == I7[:4]

    def test_the_indexes_left_over_are_the_last_in_the_panel(self, logged_in_client, fresh_app):
        """Five indexes dropped on the last two rows: those two rows get the
        panel's first two, and A03 to A05 are the ones not used."""
        _app, ctx, _db = fresh_app
        kit = _dual_kit()
        run = _run(ctx, kit)
        entries = [_pair(kit, n) for n in (5, 1, 2, 3, 4)]
        rows = run.samples[3:]

        resp = logged_in_client.post(f"/runs/{run.id}/samples/assign-indexes-bulk", data={
            "start_sample_id": rows[0].id,
            "indexes_json": json.dumps(entries),
            "target_sample_ids": json.dumps([s.id for s in rows]),
            "target_indexes": json.dumps([["", ""] for _ in rows]),
        }, headers=ORIGIN)

        assert resp.status_code == 200
        assert _stored(ctx, run.id)[3:] == [("P4", I7[0], I5[0]), ("P5", I7[1], I5[1])]


class TestADropWithNoOnePanelOrderIsRefused:
    """Indexes of two kinds, or from two kits, have no one order to fill
    the rows in. The page cannot send such a drop; the server refuses it
    and assigns nothing."""

    def test_i7_and_i5_at_once(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        kit = _combinatorial_kit()
        run = _run(ctx, kit)

        resp = _drop(logged_in_client, run, [_i7(kit, 1), _i5(kit, 1)])

        assert resp.status_code == 400
        assert "one kind" in resp.text
        assert all(i7 is None and i5 is None for _id, i7, i5 in _stored(ctx, run.id))

    def test_two_kits_at_once(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        first, second = _dual_kit("Order-Kit"), _dual_kit("Other-Kit")
        run = _run(ctx, first, second)

        resp = _drop(logged_in_client, run, [_pair(first, 1), _pair(second, 2)])

        assert resp.status_code == 400
        assert "one kit" in resp.text
        assert all(i7 is None and i5 is None for _id, i7, i5 in _stored(ctx, run.id))
