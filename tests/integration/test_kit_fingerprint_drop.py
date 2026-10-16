"""A drop gives a sample an index only from the kit the page showed (index
mix-up audit #6, 2026-10-14; the user's choice "Drop + sync").

A drop sent the kit's name and version and the index's id, and the server
took whatever that kit held now: a kit changed under the same name and
version since the page was loaded gave the sample sequences its chip never
showed. Each chip now carries its kit's fingerprint, every drop sends it,
and a drop whose fingerprint is not the stored kit's -- or that sends none
-- is refused and saves nothing.
"""

import json
import re
from html import unescape

import pytest

from seqsetup.models.index import Index, IndexKit, IndexMode, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun
from .conftest import hold_edit_lock

ORIGIN = {"Origin": "http://testserver"}
RUN_ID = "kit-fp-run"
CHANGED = "The index kit changed since this page was loaded. Nothing was assigned. Reload the page."


def _pair_kit(ctx, i7="ATTACTCG"):
    kit = IndexKit(name="FpKit", version="1.0", index_mode=IndexMode.UNIQUE_DUAL, index_pairs=[
        IndexPair(id=f"FpKit_P{k}", name=f"P{k}",
                  index1=Index(f"P{k}", seq, IndexType.I7),
                  index2=Index(f"P{k}", i5, IndexType.I5))
        for k, (seq, i5) in enumerate([(i7, "TATAGCCT"), ("TCCGGAGA", "ATAGAGGC")])
    ])
    ctx.index_kit_repo.save(kit)
    return kit


def _combo_kit(ctx, i7="ATTACTCG"):
    kit = IndexKit(name="FpCombo", version="1.0", index_mode=IndexMode.COMBINATORIAL,
                   i7_indexes=[Index("A1", i7, IndexType.I7)],
                   i5_indexes=[Index("B1", "TATAGCCT", IndexType.I5)])
    ctx.index_kit_repo.save(kit)
    return kit


def _run(ctx):
    run = SequencingRun(
        id=RUN_ID, run_name="Kit fingerprint run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=RunStatus.DRAFT,
    )
    for k in (1, 2):
        run.add_sample(Sample(id=f"s{k}", sample_id=f"S{k}", lanes=[1]))
    ctx.run_repo.save(run)
    hold_edit_lock(ctx, RUN_ID)


def _sample(ctx, sid):
    return ctx.run_repo.get_by_id(RUN_ID).get_sample(sid)


# The rows the drop lands on, as the page shows them: _run gives S1 and S2
# no index, and these drops are the first thing that touches them (F8).
SHOWN_ONE = json.dumps([["", ""]])
SHOWN_TWO = json.dumps([["", ""], ["", ""]])


def _one(client, fingerprint, **index):
    data = {"kit_id": index.pop("kit_id"), "target_indexes": SHOWN_ONE, **index}
    if fingerprint is not None:
        data["kit_fingerprint"] = fingerprint
    return client.post(f"/runs/{RUN_ID}/samples/s1/assign-index", data=data, headers=ORIGIN)


def _selected(client, fingerprint, **index):
    data = {"sample_ids": json.dumps(["s1", "s2"]), "kit_id": index.pop("kit_id"),
            "target_indexes": SHOWN_TWO, **index}
    if fingerprint is not None:
        data["kit_fingerprint"] = fingerprint
    return client.post(f"/runs/{RUN_ID}/samples/assign-index-to-selected", data=data,
                       headers=ORIGIN)


def _bulk(client, fingerprint, kit_id):
    entries = [{"id": f"FpKit_P{k}", "type": "pair", "kit_id": kit_id} for k in (0, 1)]
    if fingerprint is not None:
        for entry in entries:
            entry["kit_fingerprint"] = fingerprint
    return client.post(f"/runs/{RUN_ID}/samples/assign-indexes-bulk", data={
        "start_sample_id": "s1", "indexes_json": json.dumps(entries),
        "target_sample_ids": json.dumps(["s1", "s2"]),
        "target_indexes": json.dumps([["", ""], ["", ""]]),
    }, headers=ORIGIN)


PAIR = {"index_pair_id": "FpKit_P0", "kit_id": "FpKit:1.0"}
I7 = {"index_id": "FpCombo_i7_A1", "index_type": "i7", "kit_id": "FpCombo:1.0"}


class TestADropWithTheShownKitIsSaved:
    """The fingerprint the page showed is the stored kit's: as before."""

    def test_one_pair(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)
        kit = _pair_kit(ctx)

        r = _one(logged_in_client, kit.fingerprint(), **PAIR)

        assert r.status_code == 200, r.text[:300]
        assert _sample(ctx, "s1").index1_sequence == "ATTACTCG"

    def test_one_i7(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)
        kit = _combo_kit(ctx)

        r = _one(logged_in_client, kit.fingerprint(), **I7)

        assert r.status_code == 200, r.text[:300]
        assert _sample(ctx, "s1").index1_sequence == "ATTACTCG"

    def test_onto_the_ticked_samples(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)
        kit = _pair_kit(ctx)

        r = _selected(logged_in_client, kit.fingerprint(), **PAIR)

        assert r.status_code == 200, r.text[:300]
        assert [_sample(ctx, s).index1_sequence for s in ("s1", "s2")] == ["ATTACTCG"] * 2

    def test_several_at_once(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)
        kit = _pair_kit(ctx)

        r = _bulk(logged_in_client, kit.fingerprint(), "FpKit:1.0")

        assert r.status_code == 200, r.text[:300]
        assert [_sample(ctx, s).index1_sequence for s in ("s1", "s2")] == ["ATTACTCG", "TCCGGAGA"]


def _changed_since_the_page(ctx, make):
    """The fingerprint the page showed, then the kit changed under the same
    name and version."""
    shown = make(ctx).fingerprint()
    make(ctx, i7="GGGGGGGG")
    return shown


class TestADropFromAnOlderKitIsRefused:
    """A changed kit, or no fingerprint at all, saves nothing."""

    @pytest.mark.parametrize("sent", ["changed", "none", "empty"])
    def test_one_pair(self, logged_in_client, fresh_app, sent):
        _app, ctx, _db = fresh_app
        _run(ctx)
        shown = _changed_since_the_page(ctx, _pair_kit)
        fingerprint = {"changed": shown, "none": None, "empty": ""}[sent]

        r = _one(logged_in_client, fingerprint, **PAIR)

        assert r.status_code == 409
        assert r.text == CHANGED
        assert _sample(ctx, "s1").index_pair is None

    def test_one_i7(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)
        shown = _changed_since_the_page(ctx, _combo_kit)

        r = _one(logged_in_client, shown, **I7)

        assert r.status_code == 409
        assert r.text == CHANGED
        assert _sample(ctx, "s1").index1 is None

    @pytest.mark.parametrize("sent", ["changed", "none"])
    def test_onto_the_ticked_samples(self, logged_in_client, fresh_app, sent):
        _app, ctx, _db = fresh_app
        _run(ctx)
        shown = _changed_since_the_page(ctx, _pair_kit)

        r = _selected(logged_in_client, shown if sent == "changed" else None, **PAIR)

        assert r.status_code == 409
        assert r.text == CHANGED
        assert [_sample(ctx, s).index_pair for s in ("s1", "s2")] == [None, None]

    @pytest.mark.parametrize("sent", ["changed", "none"])
    def test_several_at_once(self, logged_in_client, fresh_app, sent):
        _app, ctx, _db = fresh_app
        _run(ctx)
        shown = _changed_since_the_page(ctx, _pair_kit)

        r = _bulk(logged_in_client, shown if sent == "changed" else None, "FpKit:1.0")

        assert r.status_code == 409
        assert r.text == CHANGED
        assert [_sample(ctx, s).index_pair for s in ("s1", "s2")] == [None, None]


class TestThePageShowsTheFingerprint:
    """Each chip carries its kit's fingerprint for the drop to send."""

    @pytest.mark.parametrize("where", ["run page", "kit picker"])
    def test_every_pair_chip(self, logged_in_client, fresh_app, where):
        _app, ctx, _db = fresh_app
        _run(ctx)
        kit = _pair_kit(ctx)

        page = unescape((logged_in_client.get(f"/runs/{RUN_ID}") if where == "run page" else
                         logged_in_client.get("/indexes/kit-content",
                                              params={"selected_kit": kit.kit_id})).text)

        chips = re.findall(r'<div class="draggable-index[^>]*>', page)
        assert len(chips) == 2
        assert all(f'data-kit-fingerprint="{kit.fingerprint()}"' in chip for chip in chips)

    @pytest.mark.parametrize("where", ["run page", "kit picker"])
    def test_every_single_index_chip(self, logged_in_client, fresh_app, where):
        _app, ctx, _db = fresh_app
        _run(ctx)
        kit = _combo_kit(ctx)

        page = unescape((logged_in_client.get(f"/runs/{RUN_ID}") if where == "run page" else
                         logged_in_client.get("/indexes/kit-content",
                                              params={"selected_kit": kit.kit_id})).text)

        chips = re.findall(r'<div class="draggable-index[^>]*>', page)
        assert len(chips) == 2
        assert all(f'data-kit-fingerprint="{kit.fingerprint()}"' in chip for chip in chips)
