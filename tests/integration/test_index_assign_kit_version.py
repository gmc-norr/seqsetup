"""Drag/drop and click assign take an index from the kit version it was
shown in, never from another version of the same kit.

Index ids are ``{kit name}_{index name}``: two versions of one kit share
them. The assign routes used to find an id in whichever kit document the
database returned first, so dragging a chip from "Kit v2.0" could give the
sample "Kit v1.0"'s sequences. Each chip now sends its kit's ``kit_id``,
and the routes look the index up in that kit only. Without a ``kit_id``
(a page loaded before this fix) the id must belong to exactly one kit;
if several versions hold it the route refuses with 409 and saves nothing.
"""

import json
import re
from html import unescape as html_unescape

import pytest

from seqsetup.models.index import Index, IndexKit, IndexMode, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun

ORIGIN = {"Origin": "http://testserver"}
RUN_ID = "kit-version-run"

# Same index names in both versions, different sequences.
V1_I7 = ["AAAAAAAA", "CCCCCCCC"]
V1_I5 = ["AGAGAGAG", "CTCTCTCT"]
V2_I7 = ["GGGGGGGG", "TTTTTTTT"]
V2_I5 = ["GAGAGAGA", "TCTCTCTC"]


def _dual_kit(ctx, version, i7, i5, name="VerKit"):
    kit = IndexKit(
        name=name, version=version, index_mode=IndexMode.UNIQUE_DUAL,
        index_pairs=[
            IndexPair(
                id=f"{name}_UDP{k}", name=f"UDP{k}",
                index1=Index(name=f"UDP{k}", sequence=i7[k], index_type=IndexType.I7),
                index2=Index(name=f"UDP{k}", sequence=i5[k], index_type=IndexType.I5),
            )
            for k in range(len(i7))
        ],
    )
    ctx.index_kit_repo.save(kit)
    return kit


def _combo_kit(ctx, version, i7_seq):
    kit = IndexKit(
        name="ComboKit", version=version, index_mode=IndexMode.COMBINATORIAL,
        i7_indexes=[Index(name="A1", sequence=i7_seq, index_type=IndexType.I7)],
        i5_indexes=[Index(name="B1", sequence="ACACACAC", index_type=IndexType.I5)],
    )
    ctx.index_kit_repo.save(kit)
    return kit


def _two_versions(ctx):
    """v1 saved first, so a lookup that ignores the version finds v1."""
    return _dual_kit(ctx, "1.0", V1_I7, V1_I5), _dual_kit(ctx, "2.0", V2_I7, V2_I5)


def _run(ctx):
    run = SequencingRun(
        id=RUN_ID, run_name="Kit version run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=RunStatus.DRAFT,
    )
    run.add_sample(Sample(id="s1", sample_id="S1", lanes=[1]))
    run.add_sample(Sample(id="s2", sample_id="S2", lanes=[1]))
    ctx.run_repo.save(run)
    return RUN_ID


def _sample(ctx, sid):
    return ctx.run_repo.get_by_id(RUN_ID).get_sample(sid)


def _stored(ctx):
    return ctx.run_repo.get_by_id(RUN_ID).to_dict()


class TestAssignOneIndex:
    """POST /runs/{id}/samples/{sid}/assign-index (drag, drop or keyboard)."""

    @pytest.mark.parametrize("which", [0, 1])
    def test_pair_comes_from_the_given_kit_version(self, logged_in_client, fresh_app, which):
        _app, ctx, _db = fresh_app
        _run(ctx)
        kits = _two_versions(ctx)
        i7s, i5s = (V1_I7, V2_I7), (V1_I5, V2_I5)

        resp = logged_in_client.post(
            f"/runs/{RUN_ID}/samples/s1/assign-index",
            data={"index_pair_id": "VerKit_UDP0", "kit_id": kits[which].kit_id},
            headers=ORIGIN,
        )

        assert resp.status_code == 200, resp.text[:300]
        sample = _sample(ctx, "s1")
        assert sample.index1_sequence == i7s[which][0]
        assert sample.index2_sequence == i5s[which][0]

    def test_single_i7_comes_from_the_given_kit_version(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)
        _combo_kit(ctx, "1.0", "AAAAAAAA")
        v2 = _combo_kit(ctx, "2.0", "GGGGGGGG")

        resp = logged_in_client.post(
            f"/runs/{RUN_ID}/samples/s1/assign-index",
            data={"index_id": "ComboKit_i7_A1", "index_type": "i7", "kit_id": v2.kit_id},
            headers=ORIGIN,
        )

        assert resp.status_code == 200, resp.text[:300]
        assert _sample(ctx, "s1").index1_sequence == "GGGGGGGG"

    def test_no_kit_id_and_two_versions_hold_the_pair_refuses(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)
        _two_versions(ctx)
        before = _stored(ctx)

        resp = logged_in_client.post(
            f"/runs/{RUN_ID}/samples/s1/assign-index",
            data={"index_pair_id": "VerKit_UDP0"},
            headers=ORIGIN,
        )

        assert resp.status_code == 409
        assert "more than one version" in resp.text
        assert _stored(ctx) == before

    def test_no_kit_id_and_two_versions_hold_the_single_index_refuses(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)
        _combo_kit(ctx, "1.0", "AAAAAAAA")
        _combo_kit(ctx, "2.0", "GGGGGGGG")
        before = _stored(ctx)

        resp = logged_in_client.post(
            f"/runs/{RUN_ID}/samples/s1/assign-index",
            data={"index_id": "ComboKit_i7_A1", "index_type": "i7"},
            headers=ORIGIN,
        )

        assert resp.status_code == 409
        assert _stored(ctx) == before

    def test_no_kit_id_and_one_kit_holds_the_pair_still_assigns(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)
        _dual_kit(ctx, "1.0", V1_I7, V1_I5)

        resp = logged_in_client.post(
            f"/runs/{RUN_ID}/samples/s1/assign-index",
            data={"index_pair_id": "VerKit_UDP0"},
            headers=ORIGIN,
        )

        assert resp.status_code == 200, resp.text[:300]
        assert _sample(ctx, "s1").index1_sequence == V1_I7[0]

    def test_unknown_kit_id_is_404_and_saves_nothing(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)
        _two_versions(ctx)
        before = _stored(ctx)

        resp = logged_in_client.post(
            f"/runs/{RUN_ID}/samples/s1/assign-index",
            data={"index_pair_id": "VerKit_UDP0", "kit_id": "VerKit:9.9"},
            headers=ORIGIN,
        )

        assert resp.status_code == 404
        assert _stored(ctx) == before

    def test_kit_without_that_pair_is_404_and_saves_nothing(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)
        _two_versions(ctx)
        other = _dual_kit(ctx, "1.0", V1_I7, V1_I5, name="OtherKit")
        before = _stored(ctx)

        resp = logged_in_client.post(
            f"/runs/{RUN_ID}/samples/s1/assign-index",
            data={"index_pair_id": "VerKit_UDP0", "kit_id": other.kit_id},
            headers=ORIGIN,
        )

        assert resp.status_code == 404
        assert _stored(ctx) == before


class TestAssignToSelected:
    """POST /runs/{id}/samples/assign-index-to-selected (drop on ticked rows)."""

    def test_pair_comes_from_the_given_kit_version(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)
        _v1, v2 = _two_versions(ctx)

        resp = logged_in_client.post(
            f"/runs/{RUN_ID}/samples/assign-index-to-selected",
            data={"sample_ids": json.dumps(["s1"]), "index_pair_id": "VerKit_UDP1",
                  "kit_id": v2.kit_id},
            headers=ORIGIN,
        )

        assert resp.status_code == 200, resp.text[:300]
        assert _sample(ctx, "s1").index1_sequence == V2_I7[1]

    def test_no_kit_id_and_two_versions_hold_the_pair_refuses(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)
        _two_versions(ctx)
        before = _stored(ctx)

        resp = logged_in_client.post(
            f"/runs/{RUN_ID}/samples/assign-index-to-selected",
            data={"sample_ids": json.dumps(["s1"]), "index_pair_id": "VerKit_UDP1"},
            headers=ORIGIN,
        )

        assert resp.status_code == 409
        assert _stored(ctx) == before

    def test_unknown_index_type_is_400_and_saves_nothing(self, logged_in_client, fresh_app):
        """With index_id, index_type must be i7 or i5. Anything else used to
        find the index and then set the kit name and kit defaults on the
        samples without giving them an index."""
        _app, ctx, _db = fresh_app
        _run(ctx)
        combo = _combo_kit(ctx, "1.0", "AAAAAAAA")
        before = _stored(ctx)

        resp = logged_in_client.post(
            f"/runs/{RUN_ID}/samples/assign-index-to-selected",
            data={"sample_ids": json.dumps(["s1"]), "index_id": "ComboKit_i7_A1",
                  "index_type": "bogus", "kit_id": combo.kit_id},
            headers=ORIGIN,
        )

        assert resp.status_code == 400
        assert _stored(ctx) == before


class TestAssignSeveralInOrder:
    """POST /runs/{id}/samples/assign-indexes-bulk (multi-index drop)."""

    def _post(self, client, entries):
        return client.post(
            f"/runs/{RUN_ID}/samples/assign-indexes-bulk",
            data={"start_sample_id": "s1", "indexes_json": json.dumps(entries)},
            headers=ORIGIN,
        )

    def test_each_entry_comes_from_its_own_kit_version(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)
        v1, v2 = _two_versions(ctx)

        resp = self._post(logged_in_client, [
            {"id": "VerKit_UDP0", "type": "pair", "kit_id": v2.kit_id},
            {"id": "VerKit_UDP1", "type": "pair", "kit_id": v1.kit_id},
        ])

        assert resp.status_code == 200, resp.text[:300]
        assert _sample(ctx, "s1").index1_sequence == V2_I7[0]
        assert _sample(ctx, "s2").index1_sequence == V1_I7[1]

    def test_no_kit_id_and_two_versions_hold_the_pair_refuses(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)
        _two_versions(ctx)
        before = _stored(ctx)

        resp = self._post(logged_in_client, [{"id": "VerKit_UDP0", "type": "pair"}])

        assert resp.status_code == 409
        assert _stored(ctx) == before

    def test_non_string_kit_id_is_400_and_saves_nothing(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)
        _two_versions(ctx)
        before = _stored(ctx)

        resp = self._post(logged_in_client, [{"id": "VerKit_UDP0", "type": "pair", "kit_id": 5}])

        assert resp.status_code == 400
        assert _stored(ctx) == before


# Opening tag of every draggable index chip, wherever it is rendered.
_CHIP_TAG_RE = re.compile(r'<div class="draggable-index-compact[^>]*>')


def _chip_kit_ids(html):
    """The data-kit-id of every chip in ``html`` (None where it is missing)."""
    ids = []
    for tag in _CHIP_TAG_RE.findall(html):
        match = re.search(r'data-kit-id="([^"]*)"', tag)
        ids.append(html_unescape(match.group(1)) if match else None)
    return ids


class TestChipsNameTheirKit:
    """Every index chip carries the kit_id of the kit it was drawn from,
    so app.js can send it with the assign request."""

    def test_run_page_chips_carry_the_shown_kit(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)
        v1, _v2 = _two_versions(ctx)

        resp = logged_in_client.get(f"/runs/{RUN_ID}")

        assert resp.status_code == 200
        assert _chip_kit_ids(resp.text) == [v1.kit_id, v1.kit_id]

    def test_kit_picker_content_chips_carry_the_picked_kit(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _v1, v2 = _two_versions(ctx)

        resp = logged_in_client.get("/indexes/kit-content", params={"selected_kit": v2.kit_id})

        assert resp.status_code == 200
        assert _chip_kit_ids(resp.text) == [v2.kit_id, v2.kit_id]

    def test_single_index_chips_carry_their_kit(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)
        combo = _combo_kit(ctx, "2.0", "GGGGGGGG")

        page = logged_in_client.get(f"/runs/{RUN_ID}")
        picked = logged_in_client.get("/indexes/kit-content", params={"selected_kit": combo.kit_id})

        assert _chip_kit_ids(page.text) == [combo.kit_id, combo.kit_id]
        assert _chip_kit_ids(picked.text) == [combo.kit_id, combo.kit_id]
