"""The kit-swap refusal shows each kit as "name version", and one clashing
kit per group.

The refusal gathered the clashing samples by ``kit.name``. Two versions of one
kit name read Read 1 and Read 2 their own way, so a bulk assignment that took
indexes from both showed the FIRST version's patterns next to every sample's
ID -- naming a read pattern that is not the one the other version's samples
would have got. The refusal itself always held: 400, nothing saved.
"""

import json

import pytest

from seqsetup.models.index import Index, IndexKit, IndexMode, IndexType

from .test_group_a1 import COMBO_A_I5, COMBO_A_I7, COMBO_B_I5, COMBO_B_I7, ORIGIN, RUN, _run, _stored
from .conftest import hold_edit_lock

UMI = {"default_index1_cycles": 8, "default_index2_cycles": 8,
       "default_read1_override": "U8Y*", "default_read2_override": "U8Y*"}


def _combo(ctx, name, version, i7s, i5s, **defaults):
    kit = IndexKit(
        name=name, version=version, index_mode=IndexMode.COMBINATORIAL,
        i7_indexes=[Index(name=f"A{k}", sequence=s, index_type=IndexType.I7)
                    for k, s in enumerate(i7s)],
        i5_indexes=[Index(name=f"A{k}", sequence=s, index_type=IndexType.I5)
                    for k, s in enumerate(i5s)],
        **defaults,
    )
    ctx.index_kit_repo.save(kit)
    return kit


def _give_umi_i7(ctx, umi):
    """PAT1 and PAT2 each keep a UMI i7, so any plainer i5 clashes."""
    run = _stored(ctx)
    for k, sample in enumerate(run.samples):
        sample.assign_index1(Index(name=f"A{k}", sequence=umi.i7_indexes[k].sequence,
                                   index_type=IndexType.I7))
        sample.read1_override_pattern = "U8Y*"
        sample.read2_override_pattern = "U8Y*"
    ctx.run_repo.save(run)
    hold_edit_lock(ctx, run.id)


def _drop_i5s(client, ctx, entries):
    """A multi-index drop of two i5 indexes on PAT1, sending the indexes the
    rows hold now, as the page would."""
    return client.post(f"/runs/{RUN}/samples/assign-indexes-bulk", data={
        "start_sample_id": "s1", "indexes_json": json.dumps(entries),
        "target_sample_ids": json.dumps(["s1", "s2"]),
        "target_indexes": json.dumps([[s.index1_sequence or "", s.index2_sequence or ""]
                                      for s in _stored(ctx).samples]),
        "index_type": "i5",
    }, headers=ORIGIN)


@pytest.fixture
def two_versions(fresh_app, logged_in_client):
    """PAT1 and PAT2 keep a UMI i7; two versions of one kit name, each
    reading Read 1 and Read 2 its own way, both plainer than the UMI i7."""
    _app, ctx, _db = fresh_app
    _run(ctx, ["PAT1", "PAT2"])
    umi = _combo(ctx, "UmiCombo", "1", COMBO_A_I7, COMBO_A_I5, **UMI)
    _give_umi_i7(ctx, umi)
    v1 = _combo(ctx, "VerKit", "1", COMBO_B_I7, COMBO_B_I5,
                default_read1_override="Y*", default_read2_override="Y*")
    v2 = _combo(ctx, "VerKit", "2", COMBO_B_I7, COMBO_B_I5, default_index1_cycles=8,
                default_index2_cycles=8, default_read1_override="U6Y*",
                default_read2_override="U6Y*")
    return ctx, v1, v2


def _indexes(ctx):
    return [(s.index1_sequence, s.index2_sequence) for s in _stored(ctx).samples]


class TestTheMessageNamesTheKitVersion:
    def test_one_clashing_kit_is_named_with_its_version(self, logged_in_client, two_versions):
        ctx, v1, _v2 = two_versions
        before = _indexes(ctx)

        resp = _drop_i5s(logged_in_client, ctx, [
            {"id": "VerKit_i5_A0", "type": "i5", "kit_id": v1.kit_id},
            {"id": "VerKit_i5_A1", "type": "i5", "kit_id": v1.kit_id},
        ])

        assert resp.status_code == 400, resp.text[:300]
        assert resp.text == (
            "These samples keep an index from a kit that reads Read 1 and Read 2 differently "
            "from VerKit 1 (Read 1 plain, Read 2 plain). Assign both indexes from one kit, or "
            "clear these samples' indexes first: PAT1, PAT2.")
        assert _indexes(ctx) == before

    def test_a_drop_from_two_versions_is_refused_before_this_check(self, logged_in_client, two_versions):
        """Two kits have no one panel order to fill the rows in (index
        mix-up audit, 2026-10-14), so such a drop is refused first and the
        two-kit message below is reached only by a direct call."""
        ctx, v1, v2 = two_versions
        before = _indexes(ctx)

        resp = _drop_i5s(logged_in_client, ctx, [
            {"id": "VerKit_i5_A0", "type": "i5", "kit_id": v1.kit_id},
            {"id": "VerKit_i5_A1", "type": "i5", "kit_id": v2.kit_id},
        ])

        assert resp.status_code == 400, resp.text[:300]
        assert resp.text == "Drag indexes of one kind from one kit at a time. Nothing was assigned."
        assert _indexes(ctx) == before

    def test_two_versions_of_one_name_are_two_kits(self, two_versions):
        from seqsetup.routes.samples import _kit_swap_refusal
        ctx, v1, v2 = two_versions
        run = _stored(ctx)

        text = _kit_swap_refusal(
            [(run.samples[0], "i5", v1), (run.samples[1], "i5", v2)], run.run_cycles,
        ).body.decode()

        assert text == (
            "These samples keep an index from a kit that reads Read 1 and Read 2 differently "
            "from the kit being assigned. Assign both indexes from one kit, or clear these "
            "samples' indexes first: VerKit 1 (Read 1 plain, Read 2 plain): PAT1; "
            "VerKit 2 (Read 1 U6Y*, Read 2 U6Y*): PAT2.")


class TestTheBannerBudgetIsKept:
    def test_what_to_do_still_comes_before_the_ids_with_two_kits(self):
        """The page's error banner shows the first 300 characters."""
        from seqsetup.models.sample import Sample
        from seqsetup.models.sequencing_run import RunCycles
        from seqsetup.routes.samples import _kit_swap_refusal
        planned = []
        for version in ("1", "2"):
            kit = IndexKit(name="VerKit", version=version, index_mode=IndexMode.COMBINATORIAL,
                           default_read1_override="U8Y*" if version == "2" else "")
            for n in range(12):
                sample = Sample(sample_id=f"Seq25-{version}{n:03d}")
                sample.assign_index1(
                    Index(name="a", sequence="ACGTACGTAC", index_type=IndexType.I7))
                sample.read1_override_pattern = "U6Y*"
                planned.append((sample, "i5", kit))

        text = _kit_swap_refusal(planned, RunCycles(151, 151, 10, 10)).body.decode()

        assert "or clear these samples' indexes first: VerKit 1 " in text[:300]
        assert text.endswith("and 2 more.")
