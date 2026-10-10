"""Later list slice 1 through the real routes (spec
docs/superpowers/specs/2026-10-10-later-1-design.md)."""

import json

import pytest

from .test_group_a1 import (
    COMBO_A_I5,
    COMBO_A_I7,
    COMBO_B_I5,
    COMBO_B_I7,
    ORIGIN,
    PLAIN_PAIRS,
    RUN,
    _assign,
    _combo_kit,
    _entry_id,
    _pair_kit,
    _run,
    _settings,
    _stored,
)

# --- spec §2: a kit swap keeps no index from a kit with other read patterns --

UMI = {"default_index1_cycles": 8, "default_index2_cycles": 8,
       "default_read1_override": "U8Y*", "default_read2_override": "U8Y*"}


def _swap(client, route, slot, kit, sids=("s1", "s2")):
    """Give ``sids`` the kit's first indexes in ``slot`` through ``route``,
    in one request; the response."""
    if route == "drop":
        entries = [{"id": _entry_id(kit, slot, k), "type": slot, "kit_id": kit.kit_id}
                   for k in range(len(sids))]
        return client.post(f"/runs/{RUN}/samples/assign-indexes-bulk", data={
            "start_sample_id": sids[0], "indexes_json": json.dumps(entries),
            "target_sample_ids": json.dumps(list(sids)),
        }, headers=ORIGIN)
    data = {"kit_id": kit.kit_id, "index_id": _entry_id(kit, slot, 0), "index_type": slot}
    if route == "one":
        assert len(sids) == 1
        return client.post(f"/runs/{RUN}/samples/{sids[0]}/assign-index", data=data,
                           headers=ORIGIN)
    data["sample_ids"] = json.dumps(list(sids))
    return client.post(f"/runs/{RUN}/samples/assign-index-to-selected", data=data,
                       headers=ORIGIN)


def _refusal(kit, r1, r2, ids):
    return (f"These samples keep an index from a kit that reads Read 1 and Read 2 differently "
            f"from {kit} (Read 1 {r1}, Read 2 {r2}). Assign both indexes from one kit, or clear "
            f"these samples' indexes first: {ids}.")


def _indexes(ctx):
    return [(s.index1_name, s.index2_name, _settings(s)) for s in _stored(ctx).samples]


class TestAKitSwapWithOtherReadPatternsIsRefused:
    """A UMI kit's i7 and i5, assigned one by one: replacing one of them from
    a plain kit would leave the other's UMI reads without their pattern."""

    @pytest.mark.parametrize("route", ["one", "selected", "drop"])
    @pytest.mark.parametrize("slot", ["i5", "i7"])
    def test_the_swap_is_refused_and_nothing_is_saved(
        self, logged_in_client, fresh_app, route, slot
    ):
        _app, ctx, _db = fresh_app
        umi = _combo_kit(ctx, "UmiCombo", COMBO_A_I7, COMBO_A_I5, **UMI)
        plain = _combo_kit(ctx, "PlainCombo", COMBO_B_I7, COMBO_B_I5)
        _run(ctx, ["PAT1", "PAT2"])
        _assign(logged_in_client, "one", "i7", umi)
        _assign(logged_in_client, "one", "i5", umi)
        before = _indexes(ctx)
        sids = ("s1",) if route == "one" else ("s1", "s2")

        resp = _swap(logged_in_client, route, slot, plain, sids)

        assert resp.status_code == 400
        ids = "PAT1" if route == "one" else "PAT1, PAT2"
        assert resp.text == _refusal("PlainCombo", "plain", "plain", ids)
        assert _indexes(ctx) == before

    def test_a_umi_index_onto_a_plain_kits_index_is_refused(self, logged_in_client, fresh_app):
        """A UMI in Read 1 only, as the shipped umi_dual_indexes.yaml: its Read 2
        Y* reads every cycle, so the message calls it plain."""
        _app, ctx, _db = fresh_app
        umi = _combo_kit(ctx, "UmiCombo", COMBO_A_I7, COMBO_A_I5, default_index1_cycles=8,
                         default_index2_cycles=8, default_read1_override="U8Y*",
                         default_read2_override="Y*")
        plain = _combo_kit(ctx, "PlainCombo", COMBO_B_I7, COMBO_B_I5)
        _run(ctx, ["PAT1", "PAT2"])
        _assign(logged_in_client, "one", "i7", plain)
        before = _indexes(ctx)

        resp = _swap(logged_in_client, "selected", "i5", umi)

        assert resp.status_code == 400
        assert resp.text == _refusal("UmiCombo", "U8Y*", "plain", "PAT1, PAT2")
        assert _indexes(ctx) == before

    def test_a_drop_is_refused_whole(self, logged_in_client, fresh_app):
        """Only PAT2 keeps an index; PAT1, which has none, is not filled either."""
        _app, ctx, _db = fresh_app
        umi = _combo_kit(ctx, "UmiCombo", COMBO_A_I7, COMBO_A_I5, **UMI)
        plain = _combo_kit(ctx, "PlainCombo", COMBO_B_I7, COMBO_B_I5)
        _run(ctx, ["PAT1", "PAT2"])
        resp = logged_in_client.post(f"/runs/{RUN}/samples/s2/assign-index", data={
            "kit_id": umi.kit_id, "index_id": _entry_id(umi, "i7", 1), "index_type": "i7",
        }, headers=ORIGIN)
        assert resp.status_code == 200, resp.text[:300]
        before = _indexes(ctx)

        resp = _swap(logged_in_client, "drop", "i5", plain)

        assert resp.status_code == 400
        assert resp.text == _refusal("PlainCombo", "plain", "plain", "PAT2")
        assert _indexes(ctx) == before


class TestOtherSwapsWorkAsToday:

    @pytest.mark.parametrize("route", ["one", "selected", "drop"])
    @pytest.mark.parametrize("first,second", [
        pytest.param({"default_read1_override": "Y*", "default_read2_override": "Y*"}, {},
                     id="Y*-then-none"),
        pytest.param({}, {"default_read1_override": "Y*", "default_read2_override": ""},
                     id="none-then-Y*-and-empty"),
        pytest.param({"default_read1_override": "U8Y*", "default_read2_override": "U8Y*"},
                     {"default_read1_override": "U8Y143", "default_read2_override": "U8Y143"},
                     id="U8Y*-then-U8Y143"),
    ])
    def test_kits_that_read_alike_swap(self, logged_in_client, fresh_app, route, first, second):
        """The patterns are compared as the run reads them: an upload stores
        Y* as none, a synced kit keeps it (review of 91fbe8e)."""
        _app, ctx, _db = fresh_app
        a = _combo_kit(ctx, "KitA", COMBO_A_I7, COMBO_A_I5, **first)
        b = _combo_kit(ctx, "KitB", COMBO_B_I7, COMBO_B_I5, **second)
        _run(ctx, ["PAT1", "PAT2"])
        _assign(logged_in_client, "one", "i7", a)
        _assign(logged_in_client, "one", "i5", a)

        _assign(logged_in_client, route, "i5", b)

        assert [s.index2_sequence for s in _stored(ctx).samples] == COMBO_B_I5

    @pytest.mark.parametrize("route", ["one", "selected", "drop"])
    def test_kits_with_the_same_read_patterns_swap(self, logged_in_client, fresh_app, route):
        _app, ctx, _db = fresh_app
        umi = _combo_kit(ctx, "UmiCombo", COMBO_A_I7, COMBO_A_I5, **UMI)
        other = _combo_kit(ctx, "OtherUmi", COMBO_B_I7, COMBO_B_I5,
                           default_index2_cycles=7, default_read1_override="U8Y*",
                           default_read2_override="U8Y*")
        _run(ctx, ["PAT1", "PAT2"])
        _assign(logged_in_client, "one", "i7", umi)
        _assign(logged_in_client, "one", "i5", umi)

        _assign(logged_in_client, route, "i5", other)

        samples = _stored(ctx).samples
        assert [s.index2_sequence for s in samples] == COMBO_B_I5
        assert [_settings(s) for s in samples] == [(8, 7, "U8Y*", "U8Y*")] * 2

    @pytest.mark.parametrize("route", ["one", "selected", "drop"])
    def test_a_pair_replaces_both_indexes(self, logged_in_client, fresh_app, route):
        _app, ctx, _db = fresh_app
        umi = _combo_kit(ctx, "UmiCombo", COMBO_A_I7, COMBO_A_I5, **UMI)
        plain = _pair_kit(ctx, "PlainKit", PLAIN_PAIRS)
        _run(ctx, ["PAT1", "PAT2"])
        _assign(logged_in_client, "one", "i7", umi)
        _assign(logged_in_client, "one", "i5", umi)

        _assign(logged_in_client, route, "pair", plain)

        assert [_settings(s) for s in _stored(ctx).samples] == [(None, None, None, None)] * 2

    @pytest.mark.parametrize("route", ["one", "selected", "drop"])
    def test_a_sample_with_only_the_same_slot_takes_the_new_kit(
        self, logged_in_client, fresh_app, route
    ):
        """An i7 replacing the only index, an i7: nothing of the old kit stays."""
        _app, ctx, _db = fresh_app
        umi = _combo_kit(ctx, "UmiCombo", COMBO_A_I7, COMBO_A_I5, **UMI)
        plain = _combo_kit(ctx, "PlainCombo", COMBO_B_I7, COMBO_B_I5)
        _run(ctx, ["PAT1", "PAT2"])
        _assign(logged_in_client, "one", "i7", umi)

        _assign(logged_in_client, route, "i7", plain)

        assert [_settings(s) for s in _stored(ctx).samples] == [(None, None, None, None)] * 2


class TestTheKitSwapMessage:

    def test_what_to_do_comes_before_the_ids(self):
        """The page's error banner shows the first 300 characters (review of
        91fbe8e)."""
        from seqsetup.models.index import Index, IndexKit, IndexMode, IndexType
        from seqsetup.models.sample import Sample
        from seqsetup.models.sequencing_run import RunCycles
        from seqsetup.routes.samples import _kit_swap_refusal
        kit = IndexKit(name="IDT for Illumina DNA/RNA UD Indexes Set A Tagm", version="1",
                       index_mode=IndexMode.COMBINATORIAL)
        planned = []
        for n in range(24):
            sample = Sample(sample_id=f"Seq25-{n:04d}")
            sample.assign_index1(Index(name="a", sequence="ACGTACGTAC", index_type=IndexType.I7))
            sample.read1_override_pattern = "U8Y*"
            planned.append((sample, "i5", kit))
        text = _kit_swap_refusal(planned, RunCycles(151, 151, 10, 10)).body.decode()
        assert "or clear these samples' indexes first: Seq25-0000" in text[:300]
        assert text.endswith("Seq25-0009 and 14 more.")

    def test_without_run_cycles_the_patterns_are_compared_as_text(self):
        from seqsetup.models.index import Index, IndexKit, IndexMode, IndexType
        from seqsetup.models.sample import Sample
        from seqsetup.routes.samples import _kit_swap_refusal
        sample = Sample(sample_id="PAT1")
        sample.assign_index1(Index(name="a", sequence="ACGTACGTAC", index_type=IndexType.I7))
        sample.read1_override_pattern = sample.read2_override_pattern = "y*"

        def refused(**patterns):
            kit = IndexKit(name="K", version="1", index_mode=IndexMode.COMBINATORIAL, **patterns)
            return _kit_swap_refusal([(sample, "i5", kit)], None) is not None

        assert not refused()
        assert not refused(default_read1_override="Y*", default_read2_override="")
        assert refused(default_read1_override="U8Y*")


# --- spec §3: mismatch numbers for an index the sample does not have --------

import html  # noqa: E402

from seqsetup.models.index import Index, IndexType  # noqa: E402
from seqsetup.models.sample import Sample  # noqa: E402
from seqsetup.models.sequencing_run import (  # noqa: E402
    InstrumentPlatform,
    RunCycles,
    RunStatus,
    SequencingRun,
)

from .conftest import mark_ready  # noqa: E402
from .test_group_a3 import BCL_FIELDS, _bcl_profile, profiles  # noqa: E402,F401


def _single_index_draft(ctx, run_id, **fields):
    """S1 and S2 with an i7 only, in lane 1 of a run that reads 10 cycles of
    Index 2, on the test A3T of group A3's ``profiles``."""
    run = SequencingRun(id=run_id, run_name=run_id, instrument_platform=InstrumentPlatform.NOVASEQ_X,
                        flowcell_type="10B", run_cycles=RunCycles(151, 151, 10, 10), **fields)
    for n, i7 in enumerate(("ACGTACGTAC", "TGCATGCAAC"), start=1):
        sample = Sample(sample_id=f"S{n}", lanes=[1], test_id="A3T", test_version="1")
        sample.assign_index1(Index(name=f"i7-{n}", sequence=i7, index_type=IndexType.I7))
        run.add_sample(sample)
    ctx.run_repo.save(run)
    return ctx.run_repo.get_by_id(run_id)


def _replace_profile(ctx, **fields):
    stored = ctx.app_profile_repo.list_all()[0]
    profile = _bcl_profile(profile_id=stored.id)
    for name, value in fields.items():
        setattr(profile, name, value)
    ctx.app_profile_repo.save(profile)


class TestTheReadySheetHasNaForAMissingIndex:

    def test_a_single_index_sample_gets_na(self, logged_in_client, profiles):
        run = _single_index_draft(profiles, "l1-na")

        resp = mark_ready(logged_in_client, run.id, ORIGIN)

        stored = profiles.run_repo.get_by_id(run.id)
        assert stored.status == RunStatus.READY, html.unescape(resp.text)[:400]
        rows = stored.generated_samplesheet_v2.split("[BCLConvert_Data]\n")[1].split("\n\n")[0]
        assert rows.splitlines()[1:] == ["S1,1,ACGTACGTAC,,Y151;I10;N10;Y151,1,na",
                                         "S2,1,TGCATGCAAC,,Y151;I10;N10;Y151,1,na"]


class TestMarkReadyRefusesAMismatchSettingWithoutTheIndex:

    def test_it_refuses(self, logged_in_client, profiles):
        _replace_profile(profiles, settings={"SoftwareVersion": "4.3.6",
                                             "BarcodeMismatchesIndex2": 1},
                         data={"BarcodeMismatchesIndex1": 1}, data_fields=BCL_FIELDS[:6])
        run = _single_index_draft(profiles, "l1-setting")

        resp = logged_in_client.post(f"/runs/{run.id}/status/ready", headers=ORIGIN)

        assert resp.headers.get("HX-Retarget") == "#ready-message"
        assert ("BCLConvert profile A3BCL 1.0.0 sets BarcodeMismatchesIndex2 for the whole run "
                "in its Settings, but 2 sample(s) have no i5: S1, S2.") in html.unescape(resp.text)
        assert profiles.run_repo.get_by_id(run.id).status == RunStatus.DRAFT

    def test_the_validation_page_names_it(self, logged_in_client, profiles):
        _replace_profile(profiles, settings={"SoftwareVersion": "4.3.6",
                                             "BarcodeMismatchesIndex2": 1},
                         data={"BarcodeMismatchesIndex1": 1}, data_fields=BCL_FIELDS[:6])
        run = _single_index_draft(profiles, "l1-setting-page")

        page = html.unescape(logged_in_client.get(f"/runs/{run.id}/validation").text)

        assert "Mismatch setting without the index: " in page


# --- spec §3: no lane splitting with a Lane column ---------------------------

from .test_group_a3 import _indexed_draft  # noqa: E402


class TestMarkReadyRefusesNoLaneSplittingWithALaneColumn:
    """Group A3's BCLConvert profile has a Lane column."""

    def test_from_the_runs_setting(self, logged_in_client, profiles):
        run = _indexed_draft(profiles, "l1-nls", test_id="A3T")
        run.no_lane_splitting = True
        profiles.run_repo.save(run)

        resp = logged_in_client.post(f"/runs/{run.id}/status/ready", headers=ORIGIN)

        assert resp.headers.get("HX-Retarget") == "#ready-message"
        assert ("BCLConvert profile A3BCL 1.0.0 has a Lane column, and NoLaneSplitting is true "
                "(the run's setting).") in html.unescape(resp.text)
        assert profiles.run_repo.get_by_id(run.id).status == RunStatus.DRAFT

    def test_from_the_profiles_settings(self, logged_in_client, profiles):
        _replace_profile(profiles, settings={"SoftwareVersion": "4.3.6", "NoLaneSplitting": True})
        run = _indexed_draft(profiles, "l1-nls-profile", test_id="A3T")

        resp = logged_in_client.post(f"/runs/{run.id}/status/ready", headers=ORIGIN)

        assert resp.headers.get("HX-Retarget") == "#ready-message"
        assert ("BCLConvert profile A3BCL 1.0.0 has a Lane column, and NoLaneSplitting is true "
                "(in the profile's Settings).") in html.unescape(resp.text)
        assert profiles.run_repo.get_by_id(run.id).status == RunStatus.DRAFT

    def test_the_validation_page_names_it(self, logged_in_client, profiles):
        run = _indexed_draft(profiles, "l1-nls-page", test_id="A3T")
        run.no_lane_splitting = True
        profiles.run_repo.save(run)

        page = html.unescape(logged_in_client.get(f"/runs/{run.id}/validation").text)

        assert "No lane splitting with a Lane column: " in page
