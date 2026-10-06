"""Group A3 through the real routes (spec 2026-10-05): the Sample Sheet carries
what Mark Ready checked."""

import html

import pytest

from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun


ORIGIN = {"Origin": "http://testserver"}
NOVASEQ_X = InstrumentPlatform.NOVASEQ_X

INDEX1_ORDER_RULE = (
    "Index 1 in OverrideCycles starts with the index in SeqSetup: the index first, then any "
    "masked or UMI cycles (for example I8N2 or I8U9). SeqSetup's checks compare the index "
    "from the first cycle of its read."
)
INDEX_SPLIT_RULE = (
    "An index part of OverrideCycles holds one run of index cycles in SeqSetup (for example "
    "I8N2, not I4N2I4). SeqSetup's checks compare the index as one run of cycles."
)
INDEX2_ORDER_RULE = (
    "Index 2 in OverrideCycles is written in reading order in SeqSetup: the index first, then "
    "the masked cycles (for example I8N2). SeqSetup writes it the way the instrument needs."
)


def _indexed_draft(ctx, run_id: str, override: str = "", i7: str = "ATTACTCG",
                   i5: str = "TATAGCCT", cycles: RunCycles = RunCycles(151, 151, 10, 10),
                   index1_cycles=None) -> SequencingRun:
    from seqsetup.models.index import Index, IndexPair, IndexType
    from seqsetup.models.sample import Sample
    run = SequencingRun(id=run_id, run_name=run_id, instrument_platform=NOVASEQ_X,
                        flowcell_type="10B", run_cycles=cycles)
    run.add_sample(Sample(sample_id="S1", lanes=[1], override_cycles=override or None,
                          index1_cycles=index1_cycles,
                          index_pair=IndexPair(
                              id="p1", name="p1",
                              index1=Index(name="i7", sequence=i7, index_type=IndexType.I7),
                              index2=Index(name="i5", sequence=i5, index_type=IndexType.I5),
                          )))
    ctx.run_repo.save(run)
    return ctx.run_repo.get_by_id(run_id)


REFUSED = [
    pytest.param("Y151;N2I8;I8N2;Y151", INDEX1_ORDER_RULE, id="index-1-masked-first"),
    pytest.param("Y151;Y2I8;I8N2;Y151", INDEX1_ORDER_RULE, id="index-1-y-first"),
    pytest.param("Y151;I8N2;Y2I8;Y151", INDEX2_ORDER_RULE, id="index-2-y-first"),
    pytest.param("Y151;I4N2I4;I8N2;Y151", INDEX_SPLIT_RULE, id="index-1-split"),
    pytest.param("Y151;I8N2;I4N2I4;Y151", INDEX_SPLIT_RULE, id="index-2-split"),
]


class TestATypedIndexPartIsRefused:
    """An index part that does not start with the index, or holds two runs of
    index cycles, is refused where it is typed and at Mark Ready (spec §4)."""

    @pytest.mark.parametrize("value,rule", REFUSED)
    def test_the_sample_input_refuses_it(self, logged_in_client, fresh_app, value, rule):
        _app, ctx, _db = fresh_app
        run = _indexed_draft(ctx, "a3-typed-row")
        resp = logged_in_client.post(
            f"/runs/{run.id}/samples/{run.samples[0].id}/settings",
            data={"override_cycles": value}, headers=ORIGIN,
        )
        assert resp.status_code == 400
        assert f"{rule} Nothing was saved." in html.unescape(resp.text)
        assert ctx.run_repo.get_by_id(run.id).samples[0].override_cycles is None

    @pytest.mark.parametrize("value,rule", REFUSED)
    def test_the_bulk_input_refuses_it(self, logged_in_client, fresh_app, value, rule):
        _app, ctx, _db = fresh_app
        run = _indexed_draft(ctx, "a3-typed-bulk")
        resp = logged_in_client.post(
            f"/runs/{run.id}/samples/set-override-cycles",
            data={"sample_ids": f'["{run.samples[0].id}"]', "override_cycles": value},
            headers=ORIGIN,
        )
        assert resp.status_code == 400
        assert f"{rule} Nothing was saved." in html.unescape(resp.text)
        assert ctx.run_repo.get_by_id(run.id).samples[0].override_cycles is None

    @pytest.mark.parametrize("value", ["Y151;I8N2;I8N2;Y151", "Y151;I8U2;N10;Y151"])
    def test_the_index_first_is_saved(self, logged_in_client, fresh_app, value):
        _app, ctx, _db = fresh_app
        run = _indexed_draft(ctx, "a3-typed-ok")
        resp = logged_in_client.post(
            f"/runs/{run.id}/samples/{run.samples[0].id}/settings",
            data={"override_cycles": value}, headers=ORIGIN,
        )
        assert resp.status_code == 200
        assert ctx.run_repo.get_by_id(run.id).samples[0].override_cycles == value

    @pytest.mark.parametrize("value,rule", REFUSED)
    def test_mark_ready_refuses_a_stored_one(self, logged_in_client, fresh_app, value, rule):
        from .conftest import disable_repos
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        run = _indexed_draft(ctx, "a3-typed-ready", override=value)

        resp = logged_in_client.post(f"/runs/{run.id}/status/ready", headers=ORIGIN)

        assert resp.headers.get("HX-Retarget") == "#ready-message"
        assert rule in html.unescape(resp.text)
        assert ctx.run_repo.get_by_id(run.id).status == RunStatus.DRAFT


class TestAnIndexMustBeAsLongAsTheCyclesRead:
    """Mark Ready refuses an index whose length differs from the cycles its
    OverrideCycles reads for it (spec §4)."""

    def test_kit_cycles_shorter_than_the_index_on_an_equal_read(self, logged_in_client, fresh_app):
        # A 10-base i7 with kit index cycles 8 on an 8-cycle read: 0 errors before.
        from .conftest import disable_repos
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        run = _indexed_draft(ctx, "a3-length", i7="ATTACTCGAT", cycles=RunCycles(151, 151, 8, 8),
                             index1_cycles=8)

        resp = logged_in_client.post(f"/runs/{run.id}/status/ready", headers=ORIGIN)

        assert resp.headers.get("HX-Retarget") == "#ready-message"
        assert (
            "1 sample(s) have an index whose length differs from the index cycles their "
            "OverrideCycles reads: S1 (i7: 10 bases, 8 read)."
        ) in html.unescape(resp.text)
        assert ctx.run_repo.get_by_id(run.id).status == RunStatus.DRAFT
