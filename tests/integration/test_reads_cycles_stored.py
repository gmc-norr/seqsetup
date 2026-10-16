"""Four different cycle counts, set through the cycle fields' route, reach the
stored sheets and JSON at Mark Ready ("Risk 4" gap).

Every [Reads] test used Read 1 = Read 2 and Index 1 = Index 2, so a swap
anywhere between the cycle fields and the stored exports -- the route that
reads the form, the run's storage, a writer -- passed. Here a NovaSeq 6000
run (it writes v1 too) gets four different counts through POST
/runs/{run_id}/cycles, samples pasted with indexes as long as each index
read, and Mark Ready through its route; the stored v2 sheet, v1 sheet and
JSON, and what the API serves from them, must carry each count under its own
name.
"""

import json

import pytest

from seqsetup.models.sequencing_run import (InstrumentPlatform, RunCycles, RunStatus,
                                            SequencingRun)

from .conftest import hold_edit_lock, mark_ready, run_version
from .test_index_safety_net import TEST_ID, TEST_VERSION, _bearer, _seed_profiles

ORIGIN = {"Origin": "http://testserver"}

# The counts the run starts with: none equal to any count set below, so a
# route that dropped a field would leave a count that shows.
START = RunCycles(76, 76, 6, 6)

# (Read 1, Read 2, Index 1, Index 2), no two alike, and the samples' indexes
# as long as each index read. The second set is the first with each pair
# swapped.
CASES = [
    pytest.param((151, 101, 10, 8), [("C-01", "ACGTACGTAC", "TTGGCCAA"),
                                     ("C-02", "TGCATGCAAC", "AACCGGTT")], id="151-101-10-8"),
    pytest.param((101, 151, 8, 10), [("C-01", "ACGTACGT", "TTGGCCAATT"),
                                     ("C-02", "TGCATGCA", "AACCGGTTAA")], id="101-151-8-10"),
]


@pytest.fixture(autouse=True)
def _profiles(fresh_app):
    """The safety net's BCLConvert profile (with a Lane column, as the shipped
    one has) and its test, so the paste's test is known and Mark Ready writes
    the profile-driven sections."""
    _app, ctx, _db = fresh_app
    _seed_profiles(ctx)


def _draft(ctx, run_id: str) -> str:
    run = SequencingRun(id=run_id, run_name=run_id, instrument_platform=InstrumentPlatform.NOVASEQ_6000,
                        flowcell_type="S4", i5_workflow="v1.5 reagents", run_cycles=START)
    ctx.run_repo.save(run)
    hold_edit_lock(ctx, run_id)
    return run_id


def _set_cycles(client, ctx, run_id: str, **counts):
    return client.post(f"/runs/{run_id}/cycles", data={**counts, "run_version": run_version(ctx, run_id)},
                       headers=ORIGIN)


def _form(counts) -> dict:
    read1, read2, index1, index2 = counts
    return {"read1_cycles": str(read1), "read2_cycles": str(read2),
            "index1_cycles": str(index1), "index2_cycles": str(index2)}


def _paste(client, run_id: str, samples):
    paste = "sample_id\tindex_i7\tindex_i5\n" + "".join(
        f"{sid}\t{i7}\t{i5}\n" for sid, i7, i5 in samples)
    resp = client.post(f"/runs/{run_id}/samples/bulk",
                       data={"paste_data": paste, "lanes": ["1"],
                             "default_test_id": TEST_ID, "default_test_version": TEST_VERSION},
                       headers=ORIGIN)
    assert resp.status_code == 200 and "rejected" not in resp.text, resp.text[:400]


def _stored_counts(ctx, run_id: str) -> tuple:
    rc = ctx.run_repo.get_by_id(run_id).run_cycles
    return (rc.read1_cycles, rc.read2_cycles, rc.index1_cycles, rc.index2_cycles)


def _reads(sheet: str) -> list[str]:
    return sheet.split("[Reads]\n", 1)[1].split("\n\n", 1)[0].splitlines()


def _ready_run(client, ctx, run_id: str, counts, samples):
    _draft(ctx, run_id)
    resp = _set_cycles(client, ctx, run_id, **_form(counts))
    assert resp.status_code == 200, resp.text[:300]
    _paste(client, run_id, samples)
    answer = mark_ready(client, run_id, ORIGIN)
    stored = ctx.run_repo.get_by_id(run_id)
    assert stored.status == RunStatus.READY, answer.text[:600]
    return stored


class TestTheCycleRouteStoresEachCount:
    """POST /runs/{run_id}/cycles stores each form field in its own count."""

    @pytest.mark.parametrize("counts,samples", CASES)
    def test_the_four_counts_are_stored_under_their_names(self, logged_in_client, fresh_app,
                                                          counts, samples):
        _app, ctx, _db = fresh_app
        run_id = _draft(ctx, "cycles-stored")

        resp = _set_cycles(logged_in_client, ctx, run_id, **_form(counts))

        assert resp.status_code == 200, resp.text[:300]
        assert _stored_counts(ctx, run_id) == counts

    def test_a_missing_count_is_refused_and_nothing_is_saved(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _draft(ctx, "cycles-missing")
        form = _form((151, 101, 10, 8))
        del form["index2_cycles"]

        resp = _set_cycles(logged_in_client, ctx, run_id, **form)

        assert resp.status_code == 400
        # A field that is not sent at all reads as not set; the range message
        # is for a value that IS sent and is out of range (review of 9fac120,
        # P2-3: the index fields are a dropdown of 8, 10, 12, 17 and 24, so
        # "a whole number from 0 to 600" named nothing they can offer).
        assert resp.text == ("Index 2 cycles is not set. Set all four cycle counts; "
                             "they are saved together.")
        assert _stored_counts(ctx, run_id) == (76, 76, 6, 6)

    def test_a_count_over_the_limit_is_refused_and_nothing_is_saved(self, logged_in_client,
                                                                    fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _draft(ctx, "cycles-over")
        form = _form((151, 101, 10, 8))
        form["read2_cycles"] = "601"

        resp = _set_cycles(logged_in_client, ctx, run_id, **form)

        assert resp.status_code == 400
        assert resp.text == "Read 2 cycles must be a whole number from 0 to 600."
        assert _stored_counts(ctx, run_id) == (76, 76, 6, 6)


class TestMarkReadyStoresEachCountInEveryExport:
    """The stored v2 sheet, v1 sheet and JSON carry the counts set through
    the route, each under its own name, and the API serves those bytes. One
    Mark Ready per set of counts: each one makes the whole report."""

    @pytest.mark.parametrize("counts,samples", CASES)
    def test_every_stored_export_carries_each_count(self, logged_in_client, fresh_app,
                                                    counts, samples):
        _app, ctx, _db = fresh_app
        read1, read2, index1, index2 = counts

        stored = _ready_run(logged_in_client, ctx, "cycles-stored", counts, samples)

        assert _reads(stored.generated_samplesheet_v2) == [
            f"Read1Cycles,{read1}", f"Read2Cycles,{read2}",
            f"Index1Cycles,{index1}", f"Index2Cycles,{index2}"]
        # Each row's OverrideCycles reads the same four counts, in the
        # instrument's order (Read 1, Index 1, Index 2, Read 2).
        rows = stored.generated_samplesheet_v2.split("[BCLConvert_Data]\n")[1].split("\n\n")[0]
        header, *data = rows.splitlines()
        column = header.split(",").index("OverrideCycles")
        assert [row.split(",")[column] for row in data] == (
            [f"Y{read1};I{index1};I{index2};Y{read2}"] * len(samples))

        assert stored.generated_samplesheet_v1 is not None
        assert _reads(stored.generated_samplesheet_v1) == [str(read1), str(read2)]

        assert json.loads(stored.generated_json)["cycles"] == {
            "read1_cycles": read1, "read2_cycles": read2,
            "index1_cycles": index1, "index2_cycles": index2,
            "total_cycles": read1 + read2 + index1 + index2}

        headers = _bearer(logged_in_client, ctx)
        served = {kind: logged_in_client.get(f"/api/runs/cycles-stored/{kind}", headers=headers)
                  for kind in ("samplesheet-v2", "samplesheet-v1", "json")}
        assert {kind: r.status_code for kind, r in served.items()} == dict.fromkeys(served, 200)
        assert served["samplesheet-v2"].text == stored.generated_samplesheet_v2
        assert served["samplesheet-v1"].text == stored.generated_samplesheet_v1
        assert served["json"].json()["cycles"] == json.loads(stored.generated_json)["cycles"]
