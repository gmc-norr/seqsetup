"""Bulk sample routes must reject a ``sample_ids`` value that isn't a JSON
list of string sample IDs.

Several handlers under ``/runs/{run_id}/samples/...`` read ``sample_ids`` as
JSON and only guard against ``json.loads`` failing outright — they don't
check the *shape* of the parsed value. JSON ``null``, an object, or a list
containing a non-string reaches an iteration/membership check and raises
(TypeError), producing a 500 instead of a 400. Clinical rule (CLAUDE.md):
never silently discard data — reject invalid input visibly, with nothing
saved.
"""

import json

import pytest

from seqsetup.models.index import Index, IndexKit, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun

ORIGIN = {"Origin": "http://testserver"}

RUN_ID = "bulk-sample-ids-run"

# The exact malformed values from the brief: JSON null, an empty object, a
# list containing a non-string element, and a bare JSON string.
MALFORMED_SAMPLE_IDS = ["null", "{}", "[1]", '"S1"']


def _run(ctx, run_id=RUN_ID, *, status=RunStatus.DRAFT):
    run = SequencingRun(
        id=run_id, run_name="Bulk sample_ids run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=status,
    )
    run.add_sample(Sample(id="s1", sample_id="S1", lanes=[1]))
    run.add_sample(Sample(id="s2", sample_id="S2", lanes=[1]))
    ctx.run_repo.save(run)
    return run_id


def _index_pair_id(ctx) -> str:
    """Save a minimal index kit with one index pair so
    assign-index-to-selected clears its own kit-lookup precondition and only
    ``sample_ids`` is under test."""
    pair = IndexPair(
        id="pair1", name="Pair 1",
        index1=Index(name="i7", sequence="ATCGATCG", index_type=IndexType.I7),
        index2=Index(name="i5", sequence="GCTAGCTA", index_type=IndexType.I5),
    )
    kit = IndexKit(name="Kit1", index_pairs=[pair])
    ctx.index_kit_repo.save(kit)
    return pair.id


# route suffix -> extra form fields the handler needs so only sample_ids is
# under test (read from each handler in routes/samples.py).
ROUTE_EXTRA_FIELDS = {
    "assign-index-to-selected": lambda ctx: {"index_pair_id": _index_pair_id(ctx)},
    "set-lanes": lambda ctx: {"lanes": json.dumps([1])},
    "set-mismatches": lambda ctx: {"mismatch_index1": "1", "mismatch_index2": "1"},
    "set-override-cycles": lambda ctx: {"override_cycles": "Y151;I8N2;I8N2;Y151"},
    "set-test-id": lambda ctx: {"test_id": "WGS"},
    "bulk-delete": lambda ctx: {},
}


@pytest.mark.parametrize("raw_sample_ids", MALFORMED_SAMPLE_IDS)
@pytest.mark.parametrize("route", sorted(ROUTE_EXTRA_FIELDS))
class TestBulkRoutesRejectNonListSampleIds:
    """Every bulk-edit handler must answer 400 (not 500, not a silent
    no-op 200) when sample_ids isn't a JSON list of strings, and must not
    touch the stored run."""

    def test_returns_400_and_leaves_run_unchanged(
        self, logged_in_client, fresh_app, route, raw_sample_ids
    ):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)
        extra = ROUTE_EXTRA_FIELDS[route](ctx)
        before = ctx.run_repo.get_by_id(run_id).to_dict()

        response = logged_in_client.post(
            f"/runs/{run_id}/samples/{route}",
            data={"sample_ids": raw_sample_ids, **extra},
            headers=ORIGIN,
        )

        assert response.status_code == 400, response.text[:300]
        after = ctx.run_repo.get_by_id(run_id).to_dict()
        assert after == before


class TestBulkRouteRejectsFileSampleIds:
    """``sample_ids`` sent as a multipart *file* part, not a text field.

    ``await request.form()`` yields an ``UploadFile`` (not a ``str``) for a
    multipart part named ``sample_ids``, and ``json.loads(UploadFile)``
    raises ``TypeError`` — not the ``json.JSONDecodeError`` the parser
    guards against. That reached no ``except`` clause and produced a 500.
    """

    def test_bulk_delete_returns_400_not_500(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)
        before = ctx.run_repo.get_by_id(run_id).to_dict()

        response = logged_in_client.post(
            f"/runs/{run_id}/samples/bulk-delete",
            files={"sample_ids": ("ids.json", b'["s1"]', "application/octet-stream")},
            headers=ORIGIN,
        )

        assert response.status_code == 400, response.text[:300]
        after = ctx.run_repo.get_by_id(run_id).to_dict()
        assert after == before


class TestSetLanesRejectsInvalidLanesJson:
    """``set-lanes`` with a valid ``sample_ids`` but a ``lanes`` value that
    isn't JSON must answer 400 naming the ``lanes`` field — not
    ``sample_ids`` — and must not touch the stored run."""

    def test_returns_400_and_leaves_lanes_unchanged(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)
        before = ctx.run_repo.get_by_id(run_id).to_dict()

        response = logged_in_client.post(
            f"/runs/{run_id}/samples/set-lanes",
            data={"sample_ids": json.dumps(["s1", "s2"]), "lanes": "not json"},
            headers=ORIGIN,
        )

        assert response.status_code == 400, response.text[:300]
        assert response.text == "Invalid lanes JSON"
        after = ctx.run_repo.get_by_id(run_id).to_dict()
        assert after == before
