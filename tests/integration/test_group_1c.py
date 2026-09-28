"""Group 1c through the real routes (spec 2026-09-28): the mismatch limit
(F6), disabled instruments (F27), the index-kit page (F31/F32) and the
Sample ID cell (F5)."""

import json
import re

import pytest

from seqsetup.data import instruments as instruments_module
from seqsetup.models.index import Index, IndexKit, IndexPair, IndexType
from seqsetup.models.instrument_definition import InstrumentDefinition
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun
from seqsetup.services.validation import ValidationService, clear_validation_cache

from .conftest import disable_repos


ORIGIN = {"Origin": "http://testserver"}
NOVASEQ_X = "NovaSeq X Series"
MISEQ_I100 = "MiSeq i100 Series"
REFUSAL = "Barcode mismatches must be 0, 1 or 2"


def _pair(i7: str, i5, name: str) -> IndexPair:
    return IndexPair(
        id=name, name=name,
        index1=Index(name=f"{name}-i7", sequence=i7, index_type=IndexType.I7),
        index2=Index(name=f"{name}-i5", sequence=i5, index_type=IndexType.I5) if i5 else None,
    )


def _mismatch_run(ctx, run_id: str) -> SequencingRun:
    """A draft with two samples, each with mismatch overrides 2 / 2."""
    run = SequencingRun(id=run_id, run_name="Group 1c", run_cycles=RunCycles(151, 151, 10, 10))
    for n in (1, 2):
        run.add_sample(Sample(sample_id=f"S{n}", lanes=[1],
                              barcode_mismatches_index1=2, barcode_mismatches_index2=2))
    ctx.run_repo.save(run)
    return ctx.run_repo.get_by_id(run_id)


def _mismatches(ctx, run_id: str):
    run = ctx.run_repo.get_by_id(run_id)
    return [(s.barcode_mismatches_index1, s.barcode_mismatches_index2) for s in run.samples], run.updated_at


class TestMismatchLimit:
    """Barcode mismatches are blank, 0, 1 or 2 (BCL Convert's range); any
    other text is refused and nothing is saved (F6)."""

    @pytest.mark.parametrize("value", ["3", "-1", "1.5", "1e", "x"])
    def test_row_refuses_value_outside_range(self, logged_in_client, fresh_app, value):
        _app, ctx, _db = fresh_app
        run = _mismatch_run(ctx, "f6-row-bad")
        before = _mismatches(ctx, run.id)

        resp = logged_in_client.post(
            f"/runs/{run.id}/samples/{run.samples[0].id}/settings",
            data={"barcode_mismatches_index1": value}, headers=ORIGIN,
        )

        assert resp.status_code == 400
        assert REFUSAL in resp.text
        assert _mismatches(ctx, run.id) == before

    @pytest.mark.parametrize("value, stored", [("", None), ("0", 0), ("2", 2), (" 1 ", 1)])
    def test_row_saves_allowed_value(self, logged_in_client, fresh_app, value, stored):
        _app, ctx, _db = fresh_app
        run = _mismatch_run(ctx, "f6-row-ok")

        resp = logged_in_client.post(
            f"/runs/{run.id}/samples/{run.samples[0].id}/settings",
            data={"barcode_mismatches_index1": value}, headers=ORIGIN,
        )

        assert resp.status_code == 200
        assert ctx.run_repo.get_by_id(run.id).samples[0].barcode_mismatches_index1 == stored

    def test_bulk_one_bad_value_changes_no_sample(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = _mismatch_run(ctx, "f6-bulk-bad")
        before = _mismatches(ctx, run.id)

        resp = logged_in_client.post(
            f"/runs/{run.id}/samples/set-mismatches",
            data={"sample_ids": json.dumps([s.id for s in run.samples]),
                  "mismatch_index1": "1", "mismatch_index2": "3"},
            headers=ORIGIN,
        )

        assert resp.status_code == 400
        assert REFUSAL in resp.text
        assert _mismatches(ctx, run.id) == before

    def test_bulk_saves_allowed_values(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = _mismatch_run(ctx, "f6-bulk-ok")

        resp = logged_in_client.post(
            f"/runs/{run.id}/samples/set-mismatches",
            data={"sample_ids": json.dumps([s.id for s in run.samples]),
                  "mismatch_index1": "0", "mismatch_index2": ""},
            headers=ORIGIN,
        )

        assert resp.status_code == 200
        assert _mismatches(ctx, run.id)[0] == [(0, None), (0, None)]
