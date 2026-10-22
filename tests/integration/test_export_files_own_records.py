"""Mark Ready writes each export file into its own record, and a Ready run
serves exactly those bytes.

The bytes an exporter returned during the Mark Ready that let the run through
are the only bytes any reader may hand out: a fresh export of the same run
would not even be equal (the check report carries its generation time), and
is not what the checks passed. Each test therefore spies on the exporters and
compares what came out of them with what every reader serves
(docs/design/2026-10-16-export-files-own-records-design.md, "What proves it"
1 and 2).
"""

import hashlib

import pytest

from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import (
    EXPORT_KINDS, InstrumentPlatform, RunCycles, RunStatus, SequencingRun,
)
from seqsetup.services.json_exporter import JSONExporter
from seqsetup.services.samplesheet_v1_exporter import SampleSheetV1Exporter
from seqsetup.services.samplesheet_v2_exporter import SampleSheetV2Exporter
from seqsetup.services.validation_report import ValidationReportJSON, ValidationReportPDF

from .conftest import disable_repos, hold_edit_lock, mark_ready, seed_profiles
from .test_group_1c import _pair


ORIGIN = {"Origin": "http://testserver"}
I5 = "TATAGCCT"
# NovaSeq 6000 / S4 writes both sheets; NovaSeq X writes no v1 sheet.
BOTH_SHEETS = (InstrumentPlatform.NOVASEQ_6000, "S4", "v1.0 reagents")
V2_ONLY = (InstrumentPlatform.NOVASEQ_X, "10B", "")

_EXPORTERS = (
    ("samplesheet_v2", SampleSheetV2Exporter),
    ("samplesheet_v1", SampleSheetV1Exporter),
    ("json", JSONExporter),
    ("validation_json", ValidationReportJSON),
    ("validation_pdf", ValidationReportPDF),
)


def spy_on_exporters(monkeypatch) -> dict:
    """Record what each exporter returns. The returned dict fills in as the
    Mark Ready request runs; a kind an exporter was never asked for is
    absent."""
    seen: dict = {}

    def watch(kind, cls):
        original = cls.export

        def export(*args, **kwargs):
            out = original(*args, **kwargs)
            seen.setdefault(kind, []).append(out)
            return out

        monkeypatch.setattr(cls, "export", staticmethod(export))

    for kind, cls in _EXPORTERS:
        watch(kind, cls)
    return seen


def seed_run(ctx, run_id, which=BOTH_SHEETS, *, samples=1):
    instrument, flowcell, workflow = which
    seed_profiles(ctx)
    run = SequencingRun(
        id=run_id, run_name=f"Run {run_id}", instrument_platform=instrument,
        flowcell_type=flowcell, i5_workflow=workflow,
        run_cycles=RunCycles(151, 151, 8, 8),
    )
    for n in range(samples):
        run.add_sample(Sample(test_id="WGS", test_version="1", sample_id=f"S{n + 1}",
                              index_pair=_pair(_I7[n], _I5[n], f"p{n + 1}"), lanes=[1]))
    ctx.run_repo.save(run)
    hold_edit_lock(ctx, run.id)
    return run.id


_I7 = ["ATTACTCG", "TCCGGAGA", "CGCTCATT", "GAGATTCC"]
_I5 = [I5, "ATAGAGGC", "CCTATCCT", "GGCTCTGA"]


def records(ctx, run_id=None) -> list:
    where = {"run_id": run_id} if run_id else {}
    return list(ctx.run_export_repo.collection.find(where))


class TestMarkReadyWritesTheFilesIntoTheirOwnRecords:

    def test_the_run_names_every_file_the_exporters_wrote(
            self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        run_id = seed_run(ctx, "own-records")
        seen = spy_on_exporters(monkeypatch)

        assert mark_ready(logged_in_client, run_id, ORIGIN).status_code == 200

        stored = ctx.run_repo.get_by_id(run_id)
        assert stored.status == RunStatus.READY
        assert set(stored.exports) == set(EXPORT_KINDS)
        assert set(seen) == set(EXPORT_KINDS)

    def test_the_run_document_no_longer_carries_any_file(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = seed_run(ctx, "no-blobs")

        assert mark_ready(logged_in_client, run_id, ORIGIN).status_code == 200

        doc = ctx.run_repo.collection.find_one({"_id": run_id})
        for key in ("generated_samplesheet_v2", "generated_samplesheet_v1",
                    "generated_json", "generated_validation_json",
                    "generated_validation_pdf"):
            assert doc[key] is None, key

    def test_each_record_holds_the_bytes_that_exporter_returned(
            self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        run_id = seed_run(ctx, "same-bytes")
        seen = spy_on_exporters(monkeypatch)

        assert mark_ready(logged_in_client, run_id, ORIGIN).status_code == 200

        stored = ctx.run_repo.get_by_id(run_id)
        for kind in EXPORT_KINDS:
            written = seen[kind][-1]
            record = ctx.run_export_repo.get(stored.exports[kind]["id"])
            assert record["content"] == written, kind
            assert record["kind"] == kind
            assert record["run_id"] == run_id

    def test_each_record_states_the_hash_and_the_length_of_its_bytes(
            self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        run_id = seed_run(ctx, "hashes")
        seen = spy_on_exporters(monkeypatch)

        assert mark_ready(logged_in_client, run_id, ORIGIN).status_code == 200

        stored = ctx.run_repo.get_by_id(run_id)
        for kind in EXPORT_KINDS:
            written = seen[kind][-1]
            raw = written.encode("utf-8") if isinstance(written, str) else written
            entry = stored.exports[kind]
            record = ctx.run_export_repo.get(entry["id"])
            assert entry["sha256"] == hashlib.sha256(raw).hexdigest(), kind
            assert entry["size"] == len(raw), kind
            assert record["sha256"] == entry["sha256"] and record["size"] == entry["size"]

    def test_each_record_says_when_it_was_written_and_by_whom(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = seed_run(ctx, "who-and-when")

        assert mark_ready(logged_in_client, run_id, ORIGIN).status_code == 200

        written = records(ctx, run_id)
        assert len(written) == len(EXPORT_KINDS), written
        for record in written:
            assert record["created_by"] == "admin-test"
            assert record["created_at"].startswith("20")

    def test_the_pdf_is_stored_as_bytes_not_base64(
            self, logged_in_client, fresh_app, monkeypatch):
        """Base64 inside the run document is what made a 10.7 MB report a
        14.2 MB field (the spec's measurement)."""
        _app, ctx, _db = fresh_app
        run_id = seed_run(ctx, "pdf-bytes")
        seen = spy_on_exporters(monkeypatch)

        assert mark_ready(logged_in_client, run_id, ORIGIN).status_code == 200

        stored = ctx.run_repo.get_by_id(run_id)
        record = ctx.run_export_repo.get(stored.exports["validation_pdf"]["id"])
        assert isinstance(record["content"], bytes)
        assert record["content"] == seen["validation_pdf"][-1]
        assert record["size"] == len(seen["validation_pdf"][-1])

    def test_a_run_whose_instrument_writes_no_v1_sheet_names_four_files(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = seed_run(ctx, "no-v1", V2_ONLY)

        assert mark_ready(logged_in_client, run_id, ORIGIN).status_code == 200

        stored = ctx.run_repo.get_by_id(run_id)
        assert set(stored.exports) == {"samplesheet_v2", "json",
                                       "validation_json", "validation_pdf"}

    def test_a_withheld_v1_sheet_is_not_stored(
            self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        monkeypatch.setattr(SampleSheetV1Exporter, "withheld", classmethod(
            lambda cls, run, mismatches=None:
            ("S1 has OverrideCycles a v1 sheet cannot hold", ["S1"])))
        run_id = seed_run(ctx, "withheld-v1")

        assert mark_ready(logged_in_client, run_id, ORIGIN).status_code == 200

        stored = ctx.run_repo.get_by_id(run_id)
        assert set(stored.exports) == {"samplesheet_v2", "json",
                                       "validation_json", "validation_pdf"}
        assert stored.samplesheet_v1_withheld

    def test_the_listing_no_longer_loads_every_run_s_files(
            self, logged_in_client, fresh_app):
        """F11: the dashboard loaded every Ready run's whole export set to
        show names and dates."""
        _app, ctx, _db = fresh_app
        run_id = seed_run(ctx, "small-document")

        assert mark_ready(logged_in_client, run_id, ORIGIN).status_code == 200

        from bson import BSON
        doc = ctx.run_repo.collection.find_one({"_id": run_id})
        doc.pop("_id", None)
        document = len(BSON.encode(dict(doc, _id=run_id)))
        files = sum(r["size"] for r in records(ctx, run_id))
        assert files > 10_000, files
        assert document < files / 2, (document, files)


class TestTheSheetTargetsComeFromTheSheetsThatWereWritten:

    def test_both_targets_are_saved_when_both_sheets_are(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = seed_run(ctx, "targets-both")

        assert mark_ready(logged_in_client, run_id, ORIGIN).status_code == 200

        stored = ctx.run_repo.get_by_id(run_id)
        assert stored.sheet_targets["samplesheet_v2"]["software"] == "BCL Convert"
        assert stored.sheet_targets["samplesheet_v1"]["software"] == "bcl2fastq"

    def test_the_v1_target_is_none_when_no_v1_sheet_was_stored(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = seed_run(ctx, "targets-v2-only", V2_ONLY)

        assert mark_ready(logged_in_client, run_id, ORIGIN).status_code == 200

        stored = ctx.run_repo.get_by_id(run_id)
        assert stored.sheet_targets["samplesheet_v1"] is None

    def test_the_v2_target_names_the_version_the_written_sheet_states(
            self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        run_id = seed_run(ctx, "targets-version")
        seen = spy_on_exporters(monkeypatch)

        assert mark_ready(logged_in_client, run_id, ORIGIN).status_code == 200

        stored = ctx.run_repo.get_by_id(run_id)
        sheet = seen["samplesheet_v2"][-1]
        version = stored.sheet_targets["samplesheet_v2"]["software_version"]
        assert version and f"SoftwareVersion,{version}" in sheet
