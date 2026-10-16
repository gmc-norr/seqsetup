"""``read_export`` — the one function every reader of a stored export goes
through.

A Ready run must serve exactly the bytes its checks passed. So the manifest
is the only source for a run that has one: the function hashes the bytes it
is about to hand back, and refuses rather than serve anything else — never
the legacy field, never a fresh export. A run stored before the files moved
out of the run document keeps being served from the field it carries them in
(docs/design/2026-10-16-export-files-own-records-design.md).
"""

import hashlib
from types import SimpleNamespace

import mongomock
import pytest

from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunStatus, SequencingRun
from seqsetup.repositories.run_export_repo import RunExportRepository
from seqsetup.services.run_exports import ExportDamaged, read_export


V2 = "[Header]\nFileFormatVersion,2\n"
V1 = "[Header]\nIEMFileVersion,4\n"
JSON = '{"run_name": "R"}'
VAL_JSON = '{"errors": []}'
PDF = b"%PDF-1.4\n\x00\xffbytes\n"
TEXTS = {"samplesheet_v2": V2, "samplesheet_v1": V1, "json": JSON,
         "validation_json": VAL_JSON, "validation_pdf": PDF}


def _raw(content):
    return content.encode("utf-8") if isinstance(content, str) else content


@pytest.fixture
def ctx():
    return SimpleNamespace(
        run_export_repo=RunExportRepository(mongomock.MongoClient()["t"]))


_next_id = iter(range(1, 10_000))


def _store(ctx, run, kinds=TEXTS, *, run_id=None, kind_in_record=None):
    """Write each file as Mark Ready does and put the manifest on the run."""
    manifest = {}
    for kind, content in kinds.items():
        file_id = f"{next(_next_id):032x}"
        raw = _raw(content)
        ctx.run_export_repo.insert({
            "_id": file_id, "run_id": run_id or run.id,
            "kind": kind_in_record or kind, "content": content,
            "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw),
            "created_at": "2026-10-16T00:00:00", "created_by": "tester",
        })
        manifest[kind] = {"id": file_id,
                          "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}
    run.exports = manifest
    return manifest


def _ready_run(**kw) -> SequencingRun:
    run = SequencingRun(run_name="R", instrument_platform=InstrumentPlatform.MISEQ, **kw)
    run.add_sample(Sample(sample_id="S1"))
    run.status = RunStatus.READY
    return run


class TestAManifestIsTheOnlySource:

    def test_each_kind_comes_back_byte_for_byte(self, ctx):
        run = _ready_run()
        _store(ctx, run)
        for kind, content in TEXTS.items():
            assert read_export(ctx, run, kind) == content

    def test_a_file_record_that_is_gone_is_refused(self, ctx):
        run = _ready_run()
        _store(ctx, run)
        ctx.run_export_repo.collection.delete_one({"kind": "json"})
        with pytest.raises(ExportDamaged, match="JSON"):
            read_export(ctx, run, "json")

    def test_a_file_record_of_another_run_is_refused(self, ctx):
        run = _ready_run()
        _store(ctx, run, run_id="another-run")
        with pytest.raises(ExportDamaged):
            read_export(ctx, run, "samplesheet_v2")

    def test_a_file_record_of_another_kind_is_refused(self, ctx):
        run = _ready_run()
        _store(ctx, run, {"json": JSON}, kind_in_record="validation_json")
        with pytest.raises(ExportDamaged):
            read_export(ctx, run, "json")

    def test_content_changed_with_the_stored_hash_left_as_it_was_is_refused(self, ctx):
        """The function hashes the bytes it is about to serve; it does not
        compare the record's own sha256 and size fields with the manifest's,
        which a hand edit of the content leaves untouched."""
        run = _ready_run()
        _store(ctx, run)
        ctx.run_export_repo.collection.update_one(
            {"kind": "samplesheet_v2"},
            {"$set": {"content": V2.replace("FileFormatVersion,2", "FileFormatVersion,9")}})
        with pytest.raises(ExportDamaged, match="Sample Sheet v2"):
            read_export(ctx, run, "samplesheet_v2")

    def test_a_pdf_changed_the_same_way_is_refused(self, ctx):
        run = _ready_run()
        _store(ctx, run)
        ctx.run_export_repo.collection.update_one(
            {"kind": "validation_pdf"}, {"$set": {"content": b"%PDF-1.4\n\x00\xffother\n"}})
        with pytest.raises(ExportDamaged):
            read_export(ctx, run, "validation_pdf")

    def test_content_of_the_right_length_but_other_bytes_is_refused(self, ctx):
        run = _ready_run()
        _store(ctx, run)
        same_length = "X" * len(JSON)
        ctx.run_export_repo.collection.update_one(
            {"kind": "json"}, {"$set": {"content": same_length}})
        with pytest.raises(ExportDamaged):
            read_export(ctx, run, "json")

    def test_a_manifest_whose_length_alone_was_changed_is_refused(self, ctx):
        """A hash and a length are two statements about the same bytes. A
        manifest edited to disagree with itself is not a manifest to serve
        from, even though the bytes match its hash."""
        run = _ready_run()
        manifest = _store(ctx, run)
        entry = dict(manifest["json"])
        entry["size"] = entry["size"] + 1
        run.exports = dict(manifest, json=entry)
        with pytest.raises(ExportDamaged, match="bytes"):
            read_export(ctx, run, "json")

    def test_a_record_whose_content_is_the_wrong_python_type_is_refused(self, ctx):
        run = _ready_run()
        _store(ctx, run)
        ctx.run_export_repo.collection.update_one(
            {"kind": "json"}, {"$set": {"content": None}})
        with pytest.raises(ExportDamaged):
            read_export(ctx, run, "json")

    def test_a_required_kind_the_manifest_does_not_name_is_refused(self, ctx):
        for kind in ("samplesheet_v2", "json", "validation_json", "validation_pdf"):
            run = _ready_run()
            _store(ctx, run, {k: v for k, v in TEXTS.items() if k != kind})
            with pytest.raises(ExportDamaged):
                read_export(ctx, run, kind)

    def test_a_missing_v1_is_refused_when_the_instrument_writes_one(self, ctx):
        run = _ready_run()
        _store(ctx, run, {k: v for k, v in TEXTS.items() if k != "samplesheet_v1"})
        with pytest.raises(ExportDamaged):
            read_export(ctx, run, "samplesheet_v1")

    def test_a_missing_v1_is_no_v1_when_mark_ready_said_why(self, ctx):
        run = _ready_run(samplesheet_v1_withheld="the settings cannot be carried")
        _store(ctx, run, {k: v for k, v in TEXTS.items() if k != "samplesheet_v1"})
        assert read_export(ctx, run, "samplesheet_v1") is None

    def test_a_missing_v1_is_no_v1_when_the_instrument_writes_none(self, ctx):
        run = _ready_run()
        run.instrument_platform = InstrumentPlatform.NOVASEQ_X
        _store(ctx, run, {k: v for k, v in TEXTS.items() if k != "samplesheet_v1"})
        assert read_export(ctx, run, "samplesheet_v1") is None

    def test_the_legacy_field_is_never_read(self, ctx):
        run = _ready_run()
        _store(ctx, run, {k: v for k, v in TEXTS.items() if k != "json"})
        run.generated_json = '{"from": "the old field"}'
        with pytest.raises(ExportDamaged):
            read_export(ctx, run, "json")

    def test_a_damaged_file_is_audited(self, ctx, monkeypatch):
        rows = []
        monkeypatch.setattr("seqsetup.services.run_exports.audit",
                            lambda event, **kw: rows.append((event, kw)))
        run = _ready_run()
        _store(ctx, run)
        ctx.run_export_repo.collection.delete_one({"kind": "json"})
        with pytest.raises(ExportDamaged):
            read_export(ctx, run, "json", actor="someone")
        assert rows and rows[0][0] == "run.export.damaged"
        assert rows[0][1]["target"] == run.id
        assert rows[0][1]["kind"] == "json"
        assert rows[0][1]["actor"] == "someone"


class TestARunStoredBeforeTheFilesMovedOut:

    def test_each_legacy_field_is_served(self, ctx):
        run = _ready_run()
        run.generated_samplesheet_v2 = V2
        run.generated_samplesheet_v1 = V1
        run.generated_json = JSON
        run.generated_validation_json = VAL_JSON
        run.generated_validation_pdf = PDF
        for kind, content in TEXTS.items():
            assert read_export(ctx, run, kind) == content

    def test_a_kind_it_never_stored_gives_none_so_the_caller_can_decide(self, ctx):
        run = _ready_run()
        assert read_export(ctx, run, "samplesheet_v2") is None

    def test_a_field_holding_an_empty_file_counts_as_nothing_stored(self, ctx):
        """As the readers treated it before the files moved out: each used
        ``stored or generate``, so an empty stored value fell through to a
        live export. A 0-byte Sample Sheet download reads as a file, not as
        an error -- a lab would load it into bcl2fastq and get no samples
        (review 2, P3-1)."""
        run = _ready_run()
        run.generated_json = ""
        run.generated_samplesheet_v1 = ""
        run.generated_validation_json = ""
        for kind in ("json", "samplesheet_v1", "validation_json"):
            assert read_export(ctx, run, kind) is None, kind


class TestTheKindMustBeOneOfTheFive:

    def test_anything_else_is_a_programming_error(self, ctx):
        run = _ready_run()
        with pytest.raises(ValueError, match="kind"):
            read_export(ctx, run, "samplesheet_v3")
