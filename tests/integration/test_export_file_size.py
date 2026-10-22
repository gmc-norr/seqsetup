"""One file has a whole MongoDB document to itself, and a file that will not
fit is refused before anything is written.

mongomock accepts a document of any size, so these tests wrap the ``runs``
and ``run_exports`` collections to refuse one over 16 MiB exactly as a real
server does -- without the wrapper a run whose files are far over the limit
together would pass, and so would a negative margin. A real ``mongo:7``
server is used once, at the end of the run that built this
(docs/design/2026-10-16-export-files-own-records-design.md, "What proves it" 4).
"""

import hashlib

import pytest
from bson import BSON

from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import EXPORT_KINDS, RunStatus, SequencingRun
from seqsetup.services.run_exports import (
    EXPORT_FILE_MARGIN, MAX_EXPORT_FILE, read_export,
)
from seqsetup.services.validation_report import ValidationReportPDF

from .conftest import mark_ready
from .test_export_files_own_records import BOTH_SHEETS, ORIGIN, records, seed_run


MONGO_LIMIT = 16 * 1024 * 1024


class _SizedCollection:
    """A mongomock collection that refuses a document over MongoDB's limit,
    with the driver's own error."""

    def __init__(self, inner):
        self._inner = inner

    def __getattr__(self, name):
        return getattr(self._inner, name)

    @staticmethod
    def _check(doc):
        from pymongo.errors import DocumentTooLarge
        size = len(BSON.encode(doc))
        if size > MONGO_LIMIT:
            raise DocumentTooLarge(f"BSON document too large ({size} bytes)")

    def insert_one(self, doc, *a, **kw):
        self._check(doc)
        return self._inner.insert_one(doc, *a, **kw)

    def replace_one(self, where, doc, *a, **kw):
        self._check(doc)
        return self._inner.replace_one(where, doc, *a, **kw)


@pytest.fixture
def mongo_limit(fresh_app):
    """Both collections refuse a document over 16 MiB, as MongoDB does."""
    _app, ctx, _db = fresh_app
    ctx.run_repo.collection = _SizedCollection(ctx.run_repo.collection)
    ctx.run_export_repo.collection = _SizedCollection(ctx.run_export_repo.collection)
    return ctx


def _pdf_of(size):
    block = hashlib.sha256(b"seed").digest() * 4096          # 128 KiB, incompressible
    return (block * (size // len(block) + 1))[:size]


def _one_huge_report(size):
    def export(_run, _result):
        return _pdf_of(size)
    return export


def _one_huge_json(size):
    def export(_run, _result):
        # Valid JSON of about ``size`` bytes.
        return '{"filler": "' + "x" * (size - 14) + '"}'
    return export


def _two_big_files(monkeypatch, each):
    """A PDF and a check report of ``each`` bytes: each fits one document,
    the two together do not."""
    from seqsetup.services.validation_report import ValidationReportJSON
    monkeypatch.setattr(ValidationReportPDF, "export", staticmethod(_one_huge_report(each)))
    monkeypatch.setattr(ValidationReportJSON, "export", staticmethod(_one_huge_json(each)))


def _audit_rows(ctx, run_id):
    return [e.details for e in
            ctx.audit_event_repo.search(limit=50, event_prefix="run.status.denied")
            if e.target == run_id]


class TestFilesThatTogetherExceedOneDocumentAreStored:
    """The whole point: five files of 4 MB each are 20 MB together, which no
    single MongoDB document can hold."""

    def test_the_run_goes_ready_and_serves_every_file(
            self, logged_in_client, mongo_limit, monkeypatch):
        ctx = mongo_limit
        run_id = seed_run(ctx, "big-together")
        _two_big_files(monkeypatch, 10 * 1024 * 1024)

        resp = mark_ready(logged_in_client, run_id, ORIGIN)

        assert resp.status_code == 200, resp.text[:400]
        stored = ctx.run_repo.get_by_id(run_id)
        assert stored.status == RunStatus.READY
        assert set(stored.exports) == set(EXPORT_KINDS)
        for kind in EXPORT_KINDS:
            assert read_export(ctx, stored, kind), kind
        assert sum(r["size"] for r in records(ctx, run_id)) > MONGO_LIMIT

    def test_the_download_serves_the_whole_pdf(
            self, logged_in_client, mongo_limit, monkeypatch):
        ctx = mongo_limit
        run_id = seed_run(ctx, "big-download")
        monkeypatch.setattr(ValidationReportPDF, "export",
                            staticmethod(_one_huge_report(12 * 1024 * 1024)))
        assert mark_ready(logged_in_client, run_id, ORIGIN).status_code == 200

        resp = logged_in_client.get(f"/runs/{run_id}/export/validation-pdf")

        assert resp.status_code == 200
        assert len(resp.content) == 12 * 1024 * 1024


class TestOneFileOverTheLimitIsRefusedBeforeAnythingIsWritten:

    def test_the_run_stays_a_draft_and_no_file_is_written(
            self, logged_in_client, mongo_limit, monkeypatch):
        ctx = mongo_limit
        run_id = seed_run(ctx, "file-too-big")
        monkeypatch.setattr(ValidationReportPDF, "export",
                            staticmethod(_one_huge_report(17 * 1024 * 1024)))

        resp = mark_ready(logged_in_client, run_id, ORIGIN)

        assert resp.status_code == 200, resp.text[:400]
        stored = ctx.run_repo.get_by_id(run_id)
        assert stored.status == RunStatus.DRAFT
        assert stored.exports == {}
        assert records(ctx) == [], "a file was written before the refusal"

    def test_the_refusal_names_the_file_the_size_and_the_limit(
            self, logged_in_client, mongo_limit, monkeypatch):
        ctx = mongo_limit
        run_id = seed_run(ctx, "file-too-big-message")
        monkeypatch.setattr(ValidationReportPDF, "export",
                            staticmethod(_one_huge_report(17 * 1024 * 1024)))

        resp = mark_ready(logged_in_client, run_id, ORIGIN)

        assert resp.headers.get("HX-Retarget") == "#ready-message", dict(resp.headers)
        assert "check report (PDF)" in resp.text, resp.text[:600]
        assert "17.0 MB" in resp.text, resp.text[:600]
        assert "16 MB in one file" in resp.text, resp.text[:600]

    def test_the_refusal_says_it_is_a_seqsetup_limit_and_gives_no_lab_advice(
            self, logged_in_client, mongo_limit, monkeypatch):
        ctx = mongo_limit
        run_id = seed_run(ctx, "file-too-big-advice")
        monkeypatch.setattr(ValidationReportPDF, "export",
                            staticmethod(_one_huge_report(17 * 1024 * 1024)))

        resp = mark_ready(logged_in_client, run_id, ORIGIN)

        message = resp.text.split("<ul>", 1)[-1].split("</ul>", 1)[0]
        assert "limit of SeqSetup, not a problem with the run" in message, message
        assert "administrator" in message, message
        for advice in ("lane", "more than one run", "split"):
            assert advice not in message.lower(), message

    def test_the_refusal_is_audited_with_the_kind_and_the_size(
            self, logged_in_client, mongo_limit, monkeypatch):
        ctx = mongo_limit
        run_id = seed_run(ctx, "file-too-big-audit")
        monkeypatch.setattr(ValidationReportPDF, "export",
                            staticmethod(_one_huge_report(17 * 1024 * 1024)))

        mark_ready(logged_in_client, run_id, ORIGIN)

        (row,) = [r for r in _audit_rows(ctx, run_id)
                  if r.get("reason") == "export_file_too_large"]
        assert row["kind"] == "validation_pdf"
        assert row["file_bytes"] > 17 * 1024 * 1024 - 1

    def test_it_is_not_reported_as_a_validation_refusal(
            self, logged_in_client, mongo_limit, monkeypatch):
        ctx = mongo_limit
        run_id = seed_run(ctx, "file-too-big-footer")
        monkeypatch.setattr(ValidationReportPDF, "export",
                            staticmethod(_one_huge_report(17 * 1024 * 1024)))

        resp = mark_ready(logged_in_client, run_id, ORIGIN)

        assert "Samples with errors are marked in the table" not in resp.text
        assert "Open the validation page" not in resp.text
        assert "Cannot mark ready: 1 error to fix first" not in resp.text


class TestTheLimitItselfIsPinned:
    """A margin at or below zero would let the route accept a record the
    server refuses -- the bare 500 after the full export time this exists to
    stop (the same review point as the run-document limit's)."""

    def test_the_threshold_is_below_what_mongodb_accepts(self):
        assert EXPORT_FILE_MARGIN > 0
        assert MAX_EXPORT_FILE <= MONGO_LIMIT
        assert MAX_EXPORT_FILE - EXPORT_FILE_MARGIN < MONGO_LIMIT

    def test_a_record_just_under_the_threshold_really_fits(self):
        """What is measured is the whole record, every field included, so the
        margin is slack rather than an allowance for the other fields. This
        pins that a record right at the threshold really is accepted."""
        content = b"x" * (MAX_EXPORT_FILE - EXPORT_FILE_MARGIN)
        doc = {"_id": "a" * 32, "run_id": "r" * 64, "kind": "validation_pdf",
               "content": content, "sha256": "b" * 64, "size": len(content),
               "created_at": "2026-10-16T12:00:00.000000", "created_by": "x" * 256}
        assert len(BSON.encode(doc)) <= MONGO_LIMIT


class TestTheWorstCaseCheckReportStillFits:
    """The check report's JSON is the one file that comes near a single
    document's limit: 8 lanes x 200 samples with 256-character sample ids,
    just under MAX_HEATMAP_SAMPLES, where the per-lane tables are still
    written. If this ever fails, that file alone has outgrown this design
    (the spec's "Chosen: A").

    The indexes are a distance-3 code, so the report is not swamped by
    collision errors. A handful remain, which makes this bound conservative:
    a report of a run that passes the checks is smaller, and only a run that
    passes can be stored at all.
    """

    @staticmethod
    def _index(n: int, offset: int = 0) -> str:
        """Four base-4 symbols repeated three times: any two differ in at
        least three of the twelve bases."""
        symbols = [(n >> (2 * k)) % 4 for k in range(4)]
        return "".join("ACGT"[(s + offset) % 4] for s in symbols) * 3

    def test_eight_lanes_of_two_hundred_long_named_samples(self):
        from seqsetup.models.index import Index, IndexPair, IndexType
        from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles
        from seqsetup.services.validation import ValidationService, clear_validation_cache
        from seqsetup.services.validation_report import ValidationReportJSON

        run = SequencingRun(
            run_name="Worst case", instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B", run_cycles=RunCycles(151, 151, 12, 12),
        )
        for lane in range(1, 9):
            for n in range(200):
                stem = f"S{lane}-{n}-"
                run.add_sample(Sample(
                    sample_id=stem + "x" * (256 - len(stem)), lanes=[lane],
                    index_pair=IndexPair(
                        id=f"p{lane}-{n}", name=f"p{lane}-{n}",
                        index1=Index(name="i7", sequence=self._index(n),
                                     index_type=IndexType.I7),
                        index2=Index(name="i5", sequence=self._index(n, 1),
                                     index_type=IndexType.I5)),
                ))

        clear_validation_cache()
        result = ValidationService.validate_run(
            run, test_profile_repo=None, app_profile_repo=None, instrument_config=None)
        report = ValidationReportJSON.export(run, result)

        size = len(report.encode("utf-8"))
        assert size < MAX_EXPORT_FILE - EXPORT_FILE_MARGIN, (
            f"the check report's JSON is {size / 1024 / 1024:.1f} MB: this file has "
            f"outgrown one MongoDB document and must move to its own storage")
        # It really is the big one: well over half the budget, so a change
        # that doubles it (the heatmap cap raised, another table added) fails
        # the line above rather than surprising a lab.
        assert size > (MAX_EXPORT_FILE - EXPORT_FILE_MARGIN) / 2, (
            f"only {size / 1024 / 1024:.1f} MB: has the report stopped writing its "
            f"per-lane tables? Then this test no longer measures the worst case")


class TestTheRunDocumentIsStillMeasured:
    """The run document's own limit stays: it no longer carries the files,
    but a run with very many samples could still outgrow it, and the driver
    must not be the one to say so."""

    def test_the_measurement_is_the_bytes_the_repository_writes(self, fresh_app):
        """Nothing else now drives a genuinely oversized run document through
        the real measurement -- the oversized report trips the per-file gate
        first -- so this pins that ``_ready_document_size`` measures the same
        document ``RunRepository.save`` stores (review 2, P3-6)."""
        from seqsetup.routes.runs import _ready_document_size
        _app, ctx, _db = fresh_app
        run_id = seed_run(ctx, "measured", samples=4)
        run = ctx.run_repo.get_by_id(run_id)
        run.run_description = "x" * 4000
        ctx.run_repo.save(run)

        stored = ctx.run_repo.collection.find_one({"_id": run_id})

        assert _ready_document_size(ctx.run_repo.get_by_id(run_id)) == len(BSON.encode(stored))

    def test_a_run_document_over_the_limit_is_refused_with_its_own_message(
            self, logged_in_client, mongo_limit, monkeypatch):
        from seqsetup.routes import runs as runs_module
        ctx = mongo_limit
        run_id = seed_run(ctx, "document-too-big")
        monkeypatch.setattr(runs_module, "_ready_document_size", lambda run: 20 * 1024 * 1024)

        resp = mark_ready(logged_in_client, run_id, ORIGIN)

        assert resp.headers.get("HX-Retarget") == "#ready-message", dict(resp.headers)
        assert "Ready record would be 20.0 MB" in resp.text, resp.text[:600]
        assert ctx.run_repo.get_by_id(run_id).status == RunStatus.DRAFT
        assert "ready_document_too_large" in [r.get("reason") for r in _audit_rows(ctx, run_id)]
