"""What a listing of 300 Ready runs costs.

docs/design/2026-10-17-listing-summaries-design.md. Measured on `a9c5038`
with mongomock, 300 Ready runs of 96 samples: one document 70 KiB, 20.5 MiB
in all, `list_by_status` 3.07 s, 68 MiB peak; at 384 samples 278 KiB, 81.4
MiB, 12.22 s, 269 MiB.

The bytes and the object counts below are exact and deterministic — they are
the assertions. Time is not asserted: the suite runs twelve ways at once.
"""

import bson
import mongomock
import pytest

from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.run_listing import RunListing
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import (
    InstrumentPlatform, RunCycles, RunStatus, SequencingRun,
)
from seqsetup.repositories.run_repo import RunRepository

RUNS = 300
SAMPLES = 96

#: A listing of 300 runs of 96 samples may read this much. The whole
#: documents are 20.5 MiB; a row is a name, a status, a date and a count.
MAX_KIB_READ = 256
#: The search reads one field of each sample as well.
MAX_KIB_READ_SEARCHING = 2048


@pytest.fixture(scope="module")
def repo():
    db = mongomock.MongoClient()["ceiling"]
    repository = RunRepository(db)
    docs = []
    for k in range(RUNS):
        run = SequencingRun(
            id=f"run-{k:04d}", run_name=f"Run {k:04d}",
            instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
            run_cycles=RunCycles(151, 151, 10, 10))
        for i in range(SAMPLES):
            run.add_sample(Sample(
                sample_id=f"PAT{k:04d}-{i:04d}", sample_name=f"name-{i}", project="PROJ-1",
                test_id="WGS", test_version="1", worksheet_id="WS-1", lanes=[1, 2],
                index_pair=IndexPair(
                    id=f"p{i}", name=f"p{i}",
                    index1=Index(name=f"i7-{i}", sequence="ACGTACGTAC", index_type=IndexType.I7),
                    index2=Index(name=f"i5-{i}", sequence="TGCATGCATG", index_type=IndexType.I5))))
        run.status = RunStatus.READY
        doc = run.to_dict()
        doc["_id"] = doc["id"]
        docs.append(doc)
    db.runs.insert_many(docs)
    repository._whole_documents_kib = sum(len(bson.encode(doc)) for doc in docs) / 1024
    return repository


def _kib_read(repo, call):
    """The bytes a real MongoDB would send back for this listing."""
    read = {"total": 0}
    inner = repo.collection.aggregate

    def counting(pipeline, *args, **kwargs):
        docs = list(inner(pipeline, *args, **kwargs))
        read["total"] += sum(len(bson.encode(doc)) for doc in docs)
        return iter(docs)

    repo.collection.aggregate = counting
    try:
        result = call()
    finally:
        repo.collection.aggregate = inner
    return result, read["total"] / 1024


class TestTheWholeDocumentsAreBig:
    def test_the_before_number_is_what_the_design_note_says(self, repo):
        assert repo._whole_documents_kib > 15 * 1024, (
            f"{repo._whole_documents_kib / 1024:.1f} MiB of run documents")


class TestAListingStaysSmall:

    def test_listing_every_ready_run_reads_little(self, repo):
        listings, kib = _kib_read(repo, lambda: repo.list_summaries("ready"))
        assert len(listings) == RUNS
        assert all(listing.sample_count == SAMPLES for listing in listings)
        assert kib <= MAX_KIB_READ, f"a listing read {kib:.0f} KiB"

    def test_the_dashboard_listing_reads_little(self, repo):
        (listings, unreadable), kib = _kib_read(repo, repo.list_readable_summaries)
        assert len(listings) == RUNS and unreadable == []
        assert kib <= MAX_KIB_READ, f"the dashboard read {kib:.0f} KiB"

    def test_a_limit_reads_one_document(self, repo):
        listings, kib = _kib_read(
            repo, lambda: repo.list_summaries("ready", newest_first=True, limit=1))
        assert len(listings) == 1
        assert kib <= MAX_KIB_READ / RUNS * 4, f"a limit of one read {kib:.1f} KiB"

    def test_the_search_reads_only_the_sample_ids(self, repo):
        (listings, matched), kib = _kib_read(
            repo, lambda: repo.search_summaries("PAT0007-0042"))
        assert [listing.id for listing in listings] == ["run-0007"]
        assert matched["run-0007"] == ["PAT0007-0042"]
        assert kib <= MAX_KIB_READ_SEARCHING, f"the search read {kib:.0f} KiB"

    def test_no_whole_run_is_ever_built(self, repo, monkeypatch):
        def refuse(*_args, **_kwargs):
            raise AssertionError("a listing built a whole SequencingRun")
        monkeypatch.setattr(SequencingRun, "from_dict", classmethod(refuse))
        assert len(repo.list_summaries("ready")) == RUNS
        assert len(repo.list_readable_summaries()[0]) == RUNS
        assert len(repo.search_summaries("Run 0001")[0]) == 1
        assert repo.count_summaries("ready") == RUNS

    def test_every_row_is_a_listing(self, repo):
        assert all(isinstance(listing, RunListing)
                   for listing in repo.list_summaries("ready", limit=5))
