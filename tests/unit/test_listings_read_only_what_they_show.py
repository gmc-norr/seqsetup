"""A listing reads the fields it shows, and nothing else.

docs/design/2026-10-17-listing-summaries-design.md. The dashboard, its tabs,
its search, /served-runs and GET /api/runs used to load every run document in
full — every sample — to show a name, a status and a date. They now ask the
database for a summary.

The allowed field names are checked against ``SequencingRun``'s own, so a
field added to the model and then let into a listing fails this file.
"""

import dataclasses

import mongomock
import pytest

from seqsetup.models.run_listing import RunListing
from seqsetup.models.sequencing_run import RunStatus, SequencingRun
from seqsetup.repositories.run_repo import RunRepository


#: What a listing is allowed to read of a run. Everything else on the model —
#: the samples, the analyses, the export manifest, the description — is big,
#: or grows, or both.
ALLOWED_FIELDS = {
    "id", "run_name", "status", "was_ready", "created_by", "updated_by",
    "created_at", "updated_at", "instrument_platform", "flowcell_type",
    "sheet_targets",
}

#: The search matches sample IDs, so it reads that one field of each sample
#: and no other.
SEARCH_EXTRA = {"samples.sample_id"}


class SpyCollection:
    """Records every find/aggregate, then does it."""

    def __init__(self, inner):
        self._inner = inner
        self.finds = []
        self.aggregates = []

    def find(self, *args, **kwargs):
        self.finds.append((args, kwargs))
        return self._inner.find(*args, **kwargs)

    def aggregate(self, pipeline, *args, **kwargs):
        self.aggregates.append(pipeline)
        return self._inner.aggregate(pipeline, *args, **kwargs)

    def count_documents(self, *args, **kwargs):
        return self._inner.count_documents(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._inner, name)


def _run(k, status=RunStatus.READY, samples=0):
    from seqsetup.models.sample import Sample
    run = SequencingRun(id=f"r{k}", run_name=f"Run {k}", flowcell_type="10B")
    for i in range(samples):
        run.add_sample(Sample(sample_id=f"S{k}-{i}", lanes=[1]))
    run.status = status
    return run


@pytest.fixture
def repo():
    db = mongomock.MongoClient()["listings"]
    repository = RunRepository(db)
    for k in range(4):
        repository.save(_run(k, samples=2))
    repository.save(_run(9, status=RunStatus.DRAFT, samples=1))
    repository.collection = SpyCollection(repository.collection)
    return repository


def _read_fields(pipeline_or_projection):
    """The document fields a projection or pipeline asks for."""
    if isinstance(pipeline_or_projection, list):
        asked = set()
        for stage in pipeline_or_projection:
            for key, value in stage.get("$project", {}).items():
                if isinstance(value, dict):
                    continue  # computed, e.g. sample_count from $size
                asked.add(key)
        return asked
    return {key for key, value in (pipeline_or_projection or {}).items()
            if not isinstance(value, dict)}


def _asked_by(repo, call):
    call()
    asked = set()
    for _args, kwargs in repo.collection.finds:
        projection = kwargs.get("projection")
        if projection is None and len(_args) > 1:
            projection = _args[1]
        assert projection is not None, "a listing must project, not read whole documents"
        asked |= _read_fields(projection)
    for pipeline in repo.collection.aggregates:
        asked |= _read_fields(pipeline)
    assert asked, "the listing read nothing at all"
    return asked


class TestTheAllowListIsAboutTheRealModel:

    def test_every_allowed_name_is_a_field_of_the_run(self):
        model_fields = {f.name for f in dataclasses.fields(SequencingRun)}
        assert ALLOWED_FIELDS <= model_fields, ALLOWED_FIELDS - model_fields

    def test_the_summary_carries_no_field_the_run_does_not_have(self):
        model_fields = {f.name for f in dataclasses.fields(SequencingRun)}
        listing_fields = {f.name for f in dataclasses.fields(RunListing)}
        assert listing_fields - {"sample_count"} <= model_fields


class TestNoListingReadsASample:

    @pytest.mark.parametrize("name,call", [
        ("list_summaries", lambda r: r.list_summaries()),
        ("list_summaries by status", lambda r: r.list_summaries("ready")),
        ("list_summaries limited", lambda r: r.list_summaries("ready", newest_first=True, limit=1)),
        ("list_readable_summaries", lambda r: r.list_readable_summaries()),
    ])
    def test_it_reads_only_the_allowed_fields(self, repo, name, call):
        asked = _asked_by(repo, lambda: call(repo))
        assert asked - {"_id"} <= ALLOWED_FIELDS, f"{name} also reads {asked - ALLOWED_FIELDS - {'_id'}}"
        assert not any(key.startswith("samples") for key in asked), f"{name} reads samples"

    def test_the_search_reads_one_field_of_each_sample_and_no_other(self, repo):
        asked = _asked_by(repo, lambda: repo.search_summaries("run"))
        sample_keys = {key for key in asked if key.startswith("samples")}
        assert sample_keys == SEARCH_EXTRA, sample_keys
        assert asked - {"_id"} - SEARCH_EXTRA <= ALLOWED_FIELDS

    def test_counting_reads_no_document_at_all(self, repo):
        repo.count_summaries("ready")
        assert repo.collection.finds == []
        assert repo.collection.aggregates == []


class TestTheDatabaseDoesTheWork:

    def test_the_status_filter_is_a_query(self, repo):
        repo.list_summaries("ready")
        stages = [stage for pipeline in repo.collection.aggregates for stage in pipeline]
        assert {"$match": {"status": "ready"}} in stages

    def test_the_limit_is_a_stage(self, repo):
        repo.list_summaries("ready", newest_first=True, limit=1, skip=2)
        stages = [stage for pipeline in repo.collection.aggregates for stage in pipeline]
        assert {"$limit": 1} in stages
        assert {"$skip": 2} in stages
        assert {"$sort": {"_listing_sort": -1}} in stages
        # The sort key is the stored updated_at, or now when there is none —
        # what SequencingRun.from_dict gives such a run, so the order does
        # not change.
        projections = [stage["$project"] for stage in stages if "$project" in stage]
        assert any("$ifNull" in str(p.get("_listing_sort")) for p in projections)

    def test_a_limit_builds_only_that_many_summaries(self, repo):
        for k in range(10, 60):
            run = _run(k, samples=1)
            run._loaded_updated_at = None
            RunRepository.save(repo, run)
        repo.collection.finds.clear()
        repo.collection.aggregates.clear()
        listings = repo.list_summaries("ready", newest_first=True, limit=1)
        assert len(listings) == 1

    def test_the_search_matches_in_the_database(self, repo):
        repo.search_summaries("S1-0")
        stages = [stage for pipeline in repo.collection.aggregates for stage in pipeline]
        matches = [stage["$match"] for stage in stages if "$match" in stage]
        assert matches, "the search must match in the database"
        assert any("$or" in match for match in matches)


class TestASummaryCannotBeSaved:

    def test_save_refuses_a_listing(self, repo):
        listing = repo.list_summaries("ready")[0]
        with pytest.raises(TypeError, match="RunListing"):
            repo.save(listing)

    def test_delete_if_unchanged_refuses_a_listing(self, repo):
        listing = repo.list_summaries("ready")[0]
        with pytest.raises(TypeError, match="RunListing"):
            repo.delete_if_unchanged(listing)

    def test_a_listing_cannot_be_turned_into_a_document(self, repo):
        listing = repo.list_summaries("ready")[0]
        assert not hasattr(listing, "to_dict")
        assert not hasattr(listing, "samples")

    def test_a_listing_is_frozen(self, repo):
        listing = repo.list_summaries("ready")[0]
        with pytest.raises(dataclasses.FrozenInstanceError):
            listing.run_name = "changed"
