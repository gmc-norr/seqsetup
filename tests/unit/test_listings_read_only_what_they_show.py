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

#: A projection may also compute a value. Each computed output is named
#: here with exactly the stored fields its expression may read, because an
#: expression is the other way a big field gets into a listing:
#: ``{"all_samples": {"$ifNull": ["$samples", []]}}`` returns every sample
#: while naming none. A new computed output, or an old one reading a new
#: field, fails this file until it is written down here.
COMPUTED = {
    # the number of samples, never the samples
    "sample_count": {"samples"},
    # the sort key: the stored time as text
    "_listing_sort": {"updated_at"},
}


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


def _referenced(value) -> set:
    """Every "$field" a computed projection expression reads.

    A field let in by name is obvious; one let in by expression —
    ``{"all_samples": {"$ifNull": ["$samples", []]}}`` — is not, and reads
    just as many bytes.
    """
    found = set()
    if isinstance(value, str) and value.startswith("$") and not value.startswith("$$"):
        found.add(value[1:])
    elif isinstance(value, dict):
        for key, inner in value.items():
            if not key.startswith("$"):
                found.add(key)
            found |= _referenced(inner)
    elif isinstance(value, (list, tuple)):
        for inner in value:
            found |= _referenced(inner)
    return found


def _projections(pipeline_or_projection):
    """Every projection in a pipeline, or the one passed to find()."""
    if isinstance(pipeline_or_projection, list):
        return [stage["$project"] for stage in pipeline_or_projection if "$project" in stage]
    return [pipeline_or_projection or {}]


def _returned_fields(projection):
    """The stored fields a projection sends back, named one by one."""
    return {key for key, value in projection.items() if not isinstance(value, (dict, list))}


def _computed_reads(projection):
    """Each computed output and the stored fields its expression reads."""
    return {key: _referenced(value) for key, value in projection.items()
            if isinstance(value, (dict, list))}


def _asked_by(repo, call):
    """The fields a listing sends back, after checking what it computes.

    A computed output must be one COMPUTED names, reading no more than
    COMPUTED allows it — so a big field cannot be smuggled in through an
    expression that names none of it.
    """
    call()
    found = []
    for _args, kwargs in repo.collection.finds:
        projection = kwargs.get("projection")
        if projection is None and len(_args) > 1:
            projection = _args[1]
        assert projection is not None, "a listing must project, not read whole documents"
        found.extend(_projections(projection))
    for pipeline in repo.collection.aggregates:
        found.extend(_projections(pipeline))
    assert found, "the listing read nothing at all"

    returned = set()
    for projection in found:
        returned |= _returned_fields(projection)
        for name, reads in _computed_reads(projection).items():
            assert name in COMPUTED, f"a computed projection {name!r} nobody wrote down"
            assert reads <= COMPUTED[name], (
                f"{name!r} reads {sorted(reads - COMPUTED[name])}, which it may not")
    return returned


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


class TestTheGuardItselfCatchesSmuggling:
    """A field let in by expression reads as many bytes as one let in by
    name; the guard above must see both."""

    def _asked(self, repo, projection):
        repo.collection.aggregates.clear()
        repo.collection.finds.clear()
        list(repo.collection.aggregate([{"$project": projection}]))
        return _asked_by(repo, lambda: None)

    def test_a_field_let_in_by_name_is_caught(self, repo):
        asked = self._asked(repo, {"run_name": 1, "samples": 1})
        assert "samples" in asked, "a named field must show up"

    @pytest.mark.parametrize("projection", [
        {"all_samples": {"$ifNull": ["$samples", []]}},
        {"first_sample": {"$arrayElemAt": [{"$ifNull": ["$samples", []]}, 0]}},
        {"stored_sheet": {"$ifNull": ["$generated_samplesheet_v2", ""]}},
        {"sample_count": {"$concat": ["$run_description", "x"]}},
    ])
    def test_a_field_let_in_by_expression_is_caught(self, repo, projection):
        with pytest.raises(AssertionError):
            self._asked(repo, projection)


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
        assert {"$sort": {"_listing_sort": -1, "_id": 1}} in stages
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


class TestTheOrderIsTheStoredTimeAsText:
    """SeqSetup always writes an ISO string, but a direct database write may
    leave a real BSON date. The database sorts every date before every
    string, so without a text sort key such a run jumps to the front of
    every page — and of every API page, which moves the boundaries a paging
    client reads."""

    @pytest.fixture
    def dated(self):
        import datetime
        db = mongomock.MongoClient()["dated"]
        repository = RunRepository(db)
        for k, when in enumerate(("2026-01-01T00:00:00", "2020-01-01T00:00:00")):
            run = _run(k)
            repository.save(run)
            db.runs.update_one({"_id": run.id}, {"$set": {"updated_at": when}})
        old = _run(9)
        repository.save(old)
        db.runs.update_one({"_id": old.id},
                           {"$set": {"updated_at": datetime.datetime(2021, 1, 1)}})
        return repository

    def test_a_stored_date_keeps_its_place(self, dated):
        order = [listing.id for listing in dated.list_summaries("ready", newest_first=True)]
        assert order == ["r0", "r9", "r1"], (
            "2026 first, then the 2021 date, then 2020 — a date sorting first "
            "would mean the sort key was not text")

    def test_the_row_still_carries_the_date(self, dated):
        (row,) = [x for x in dated.list_summaries("ready") if x.id == "r9"]
        assert row.updated_at.year == 2021


class TestARowIsNeverListedWithNoReasonGiven:
    """The database picks the rows with a regular expression; the "Samples:"
    hint under a row must be found with the same pattern. Two rules disagree
    on a handful of letters — a long s folds to S for a regular expression
    but not for str.lower() — and the row would then be listed with nothing
    to show for it."""

    @pytest.fixture
    def folded(self):
        from seqsetup.models.sample import Sample
        db = mongomock.MongoClient()["folded"]
        repository = RunRepository(db)
        run = SequencingRun(id="fold", run_name="Nothing to see", flowcell_type="10B")
        run.add_sample(Sample(sample_id="PATıSTANBUL", lanes=[1]))
        run.add_sample(Sample(sample_id="MEAſURE-1", lanes=[1]))
        run.status = RunStatus.READY
        repository.save(run)
        return repository

    @pytest.mark.parametrize("query", ["meas", "MEAS"])
    def test_the_hint_names_the_sample_the_row_was_picked_for(self, folded, query):
        listings, matched = folded.search_summaries(query)
        assert [listing.id for listing in listings] == ["fold"], (
            f"{query!r} should pick the run whose sample folds to it")
        assert matched["fold"] == ["MEAſURE-1"], (
            "a row picked by the database's pattern must say which sample matched")
