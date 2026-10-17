# A listing reads only what it shows

Decision: 2026-10-17.

## The defect

`RunRepository.list_by_status` and `list_all_readable` load every run document
in full and build a whole `SequencingRun` from each — every sample, every
setting — to show a name, a status and a date.

- the dashboard, its three status tabs and its search (`routes/dashboard.py`),
- `/served-runs`, the API Exports list (`routes/served_runs.py`),
- `GET /api/runs` (`api/app.py`), which applies its `limit` **after** loading
  everything.

Since 2026-10-16 a Ready run's export files are their own records and the run
carries only a small manifest, which cut the bytes a lot. What is left is the
samples. Measured on `a9c5038` (mongomock), 300 Ready runs:

| | one document | all | `list_by_status` | peak |
|---|---|---|---|---|
| 96 samples | 70 KiB | 20.5 MiB | 3.07 s | 68 MiB |
| 384 samples | 278 KiB | 81.4 MiB | 12.22 s | 269 MiB |

and end to end at 96 samples: `GET /api/runs?limit=1` 1.06 s, `GET /` 0.91 s,
the search 0.85 s, `/served-runs` 0.91 s — about 21 MB a request, which the
search asks for again on every typing pause. It grows with every run ever made.
**No wrong sheet**: this is memory, latency, and eventually an out-of-memory
kill of the one process that serves everyone.

## The decision: a summary type

A listing query asks the database for the fields it shows and nothing else, and
returns a small **frozen** `RunListing` (`models/run_listing.py`) — **not** a
`SequencingRun`. `run_repo.save` cannot take one, so no listing can write a run
back without its samples or its export manifest. Sorting, the status filter,
the search's match and the API's limit are done in the database.

It is called `RunListing`, not `RunSummary`, because `api/schemas.py` already
has a `RunSummary` — the JSON DTO the API returns. Two types of one name in one
request path is how a wrong field gets served.

### What a listing reads

`RunListing.FIELDS` is the projection: `_id`, `id`, `run_name`, `status`,
`was_ready`, `created_by`, `updated_by`, `created_at`, `updated_at`,
`instrument_platform`, `flowcell_type`, `sheet_targets`, plus `sample_count`,
computed **in the database** as `{$size: {$ifNull: ["$samples", []]}}`.

`samples` is never read, and neither is any other large field — the four
`generated_*` fields, `exports`, `analyses`, `run_description`. The one
exception is the dashboard **search**, which searches sample IDs: it projects
`samples.sample_id` and nothing else of a sample, because that is the field it
matches on. `tests/unit/test_listings_read_only_what_they_show.py` asserts the
projection against the model's own field names, so a new field on
`SequencingRun` that a listing has not been taught about fails the test.

### Reading a document the same way the run does

`RunListing.from_doc` mirrors `SequencingRun.from_dict` exactly for the fields
it reads: `"complete"` still means archived, an unknown status still falls back
to DRAFT with a warning, an unknown instrument still falls back to NovaSeq X
with a warning, a missing or non-string timestamp still becomes `utcnow()`.
A listing must not disagree with the page it links to.

### Two methods, as today

- `list_summaries(status=None, *, newest_first=False, limit=None, skip=0)` —
  **raises** on a document whose summary cannot be built, as `list_by_status`
  does today. `GET /api/runs` and `/served-runs` use it, so a run is never
  quietly missing from what an external clinical consumer receives.
- `list_readable_summaries()` — returns `(listings, unreadable ids)`, as
  `list_all_readable` does today. The dashboard uses it and names the ids.
- `search_summaries(query)` — the match in the database, returning the listings
  and, per run, the sample IDs that matched.
- `count_summaries(status)` — the API's `total`, counted in the database.

`list_by_status` and `list_all_readable` stay for whoever needs whole runs.

### The one behaviour change

Today a listing that cannot build a run names it: the dashboard lists its id as
unreadable, and `GET /api/runs` fails loudly — deliberately. A summary that does
not read the samples cannot see a bad **sample**.

- Everything the summary **does** read keeps both guarantees: a bad
  `created_at`, a bad id — the dashboard still names the run, the API list
  still fails loudly, and no run is dropped and no list quietly shortened.
- A run whose summary reads but whose **samples** do not is now **listed**.
  Opening it still fails exactly as it does today.

This is recorded because it is a change, not an accident:
`tests/integration/test_listing_behaviour.py` pins both halves.

## What proves it

1. `tests/unit/test_listings_read_only_what_they_show.py` — the projection of
   every listing, asserted against `SequencingRun`'s own field names.
2. The API's limit is applied in the database: with 50 Ready runs,
   `GET /api/runs?limit=1` builds exactly one `RunListing` (counted, not timed).
3. Nothing can be erased: every listing over a Ready run leaves the stored
   document byte-identical, and `run_repo.save(a RunListing)` raises `TypeError`
   — a guard in the repository, so it cannot be forgotten.
4. The listings show the same rows in the same order as before, across every
   status (including archived, the legacy `complete`, an old-shape document and
   a run with no samples), compared field by field against the old code's
   output.
5. Asserted ceilings on the bytes read and the objects built.
6. Once, by hand, against a real `mongo:7`: mongomock is not MongoDB, so the
   projection and the `$size` aggregation are run against both and compared.
