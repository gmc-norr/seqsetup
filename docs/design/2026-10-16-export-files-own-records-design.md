# A Ready run's export files in their own records

Finding F6 of the outside review of `f490536` (the real fix; the interim
refusal is in `update_status`), and most of F11. The user chose this on
2026-10-16, before the first deployment. Revised the same day after a fresh
review of the first draft (no P1; its P2s and P3s are folded in below).

## The problem

Mark Ready writes five files and stores all of them **inside the run
document** (`models/sequencing_run.py`, the `generated_*` fields): Sample
Sheet v2, Sample Sheet v1, the JSON export, the validation report's JSON, and
its PDF, base64-encoded. MongoDB refuses a document over 16 MiB.

Measured by the verifier on real `mongo:7` (NovaSeq X 10B, 8 lanes, 0 errors):

| different samples per lane | Ready document | of 16 MiB |
|---|---|---|
| 64 | 11.7 MB | 70% |
| 88 | 17.6 MB | 105% |
| 96 | 18.9 MB | 112.8% |
| 192 | 32.1 MB | 191% |

At 96 per lane the document is `v2 78 KB · json 494 KB · validation json
3.5 MB · pdf 10.7 MB (14.2 MB as base64)`. Such a run cannot be marked Ready
at all; the interim refusal only says so clearly.

Each file on its own (the design review's measurement, 8 lanes, one 8-base
i7, in process):

| samples per lane | sample ID length | validation JSON | PDF |
|---|---|---|---|
| 96 | short | 3.5 MB | 10.7 MB (verifier) |
| 192 | 20 | 13.7 MiB | — |
| 200 | 20 | 14.8 MiB | — |
| 200 | 256 | **15.2 MiB** (95% of one file's limit) | 1.55 MiB |

The validation JSON is bounded only by `MAX_HEATMAP_SAMPLES = 200`
(`services/index_collision_validator.py`): above it the per-lane tables are
left out. The largest file is therefore close to one document's limit at the
worst case, and a test pins it (below).

Every listing also loads every Ready run's files (F11): 300 Ready runs of 96
samples are about 650 MB per listing request, to show names and dates.

## What must not change

- **A Ready run serves exactly the bytes its checks passed** (CLAUDE.md, Run
  state integrity). The API serves stored content, never a live re-export.
- **Ready is the last step.** A reader must never see a Ready run whose files
  are not all stored.
- **READY→DRAFT clears the exports, READY→ARCHIVED keeps them.** A
  re-promotion never adopts files from before the edit cycle.
- **A deleted run's kept copy stays complete** (`models/deleted_run.py`: the
  copy is the whole run document).
- **What the files say.** This changes where bytes live, never their content.

## Options

**A. A `run_exports` collection, one document per file, with a checksum.**
The run document keeps a small manifest. Each file has its own 16 MiB, and
the PDF is stored as binary, not base64. Needs nothing new from MongoDB or
the driver.

**B. GridFS.** No size limit at all, but a second storage mechanism to know,
back up and restore, a streaming read where today there is one document
read, and nothing gained until a single file passes 16 MiB.

**C. Keep the files in the run document, compressed.** Buys a factor of
about 1.5 on the PDF and nothing on the per-lane growth; the listing still
loads every byte. Does not fix F11.

## Chosen: A

It is the smallest change that removes the whole-record limit and fixes the
listing size, with no new storage mechanism. The one file that comes near a
single document's limit is the validation JSON at 200 samples per lane with
long IDs; if that test ever fails (the cap raised, the indent changed), that
file moves to B, alone.

## The design

### The collection

`run_exports`, one document per file:

```
{_id: <32 hex>, run_id, kind, content, sha256, size, created_at, created_by}
```

- `kind` is one of `samplesheet_v2`, `samplesheet_v1`, `json`,
  `validation_json`, `validation_pdf`.
- `content` is the text for the first four and plain `bytes` for the PDF
  (stored by the driver as BSON binary).
- `sha256` is the hex SHA-256 of the file's bytes (the text as UTF-8), and
  `size` their length.
- **Only ever inserted.** The application never updates or deletes a file
  document. A file is immutable once written, so a manifest that names it
  always names the same bytes, and a deleted run's kept copy, an archived run
  and a run sent back to Draft never lose anything they point at. Files of a
  deleted run's copy and of a Mark Ready that failed both look unreferenced:
  operators must never prune the collection.

`RunExportRepository` (`repositories/run_export_repo.py`) is a thin data
layer with `insert(doc)` (`insert_one`) and `get(file_id)` only. It does
**not** subclass `BaseRepository`, whose `save` (an upserting replace) and
`delete` would break the insert-only rule. It is a required repository in the
registry (`startup.py`) and in `AppContext` (not `Optional`), so a missing
repository cannot fall through to another path.

### The run document

A new field, `exports` — kind → `{"id", "sha256", "size"}` — checked on every
assignment (`SequencingRun.__setattr__`): only the five kinds, a 32-hex id, a
64-hex sha256, a whole-number size. It is stored as a read-only mapping and
only ever assigned whole, so `run.exports[kind] = …` cannot slip past the
check. Empty on a Draft. `exports` joins `_FINGERPRINT_IGNORED_KEYS`
(`routes/runs.py`) and the keys `services/run_diff.py` ignores.

The five `generated_*` fields stay: they are how a run stored before this
change carries its files. A run marked Ready by this release never sets them.

### Mark Ready

In `update_status`:

1. **Right after `_pregenerate_exports`** (before the re-fetch of the run and
   before the last refusal checks: the instrument switch, the edit lock, the
   sync note, the inputs version, which stay "just before saving"):
   - **Measure** every file document's BSON size, and refuse — before
     anything is written — when one is over 16 MiB less a margin. That
     refusal has its own message ("the check report's JSON for this run would
     be X MB; SeqSetup stores at most 16 MB in one file. This is a limit of
     SeqSetup, not a problem with the run…") and an audit row
     `run.status.denied`, reason `export_file_too_large`, with the kind and
     size.
   - **Write the files**, one insert each, and **read each back**, hashing
     the bytes that came back. A mismatch refuses Mark Ready (500, audited)
     with the run still a Draft. Its purpose: a run never goes Ready naming a
     file that cannot be served.
   - Keep the ids, hashes and sizes in local variables.
2. The re-fetch and the refusal checks, unchanged.
3. **Save the run** in `saving_run`, on the re-fetched run: status Ready, the
   whole manifest assigned at once (never merged into one already there), the
   legacy fields None, `samplesheet_v1_withheld`, `test_versions_used` as
   now, and `sheet_targets` built **from the v2 text that was written, and
   from the v1 text only when it was stored** (today it reads
   `run.generated_samplesheet_*`, which a new run no longer has). The run
   document's size is still measured, as the interim refusal does.

Files written by an attempt that then fails (any refusal after step 1, a
version conflict) are referenced by nothing, left in place, and logged with
the run id.

### READY→DRAFT, READY→ARCHIVED, delete

- READY→DRAFT sets `exports` to empty and the legacy fields to None, as now.
  The files stay. A re-promotion writes new files with new ids.
- READY→ARCHIVED keeps the manifest.
- Deleting a run keeps its files; the kept copy holds the manifest. Nothing
  reads files from a kept copy today.
- Duplicate and "new run from a template" copy a run field by field
  (`services/run_builder.py`), so no manifest goes with them.

### Reading — one function for every reader

`read_export(ctx, run, kind)` in `services/run_exports.py`:

- **The run has a manifest** (`exports` not empty): the manifest is the only
  source. A kind it names is loaded by id; missing, another run's, another
  kind, or **bytes whose SHA-256 or length is not the manifest's** (the
  function hashes the bytes it is about to serve; it does not compare stored
  fields) → raise `ExportDamaged`. A required kind the manifest does not name
  → `ExportDamaged` too: v2, json, validation_json and validation_pdf always;
  v1 when the instrument writes one and `samplesheet_v1_withheld` is empty.
  The legacy fields are **never read** and nothing is **generated live** for
  such a run.
- **The run has no manifest**: a run stored before this change. The legacy
  field, and the UI's live fallback for runs from before pre-generation, as
  today.

Every reader goes through it:

- the five UI downloads (`routes/export.py`), including the v1 "withheld"
  decision, which today looks at `run.generated_samplesheet_v1`;
- the five API endpoints (`api/app.py`);
- the API Exports pages (`routes/served_runs.py`), which show a damaged file
  on its own row rather than failing the whole page;
- the operator's tool `tools/check_broken_samplesheets.py`, which reads the
  stored v2 sheet from the database.

`ExportDamaged` answers 500 with a plain message naming the file, and an
audit row `run.export.damaged`. Each UI export route re-raises it ahead of its
catch-all `except Exception` (as `InstrumentRecordError` is), so it is never
reported as "failed to generate, try again".

A guard test (like `tests/unit/test_one_clock.py`) fails on any read of a
`generated_` field in `src/` or `tools/` outside the model, `read_export` and
the clearing on Return to Draft.

### Runs stored before this change

They keep their files inside the document and are served from there.
Nothing is migrated: reading both shapes is the safer choice, and costs one
branch in `read_export`.

## What proves it

1. **The bytes the checks passed are the bytes served.** For corpus runs on
   every instrument, Mark Ready through the route with a spy on each
   exporter, then fetch every file through the UI download and the API: each
   is byte for byte what that exporter returned during that Mark Ready. (Not
   a fresh export: the validation JSON and PDF carry their generation time.)
2. **Ready is the last step.** Make each file insert fail in turn, and the
   read-back: each time the run document is unchanged (still the Draft that
   was loaded) and the edit lock still held.
3. **The checksum bites.** Change a stored file's `content` while leaving its
   `sha256` and `size` fields as they were; delete a file; point the manifest
   at another run's file; drop a required kind from the manifest. Every
   reader refuses with 500 and an audit row, and never serves those bytes,
   a legacy field or a regenerated file.
4. **The size limits, enforced in the tests.** Mongomock accepts documents
   over 16 MiB, so the tests wrap the `runs` and `run_exports` collections to
   refuse a document over 16 MiB as MongoDB does. Under that wrapper: a run
   whose files are each under the limit but together far over it goes Ready
   and serves every file; a single file over the limit is refused before
   anything is written; and the worst case (8 lanes × 200 samples, 256-char
   sample IDs) keeps the validation JSON under the limit less the margin.
5. **READY→DRAFT and back** writes new file ids, and the old files are still
   there. A run Ready **with** a v1 sheet, sent back to Draft, changed so v1
   is withheld, and marked Ready again, serves no v1. **READY→ARCHIVED**
   keeps serving, also from a fresh app instance.
6. **A deleted run's copy** names files that still exist.
7. **An old-shape run** (files inside the document) serves the same bytes as
   before, through every reader.
8. **The listing is small.** A Ready run's document no longer carries its
   files: measured before and after.
9. **The existing tests that mean "nothing stored" or "cleared"** — about 46
   assertions of `generated_* is None` across the suite — are rewritten
   against `exports` and `read_export`, and each is break-tested: with the
   files inside the run document they would pass whatever happened.

The sheets check (`78 checked, 0 differ, 0 refused`) stays green, but it calls
the exporters directly and never stores or reads a file: it proves the files'
content did not change, nothing about where they live.

## Docs and rules to update

- CLAUDE.md, Run state integrity: the exports bullets (where they live, the
  manifest, insert-only, the reader refuses a damaged file).
- `routes/export.py`'s docstring; the encryption-at-rest note in
  `models/sequencing_run.py`.
- `docs/api-reference/runs.rst`: the new 500 for a damaged file.
- `docs/getting-started/deployment.rst` (backups) and the admin guide: the
  collection holds every Ready run's files; a backup or restore must include
  it; never prune it; a file removed by hand makes its run refuse to serve
  rather than serve something else.
- `docs/user-guide/export.rst`: the size paragraph (the whole-record limit
  goes; the one-file limit stays, with the measured numbers).
