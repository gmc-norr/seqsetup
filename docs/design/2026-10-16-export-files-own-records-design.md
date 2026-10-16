# A Ready run's export files in their own records

Finding F6 of the outside review of `f490536` (the real fix; the interim
refusal is in `update_status`), and most of F11. The user chose this on
2026-10-16, before the first deployment.

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
  The sheets check stays `78 checked, 0 differ, 0 refused`.

## Options

**A. A `run_exports` collection, one document per file, with a checksum.**
The run document keeps a small manifest. Each file has its own 16 MiB, and
the PDF is stored as binary, not base64. Needs nothing new from MongoDB or
the driver.

**B. GridFS.** No size limit at all, but a second storage mechanism to know,
back up and restore, a streaming read where today there is one document
read, and nothing gained until a single file passes 16 MiB. The largest
single file measured is the 10.7 MB PDF.

**C. Keep the files in the run document, compressed.** Buys a factor of
about 1.5 on the PDF and nothing on the per-lane growth; the listing still
loads every byte. Does not fix F11.

## Chosen: A

It is the smallest change that removes the limit for every measured run and
fixes the listing size, with no new storage mechanism. If a single file is
ever measured above the limit (the validation JSON grows with the per-lane
tables), that is the signal for B, for that file only.

## The design

### The collection

`run_exports`, one document per file:

```
{_id: <32 hex>, run_id, kind, content, sha256, size, created_at, created_by}
```

- `kind` is one of `samplesheet_v2`, `samplesheet_v1`, `json`,
  `validation_json`, `validation_pdf`.
- `content` is the text for the first four and BSON binary for the PDF.
- `sha256` is the hex SHA-256 of the file's bytes (the text as UTF-8), and
  `size` their length.
- **Only ever inserted.** The application never updates or deletes a file
  document. A file is immutable once written, so a manifest that names it
  always names the same bytes, and a deleted run's kept copy, an archived run
  and a run sent back to Draft never lose anything they point at.

`RunExportRepository` (`repositories/run_export_repo.py`) is a thin data
layer: `insert(doc)` and `get(file_id)`. It contains no business logic.

### The run document

A new field, `exports: dict` — kind → `{"id", "sha256", "size"}` — checked on
every assignment (`SequencingRun.__setattr__`): only the five kinds, a
32-hex id, a 64-hex sha256, a whole-number size. Empty on a Draft.

The five `generated_*` fields stay, read-only in practice: they are how a run
stored before this change carries its files. A run marked Ready by this
release never sets them.

### Mark Ready

In `update_status`, unchanged up to the last refusal check (the edit lock,
the sync note, the inputs version). Then:

1. **Measure first.** Build every file document and measure its BSON size;
   measure the run document with its manifest. If any is over 16 MiB less a
   margin, refuse as the interim refusal does today (its message, audit row
   and HTMX target), **before anything is written**.
2. **Write the files**, one `insert` each.
3. **Read each back** by id and compare its sha256 and size with what was
   generated. A mismatch refuses Mark Ready (500, "the exports could not be
   stored"), audited, with the run still a Draft.
4. **Save the run** in `saving_run`: status Ready, the manifest, the legacy
   fields None, and the rest exactly as now (`samplesheet_v1_withheld`,
   `test_versions_used`, `sheet_targets`).

Files written by an attempt that then fails (a version conflict, a refusal
in step 3) are referenced by nothing. They are left in place, never deleted,
and their ids are logged with the run id. Nothing ever serves an unreferenced
file.

### READY→DRAFT, READY→ARCHIVED, delete

- READY→DRAFT sets `exports = {}` and the legacy fields to None, as now. The
  files stay. A re-promotion writes new files with new ids.
- READY→ARCHIVED keeps the manifest.
- Deleting a run keeps its files; the kept copy holds the manifest.

### Reading — one function for every reader

`read_export(ctx, run, kind)` in `services/run_exports.py` returns the file's
text (bytes for the PDF), or None when the run has no such file:

- **The manifest names the file:** load it by id. Missing, another run's,
  another kind, or a sha256 or size that does not match the manifest →
  raise `ExportDamaged`. **No fallback** to a legacy field or to a live
  re-export: a damaged stored file is refused, never replaced.
- **The manifest does not name it:** the legacy field (a run stored before
  this change), exactly as today.

Every reader goes through it: the five UI downloads (`routes/export.py`,
whose live fallback for runs from before pre-generation stays as it is), the
five API endpoints (`api/app.py`), and the API Exports pages
(`routes/served_runs.py`). `ExportDamaged` answers 500 with a plain message
naming the file, and an audit row `run.export.damaged`.

`services/run_diff.py` ignores `exports`, as it ignores the `generated_*`
fields.

### Runs stored before this change

They keep their files inside the document and are served from there.
Nothing is migrated: reading both shapes is the safer choice, and costs one
branch in `read_export`.

## What proves it

1. **Same bytes as today.** For corpus runs on every instrument, Mark Ready
   through the route, then fetch every file through the UI download and the
   API: each is byte for byte what the exporters produce for that run.
2. **Ready is the last step.** Make each file insert fail in turn, and the
   read-back too: the run is still a Draft every time, and no export is
   served.
3. **The checksum bites.** Change a stored file's bytes, delete it, or point
   the manifest at another run's file: every reader refuses with 500 and an
   audit row, and never serves those bytes or a regenerated file.
4. **The size refusal, at the new ceiling.** A run whose files are each under
   the limit but together far over it (the 96-per-lane case) now goes Ready
   and serves every file. A single file over the limit is refused before
   anything is written.
5. **READY→DRAFT and back** writes new file ids; the old files are still
   there. **READY→ARCHIVED** keeps serving, also from a fresh app instance.
6. **A deleted run's copy** names files that still exist.
7. **An old-shape run** (files inside the document) serves the same bytes as
   before.
8. **The listing is small.** A Ready run's document no longer carries its
   files: measured before and after.
9. `sheets: 78 checked, 0 differ, 0 refused` throughout.

## Operators

`docs/getting-started/deployment.rst` (backups) and the admin guide say the
new collection holds every Ready run's files: a backup or restore must
include it, and a file removed by hand makes its run refuse to serve rather
than serve something else.
