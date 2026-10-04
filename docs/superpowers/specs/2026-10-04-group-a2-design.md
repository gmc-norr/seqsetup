# Group A2: the i5 direction follows the instrument, the workflow and the reader — design

## Why

Four findings from the 2026-10-03 project review, and one the user raised:

1. **The read direction is wrong for four instruments** (review S-4). The instrument files
   say NextSeq 500/550, NextSeq 1000/2000, MiniSeq and MiSeq i100 read the i5 forward.
   Illumina says they read it as its reverse complement (with their standard kits and
   workflow). The read direction drives the dark-start check (which stops Mark Ready) and
   the colour-balance check, so on these four instruments both look at the wrong end of
   the i5: a real dark start is missed, and a good index is refused. No Sample Sheet is
   affected: the v2 writer uses a separate setting, and the v1 writer (which uses the read
   direction) only serves MiSeq and NovaSeq 6000.
2. **One direction per instrument cannot follow the kit or the run mode** (raised by the
   user). MiniSeq reads the i5 forward with Rapid kits and reversed with standard kits;
   MiSeq i100 reads it forward in index-first runs and reversed in read-first runs;
   NovaSeq 6000 reads it forward with v1.0 reagents and reversed with v1.5.
3. **A synced instrument guesses its sheet direction** (E-1, found during the Sample Sheet
   follow-ups). A synced file that gives `i5_read_orientation` but not
   `samplesheet_v2_i5_orientation` writes the i5 forward (the model's default), while the
   same entry in the local file falls back to the read direction.
4. **The v2 header always says `IndexOrientation,Forward`** (review S-7), even on sheets
   whose i5 sequences are written reversed. Illumina's Run Planning and its BaseSpace BCL
   Convert app read that line as "these i5s are forward; reverse them as needed".
5. **One unreadable synced instrument record switches every lookup to the local file**
   (review H-2). `_get_synced_instruments` catches the error, logs a WARNING and returns
   nothing, so every instrument (its i5 direction, flow cells, checks) silently comes from
   `config/instruments.yaml` instead of what the lab synced.

## What Illumina says (the basis for the rule)

- **How each instrument reads the i5** ([Indexed Sequencing Overview for Paired-End Flow
  Cells](https://knowledge.illumina.com/library-preparation/general/library-preparation-general-reference_material-list/000002099)):
  forward with NovaSeq 6000 v1 reagents, MiniSeq Rapid kits and MiSeq; reverse complement
  with MiSeq i100 (read-first), iSeq 100, MiniSeq standard kits, NextSeq 500/550,
  NextSeq 1000/2000, NovaSeq 6000 v1.5 reagents and NovaSeq X.
- **MiSeq i100** ([Considerations for index color balancing on the MiSeq i100
  Series](https://knowledge.illumina.com/instrumentation/miseq-i100-series/instrumentation-miseq-i100-series-reference_material-list/000009405)):
  read-first is the standard strategy and reads the i5 reversed; index-first is an option
  and reads both index reads forward.
- **What BCL Convert expects in the sheet** ([DRAGEN v4.5 BCL
  conversion](https://help.dragen.illumina.com/dragen-v4.5/product-guides/dragen-v4.5/bcl-conversion)):
  every barcode is taken as forward, and reversed during processing, only when the run's
  `RunInfo.xml` has an `isReverseComplement` tag on the read (with any value) or
  `OverrideReads` is set. Otherwise the Index2 column is compared with the bases as read.
  The page does not mention `IndexOrientation`.
- **The resulting table** ([i5 Index Orientation
  Table](https://help.connected.illumina.com/run-set-up/overview/index-orientation-guide/i5-index-orientation-table)):
  standalone BCL Convert wants the i5 forward for NextSeq 1000/2000, NovaSeq X and MiSeq
  i100, and reversed for MiniSeq, iSeq 100, NextSeq 500/550 and NovaSeq 6000; forward for
  MiSeq; MiniSeq Rapid kits always forward. bcl2fastq wants it as read. Onboard DRAGEN
  (NovaSeq X, MiSeq i100, NextSeq 1000/2000) wants it forward, the same as standalone BCL
  Convert, so one sheet works for both.

## Decisions

Approved by the user on 2026-10-04:

1. **A generic rule from two facts**, instead of an instrument file stating the sheet
   direction: how the instrument reads the i5 in the run's workflow, and whether its
   `RunInfo.xml` marks the i5 read. SeqSetup is a tool for any lab, not one lab's
   instruments.
2. **Every workflow is supported.** Each instrument lists its i5 workflows; a run picks
   one; the first is the standard one.
3. **One mechanism**: the workflow list. A flow cell does not set a direction of its own.
4. **When the synced instrument records cannot be used, SeqSetup stops and says so.** It
   never falls back to the local file for them.

## 1. The instrument file

Each instrument (in `config/instruments.yaml`, in each synced file, and in
`config/instruments/*.yaml`) gives two facts about the i5:

```yaml
# How the instrument reads the i5, per workflow. The first one is the standard one.
i5_workflows:
  - name: Read-first
    i5_read_orientation: reverse-complement
  - name: Index-first
    i5_read_orientation: forward
# Does the instrument's RunInfo.xml mark the i5 read (isReverseComplement)?
runinfo_marks_i5_reversed: true
```

Rules, checked by `validate_instrument_yaml` (so both a config sync and the start-up check
of the local file apply them) and by `InstrumentDefinition` on every assignment:

- `i5_workflows` is required: a non-empty list. Each entry is a mapping with exactly the
  keys `name` and `i5_read_orientation`.
  - `name`: 1–64 characters, `[A-Za-z0-9][A-Za-z0-9 ._-]*`, unique within the instrument
    (ignoring case).
  - `i5_read_orientation`: `forward` or `reverse-complement`.
- `runinfo_marks_i5_reversed` is required: `true` or `false` (a YAML boolean, not text).
- The old keys are refused: a top-level `i5_read_orientation`, and
  `samplesheet_v2_i5_orientation`. The message says they were replaced by `i5_workflows`
  and `runinfo_marks_i5_reversed` and points to the admin guide. Nothing is guessed from
  them: an old file may carry a wrong read direction (as the shipped ones did, S-4).
- Every way in from a file or the database states both facts: `from_yaml` and `from_dict`
  refuse a record that lacks either. The model's own defaults (one forward workflow named
  "Standard", not marked: what today's defaults mean) serve only code that builds a record
  directly, such as tests.

The built-in instruments, in `config/instruments.yaml` and `config/instruments/*.yaml`:

| Instrument | `i5_workflows` (first = standard) | `runinfo_marks_i5_reversed` |
|---|---|---|
| MiSeq i100 Series | Read-first: reverse-complement; Index-first: forward | true |
| MiniSeq | Standard kits: reverse-complement; Rapid kits: forward | false |
| NovaSeq 6000 | v1.5 reagents: reverse-complement; v1.0 reagents: forward | false |
| NextSeq 500/550 | Standard: reverse-complement | false |
| HiSeq 4000 | Standard: reverse-complement | false |
| HiSeq X | Standard: reverse-complement | false |
| NextSeq 1000/2000 | Standard: reverse-complement | true |
| NovaSeq X Series | Standard: reverse-complement | true |
| MiSeq | Standard: forward | false |
| HiSeq 2000/2500 | Standard: forward | false |
| GAIIx | Standard: forward | false |

The wrong comment in `config/instruments.yaml` ("patterned flow cell geometry causes i5 to
be read as the reverse complement") is replaced by a short statement of the rule and links
to the Illumina pages above.

## 2. The rule

In `data/instruments.py`:

- **The run's workflow**: the workflow named by `run.i5_workflow`, or the instrument's
  first workflow when `run.i5_workflow` is empty. A name that the instrument does not list
  gives no workflow (never a guess).
- **Read direction** = the workflow's `i5_read_orientation`. It drives the dark-start and
  colour-balance checks, and the v1 sheet (bcl2fastq writes the i5 as read).
- **Sheet direction (v2)**: the i5 is written **reversed** when the workflow reads it
  reversed **and** the instrument's `runinfo_marks_i5_reversed` is false. Otherwise it is
  written **forward**.
- For the two v1 instruments (MiSeq, NovaSeq 6000), neither marks the i5 read, so the v1
  and v2 rules give the same direction.

`get_i5_read_orientation(_by_name)` and `get_samplesheet_v2_i5_orientation(_by_name)` are
replaced by functions that take the run (its instrument and workflow); every caller moves
to them. Nothing reads the old keys any more.

## 3. The run's workflow

- New run field `SequencingRun.i5_workflow: str = ""`. Empty means the instrument's
  standard (first) workflow. It is checked on every assignment like `flowcell_type`
  (at most 256 characters, no line breaks) and is saved in `to_dict`/`from_dict`. Because
  `_export_input_fingerprint` hashes `to_dict`, a workflow change during Mark Ready's
  export step is caught like any other input change.
- **Where it is picked**: a new select, `wizard/_i5_workflow_select.html`, placed after the
  flow cell in `wizard/_instrument_config.html` (the new-run wizard and the run's setup
  page). It is shown only when the instrument lists more than one workflow, with the run's
  workflow selected; the standard one is marked "(standard)". For every other instrument
  the page is unchanged.
- **Saving**: `POST /runs/{run_id}/i5-workflow`, behind `get_editable_run`, saved with
  `saving_run`. The value must be one of the instrument's workflow names; anything else is
  a 400 naming the instrument and its workflows. The chosen name is stored.
- **Changing the instrument** (`POST /runs/{run_id}/instrument`) sets `i5_workflow` back to
  empty and sends the new instrument's select (or nothing) out of band, the way the
  reagent-kit select is sent today.
- **Mark Ready**: when the run's `i5_workflow` is not empty and the instrument does not
  list it (the instrument files changed), validation reports an error and Mark Ready is
  refused: "<workflow> is not an i5 workflow of <instrument> (it has: <names>). Pick one in
  Run Setup." The dark-start and colour-balance checks do not run for that run, as there is
  no read direction. The writers refuse such a run too (`ValueError`), as a safety net.
- Templates do not carry a workflow: a run built from a template starts with the standard
  workflow, shown on the setup page.

## 4. What the sheets and checks do

- **v2 sheet**: the Index2 column and the Index2 part of `OverrideCycles` follow the sheet
  direction (today's code: reversed i5 sequence, and `I8N2` becomes `N2I8`).
- **v2 header**: `IndexOrientation,Forward` is written only when the sheet direction is
  forward; it is left out when the i5s are written reversed.
- **v1 sheet**: the i5 is written as the run's workflow reads it.
- **Dark-start and colour-balance checks**: they use the run's read direction.
- **JSON export**: unchanged.

With each built-in instrument's standard workflow, every Sample Sheet is byte for byte what
SeqSetup writes today, except that the `IndexOrientation,Forward` line is gone from the v2
sheets of MiniSeq, NextSeq 500/550, NovaSeq 6000, HiSeq 4000 and HiSeq X (their i5s are
written reversed). The checks change on NextSeq 500/550, NextSeq 1000/2000, MiniSeq and
MiSeq i100: some runs that pass today are refused (their i5 really does start dark as the
instrument reads it) and some refused today pass.

## 5. Synced instrument records that cannot be used (H-2)

- `_get_synced_instruments` no longer falls back. When reading the synced records fails
  for any reason (an unreadable document, an old-format record, a bad value), it raises a
  new `SyncedInstrumentsUnusable` error that carries the reason, and logs it. Nothing is
  cached while it fails, so the first lookup after a good sync works.
- `InstrumentDefinition.from_dict` refuses a stored record in the old format or with a bad
  value (the rules of section 1), naming the record and the problem.
- Other code that reads synced records directly treats a record it cannot load the same
  way (raises `SyncedInstrumentsUnusable`): the Mark Ready re-read of the instrument's
  on/off switch, and the admin Instruments page.
- One exception handler shows the error, like the existing `HTTPException` handler: an
  HTMX request gets the error fragment, a page gets the error page, status 503. The text:
  "The synced instrument settings cannot be used: <reason>. Update the instrument files
  and run a config sync (Admin > Config Sync)."
- Mark Ready is refused and nothing is saved (the error is raised during validation,
  before any export or save).
- When there are no synced records at all, the local file is used, as today.
- **The sync can always repair it.** Today the sync loads every stored record in full
  (`list_all`) to keep each instrument's on/off switch, so an old-format record would make
  the sync that fixes it fail. Instead it reads only each stored record's
  `samplesheet_name` and `enabled` fields, through a new repository method, then replaces
  the records as today.
- The admin Config Sync page does not read instrument settings (checked: it only clears the
  cache), so it keeps working while the records cannot be used.

## Docs

- `docs/admin-guide/instruments.rst`: the two facts and the rule, the new keys and their
  checks, the built-in table, the Illumina links, "the first workflow is the standard one;
  do not reorder (a run that never picked one uses the first)", and an **upgrade note**:
  instrument files in the old format are refused; a lab's own local file stops SeqSetup
  from starting until it is updated; synced files must be updated and synced, and until
  then pages say so and Mark Ready is refused.
- `docs/architecture/instruments.rst` and `docs/architecture/services.rst`: the read
  direction table (four rows were wrong) and the sheet-direction rule.
- `docs/user-guide/run-setup.rst`: the i5 workflow choice (when it appears, the standard
  one, when to change it).
- No doc picture changes. The docs-screenshot tests build their instrument records with
  the new keys; no page they capture shows an i5 direction, and the run pages they capture
  use NovaSeq X Series, which has one workflow (so no new select).

## Tests

- **The rule against Illumina's table**: for every built-in instrument and workflow, the
  read direction and the v2 sheet direction match the table above and Illumina's pages.
- **Built-in sheets unchanged**: for every built-in instrument with its standard workflow,
  the v2 sheet (and the v1 sheet for MiSeq and NovaSeq 6000) is what today's code writes,
  apart from the header line on the five reversed-i5 instruments; the header line is still
  written on forward sheets.
- **Workflows that differ**: MiSeq i100 index-first, MiniSeq Rapid kits and NovaSeq 6000
  v1.0 give forward read directions; their dark-start checks look at the i5 forward; their
  v2 sheets follow the rule (MiniSeq Rapid and NovaSeq 6000 v1.0: forward, with the header
  line).
- **The checks**: an i5 that starts dark only when read reversed is now refused on each of
  the four corrected instruments with its standard workflow, and passes on MiSeq i100
  index-first (a two-colour instrument reading the i5 forward). MiSeq and the HiSeqs run
  no colour checks (`color_balance_enabled: false`), as today.
- **Existing tests that pin the old keys** (`tests/unit/test_instruments.py`,
  `tests/unit/test_instrument_file_check.py`,
  `tests/integration/test_scheduled_sync_instrument_cache.py`,
  `tests/browser/test_docs_screenshots.py`) move to the new keys and still protect the
  same thing, except the read directions of the four corrected instruments, which change
  by design.
- **The file rules**: each rule of section 1 refused at sync (the file is skipped and
  logged) and in the local file (SeqSetup does not start); the old keys refused with the
  message; every `config/instruments/*.yaml` and `config/instruments.yaml` passes.
- **The run's workflow**: the route stores a listed name, refuses another (400), refuses a
  Ready run (403); an instrument change empties it; an unlisted name stops Mark Ready with
  the message; the export fingerprint changes with it.
- **H-2**: an unreadable record and an old-format record each make pages show the message,
  refuse Mark Ready with nothing saved, and never use the local file; the sync then
  replaces them (keeping a switched-off instrument switched off) and the next lookup works.
- **Browser**: the workflow select appears for MiSeq i100 and not for NovaSeq X, and a
  change is saved.

## Rollout

SeqSetup has never been deployed, so no stored run changes. A stored run without
`i5_workflow` uses the standard workflow. Synced instrument records stored by an older
SeqSetup cannot be used until the lab's instrument files are updated and synced (section
5); the shipped local file and example files are updated in this change.

## Not in this change

- A flow cell choosing its workflow automatically (decision 3). The built-in MiniSeq still
  lists only standard flow cells; a lab with Rapid kits adds its flow cells and picks the
  Rapid workflow.
- Writing `OverrideReads` or `Index2ColumnReverseComplement` into sheets.
- v1 sheets (bcl2fastq) for instruments other than MiSeq and NovaSeq 6000.
- The JSON export (review S-10) and the `IndexOrientation` handling of anything other than
  the v2 header line.
- Templates carrying a workflow.
- Custom instruments (`_format_custom_instrument`; no route creates them).
- The rest of group A (A3: the sheet's shape at Mark Ready) and groups B–E.
