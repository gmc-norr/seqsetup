# Group A2: the i5 direction follows the instrument, the workflow and the reader — design

## Why

Findings from the 2026-10-03 project review, from the review of this spec, and one the user
raised:

1. **The i5 mask in OverrideCycles is written the wrong way round** (found by the review of
   this spec, F-1). When the i5 is shorter than its index read (an 8-base i5 on a 10-cycle
   Index 2 read), the Index 2 part of `OverrideCycles` must mask the right end. Today
   SeqSetup writes `I8N2` for NovaSeq X, NextSeq 1000/2000 and MiSeq i100, where Illumina
   says `N2I8`, and `N2I8` for NextSeq 500/550, MiniSeq, NovaSeq 6000, HiSeq 4000 and HiSeq
   X, where BCL Convert reads the mask in sequencing order and needs `I8N2`. BCL Convert then
   compares the wrong 8 bases: the reads go to Undetermined, or, rarely, match another
   sample. `services/samplesheet_v2_exporter.py:326-380` flips the mask whenever the sheet
   writes the i5 reversed; its docstring states that rule as Illumina's, and
   `docs/user-guide/export.rst:134-145` repeats it.
2. **The read direction is wrong for three instruments** (review S-4). The instrument files
   say NextSeq 500/550, NextSeq 1000/2000 and MiniSeq read the i5 forward; Illumina says
   they read it as its reverse complement (MiniSeq with its standard kits). The read
   direction drives the dark-start check (which stops Mark Ready) and the colour-balance
   check, so on these instruments both look at the wrong end of the i5: a real dark start
   is missed, and a good index is refused. The review also listed MiSeq i100; its
   instrument default (index-first) does read the i5 forward, so its standard read
   direction is right today.
3. **One direction per instrument cannot follow the kit or the run mode** (raised by the
   user). MiniSeq reads the i5 forward with Rapid kits and reversed with standard kits;
   MiSeq i100 reads it forward in index-first runs and reversed in read-first runs;
   NovaSeq 6000 reads it forward with v1.0 reagents and reversed with v1.5.
4. **A synced instrument guesses its sheet direction** (E-1). A synced file that gives
   `i5_read_orientation` but not `samplesheet_v2_i5_orientation` writes the i5 forward
   (the model's default), while the same entry in the local file falls back to the read
   direction.
5. **The v2 header always says `IndexOrientation,Forward`** (review S-7), even on sheets
   whose i5 sequences are written reversed. Illumina's Run Planning and its BaseSpace BCL
   Convert app read that line as "these i5s are forward; reverse them as needed".
6. **SeqSetup uses the local instruments file while synced records exist** (review H-2,
   and the spec reviews). `_get_synced_instruments` catches any error reading the synced
   records, logs a WARNING and returns nothing, so every instrument comes from
   `config/instruments.yaml`. And even when the synced records load, `get_instrument_config`
   (`data/instruments.py:250-257`) takes any instrument that is not among them from the
   local file, and `is_instrument_enabled_by_name` counts it as switched on.

## What Illumina says (the basis for the rule)

- **How each instrument reads the i5**:
  - [Indexed Sequencing Overview for Paired-End Flow
    Cells](https://knowledge.illumina.com/library-preparation/general/library-preparation-general-reference_material-list/000002099):
    forward with NovaSeq 6000 v1 reagents, MiniSeq Rapid kits and MiSeq; reverse complement
    with MiSeq i100 read-first, iSeq 100, MiniSeq standard kits, NextSeq 500/550,
    NextSeq 1000/2000, NovaSeq 6000 v1.5 reagents and NovaSeq X.
  - Indexed Sequencing Overview Guide (document 15057455 v08), for the HiSeqs on paired-end
    flow cells: forward on HiSeq 2500 and 2000; reverse complement on HiSeq X, 4000 and
    3000. On a single-read flow cell the HiSeqs read the i5 differently (not covered here).
- **MiSeq i100**:
  - [Planning a Manual Mode Run on MiSeq i100
    Series](https://knowledge.illumina.com/instrumentation/miseq-i100-series/instrumentation-miseq-i100-series-reference_material-list/000009499):
    "If Read First sequencing is required, deselect the Sequence Indexes First checkbox."
    So index-first is the instrument's default.
  - [Considerations for index color balancing on the MiSeq i100
    Series](https://knowledge.illumina.com/instrumentation/miseq-i100-series/instrumentation-miseq-i100-series-reference_material-list/000009405):
    read-first reads the i5 reversed; index-first reads both index reads forward. The i100
    needs no image registration. Its two-G advice is written for NextSeq 1000/2000 and
    NovaSeq X.
- **What BCL Convert does** ([DRAGEN v4.5 BCL
  conversion](https://help.dragen.illumina.com/dragen-v4.5/product-guides/dragen-v4.5/bcl-conversion)):
  - `RunInfo.xml` can mark each index read `IsReverseComplement="Y"` (sequenced in the
    reverse orientation) or `"N"` (forward).
  - When the tag is present, every barcode in the sheet is taken as forward and transformed
    during processing. Without it, the Index 2 column is compared with the bases as read.
  - With `Y`, "the OverrideCycles value specified will be reversed for the corresponding
    index read". Without the flag, BCL Convert "will interpret the index sequences as
    specified".
- **NovaSeq X** ([NovaSeq X
  Settings](https://help.connected.illumina.com/run-set-up/overview/instrument-settings/novaseq-x-series-settings)):
  Index2 and OverrideCycles are entered forward. Example: forward i5 `XXATCGCGGT`; as
  sequenced `ACCGCGATXX`; `OverrideCycles` for Index 2: `N2I8`.
- **The resulting table** ([i5 Index Orientation
  Table](https://help.connected.illumina.com/run-set-up/overview/index-orientation-guide/i5-index-orientation-table)):
  - standalone BCL Convert wants the i5 forward for NextSeq 1000/2000, NovaSeq X, MiSeq
    i100 and MiSeq, and reversed for MiniSeq, iSeq 100, NextSeq 500/550 and NovaSeq 6000;
  - MiniSeq Rapid kits are always forward;
  - bcl2fastq wants it as read;
  - onboard DRAGEN (NovaSeq X, MiSeq i100, NextSeq 1000/2000) wants it forward, the same as
    standalone BCL Convert, so one sheet works for both.
- **What all this rests on:** the reader is BCL Convert, standalone or as part of DRAGEN,
  in a version that acts on `IsReverseComplement` (the first such version is not
  documented; the v3.7.5 guide does not mention it). The instrument's control software
  must also write the tag.

## Decisions

Approved by the user on 2026-10-04:

1. **A generic rule from two facts**, instead of an instrument file stating the sheet
   direction: how the instrument reads the i5 in the run's workflow, and whether its
   `RunInfo.xml` marks a reversed i5 read. SeqSetup is a tool for any lab, not one lab's
   instruments.
2. **Every workflow is supported.** Each instrument lists its i5 workflows; a run picks
   one; the first is the standard one.
3. **One mechanism**: the workflow list. A flow cell does not set a direction of its own.
4. **When the synced instrument records cannot be used, SeqSetup stops and says so.** It
   never uses the local file while synced records exist.
5. **MiSeq i100's standard workflow is index-first**, the instrument's default.
6. **The i5 mask fix (Why 1) is part of A2.**
7. **The dark-start check stays on MiSeq i100 as today**, with the workflow's read
   direction. Whether the two-G rule applies to the i100 at all goes on the later list.

## 1. The instrument file

Each instrument (in `config/instruments.yaml`, in each synced file, and in
`config/instruments/*.yaml`) gives two facts about the i5:

```yaml
# How the instrument reads the i5, per workflow. The first one is the standard one.
i5_workflows:
  - name: Index-first
    i5_read_orientation: forward
  - name: Read-first
    i5_read_orientation: reverse-complement
# In a run whose i5 read is reversed, does RunInfo.xml mark it IsReverseComplement="Y"?
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
  It means: in a run whose i5 read is reversed, this instrument's `RunInfo.xml` marks that
  read `IsReverseComplement="Y"`. A lab whose control software does not write the tag, or
  whose BCL Convert does not act on it, sets `false`.
- The old keys are refused: a top-level `i5_read_orientation`, and
  `samplesheet_v2_i5_orientation`. The message says they were replaced by `i5_workflows`
  and `runinfo_marks_i5_reversed` and points to the admin guide. Nothing is guessed from
  them: an old file may carry a wrong read direction (as the shipped ones did, S-4).
- In the model, the workflows are a tuple of frozen dataclasses (`I5Workflow(name,
  i5_read_orientation)`), checked as a whole on every assignment, so they cannot be changed
  in place. Neither fact has a default: `InstrumentDefinition(...)`, `from_yaml` and
  `from_dict` all need both. A record that lacks either, or carries an old key, is refused.
- `from_dict` and `from_yaml` raise a new `InstrumentRecordError` (a `ValueError`) that
  names the record and the problem. The validator and the model accept and refuse the same
  inputs, so a record a sync stores always loads again.

The built-in instruments, in `config/instruments.yaml` and `config/instruments/*.yaml`:

| Instrument | `i5_workflows` (first = standard) | `runinfo_marks_i5_reversed` |
|---|---|---|
| MiSeq i100 Series | Index-first: forward; Read-first: reverse-complement | true |
| MiniSeq | Standard kits: reverse-complement; Rapid kits: forward | false |
| NovaSeq 6000 | v1.5 reagents: reverse-complement; v1.0 reagents: forward | false |
| NextSeq 500/550 | Standard: reverse-complement | false |
| HiSeq 4000 | Standard: reverse-complement | false |
| HiSeq X | Standard: reverse-complement | false |
| NextSeq 1000/2000 | Standard: reverse-complement | true |
| NovaSeq X Series | Standard: reverse-complement | true |
| MiSeq | Standard: forward | false |
| HiSeq 2000/2500 | Standard: forward | false |
| GAIIx | Standard: forward (as today; no Illumina source found) | false |

The HiSeq rows describe paired-end flow cells (guide 15057455). The comment block in
`config/instruments.yaml` (lines 30-51, including "patterned flow cell geometry causes i5
to be read as the reverse complement") and the header comment of each
`config/instruments/*.yaml` file are replaced by a short statement of the rule and the
Illumina links.

## 2. The rule

In `data/instruments.py`, all from the run (its instrument and workflow):

- **The run's workflow**: the workflow `run.i5_workflow` names (exact match), or the
  instrument's first workflow when `run.i5_workflow` is empty (only runs stored before this
  change). A name the instrument does not list, or an instrument with no settings (section
  5), raises an error. It never falls back to a direction.
- **Read direction** = the workflow's `i5_read_orientation`. It drives the dark-start and
  colour-balance checks, and the v1 sheet's i5 (bcl2fastq expects the i5 as read).
- **Index2 column (v2 sheet)**: written **reversed** when the workflow reads the i5
  reversed **and** `runinfo_marks_i5_reversed` is false. Otherwise it is written
  **forward**.
- **The Index 2 part of `OverrideCycles` (v2 sheet)**: written **reversed** (`I8N2`
  becomes `N2I8`) when the workflow reads the i5 reversed **and** `runinfo_marks_i5_reversed`
  is true, because BCL Convert reverses it back. Otherwise it is written as stored. A
  stored value (computed by SeqSetup or typed by a user) is always in reading order: the
  index first, then the masked or extra cycles. The Index 1 part never changes. This
  applies everywhere the writer uses `_adjust_override_cycles_for_instrument`: the
  `[BCLConvert_Settings]` line, each `[BCLConvert_Data]` row, and the profile-driven data
  sections.
- **`IndexOrientation,Forward` (v2 header)**: written when the Index2 column is written
  forward, as today; left out when it is written reversed.
- For the two v1 instruments (MiSeq, NovaSeq 6000), neither marks the i5 read, so the v1
  and v2 rules give the same i5 direction. The v1 sheet has no `OverrideCycles`.
- The functions read the two facts with no defaults, from local-file entries and synced
  records alike. `get_i5_read_orientation(_by_name)` and
  `get_samplesheet_v2_i5_orientation(_by_name)` are removed; every caller moves to the new
  functions.

What this gives for an 8-base i5 on a 10-cycle Index 2 read:

| Run | Index2 column | Index 2 mask | Today's mask |
|---|---|---|---|
| NovaSeq X, NextSeq 1000/2000, MiSeq i100 read-first | forward | `N2I8` | `I8N2` |
| MiSeq i100 index-first | forward | `I8N2` | `I8N2` |
| NextSeq 500/550, MiniSeq standard, NovaSeq 6000 v1.5, HiSeq 4000, HiSeq X | reversed | `I8N2` | `N2I8` |
| MiniSeq Rapid, NovaSeq 6000 v1.0 | forward | `I8N2` | (new workflows) |
| MiSeq, HiSeq 2000/2500, GAIIx | forward | `I8N2` | `I8N2` |

## 3. The run's workflow

- **The field**: `SequencingRun.i5_workflow: str = ""`. On every assignment it is cut to
  256 characters and line breaks become spaces (as `run_name`). It is saved in `to_dict` /
  `from_dict`. Because `_export_input_fingerprint` hashes `to_dict`, a workflow change
  during Mark Ready's export step is caught like any other input change.
- **A name is always stored.** The new-run route (`routes/wizard.py`, after
  `run_repo.create_run`) and the instrument-change route
  (`POST /runs/{run_id}/instrument`) store the instrument's standard (first) workflow name.
  `build_draft_run` (duplicate, and create from template) copies it. Only a run stored
  before this change has `""`. So reordering an instrument file never moves an existing
  run; renaming a workflow makes it "not listed" (an error), never a silent switch.
- **Templates carry it**: `RunTemplate` gets the same field, copied when a template is
  made from a run, so a template from a NovaSeq 6000 v1.0 run starts runs on v1.0.
  `assert_references_available` also refuses a source whose workflow the instrument no
  longer lists ("<workflow> is no longer an i5 workflow of <instrument>; this
  template/run cannot be instantiated.").
- **Where it is picked**: a new select, `wizard/_i5_workflow_select.html`, inside a
  container with a fixed id, placed after the flow cell in `wizard/_instrument_config.html`
  (the new-run page, which is also the draft's "Edit setup" page).
  - The select is shown when the instrument lists more than one workflow, **or** when the
    run's workflow is not listed (then that value is shown marked "not available", like an
    instrument that is no longer offered). Otherwise the container is empty.
  - The standard workflow is labelled "(standard)".
  - `POST /runs/{run_id}/instrument` always sends the container out of band (filled or
    empty), the way the reagent-kit select is sent today.
- **Saving**: `POST /runs/{run_id}/i5-workflow`, behind `get_editable_run`, saved with
  `saving_run`. A missing field is a 400 and nothing is written. The value must exactly
  match one of the instrument's workflow names; anything else is a 400 naming the
  instrument and its workflows.
- **Shown where the run is reviewed**: the run page's Setup panel
  (`templates/runs/_run_config_panel.html`) shows "i5 workflow: <name>" for an instrument
  with more than one workflow, and always when the workflow is not listed. The validation
  report (JSON and PDF, `services/validation_report.py`) records the workflow and the i5
  read direction the checks used, next to the instrument and flow cell.
- **Mark Ready**: when the instrument does not list the run's workflow, validation reports
  an error and Mark Ready is refused: "<workflow> is not an i5 workflow of <instrument>
  (it has: <names>). Pick one in Run Setup." The dark-start and colour-balance checks do not
  run for that run, as there is no read direction. The writers refuse such a run too
  (`ValueError`), as a safety net.

## 4. What the sheets and checks do

- **v2 sheet**: the Index2 column, the Index 2 mask and the header line follow section 2.
- **v1 sheet**: the i5 is written as the run's workflow reads it.
- **Dark-start and colour-balance checks**: they use the run's read direction.
- **JSON export**: unchanged.

With each built-in instrument's standard workflow:
- the i5 sequences in every Sample Sheet are written exactly as today;
- the `IndexOrientation,Forward` line is gone from the v2 sheets of MiniSeq, NextSeq
  500/550, NovaSeq 6000, HiSeq 4000 and HiSeq X (their i5s are written reversed);
- the Index 2 mask changes where the i5 is shorter than its read (or carries another
  asymmetric pattern): on NovaSeq X, NextSeq 1000/2000, NextSeq 500/550, MiniSeq,
  NovaSeq 6000, HiSeq 4000 and HiSeq X (the table in section 2). A symmetric mask such as
  `I10` does not change;
- nothing else in the sheets changes.

The checks change on NextSeq 500/550, NextSeq 1000/2000 and MiniSeq: some runs that pass
today are refused (their i5 really does start dark as the instrument reads it), and some
refused today pass. MiSeq i100 runs on the standard workflow (index-first) are checked as
today.

**A check by the lab before first clinical use**, recommended in the admin guide: run BCL
Convert on a real run that has an i5 shorter than its read, with the sheet SeqSetup
writes, on each instrument the lab uses. Or compare with a sheet that Illumina's own run
setup wrote for such a run.

## 5. When the synced records cannot be used (H-2)

- **Missing instruments**: while synced records exist, an instrument that is not among
  them has no settings. `get_instrument_config` returns nothing for it and never reads the
  local file, and `is_instrument_enabled_by_name` says it is not available. Validation
  reports "<instrument> is not among the synced instruments" and Mark Ready is refused.
  The writers refuse it. The local file is used only when there are no synced records at
  all, as today.
- **Records that cannot be loaded**: `_get_synced_instruments` no longer falls back.
  - A stored record in the old format or with a bad value raises `InstrumentRecordError`
    from the model. `_get_synced_instruments` turns it into a new
    `SyncedInstrumentsUnusable` error, with the message: "The synced instrument settings
    cannot be used: <record>: <problem>. Update the instrument files and run a config sync
    (Admin > Config Sync)."
  - A database error raises `SyncedInstrumentsUnusable` with a different message: "The
    synced instrument settings could not be read from the database: <error>."
  - Programming errors are not caught.
  - Nothing is cached while it fails, so the first lookup after a good sync works. The
    failure is logged once per change of state, not on every lookup.
- **Every reader stops the same way**, with nothing to remember: one exception handler,
  registered for `InstrumentRecordError` and `SyncedInstrumentsUnusable`, shows the
  message like the existing `HTTPException` handler (an HTMX request gets the error
  fragment, a page gets the error page, status 503). So any direct read of a stored record
  is covered too: the Mark Ready re-read of the on/off switch, the admin Instruments page,
  `list_enabled`.
- **Not swallowed**: `_pregenerate_exports` (inside Mark Ready) and the live-export
  fallbacks in `routes/export.py` re-raise both errors before their generic `except`, so
  the user gets the message, not "Failed to generate exports".
- **Mark Ready** is refused and nothing is saved. The refusal is audited as
  `run.status.denied` with reason `synced_instruments_unusable`.
- **Run pages**, including those of Ready and Archived runs (the run page runs
  validation), show the message while the records cannot be used. The API and the
  pre-generated exports keep working.
- **The sync can always repair it**:
  - Today the sync loads every stored record in full (`list_all`) to keep each instrument's
    on/off switch, so a record that cannot be loaded would make the sync that fixes it
    fail. Instead it reads only each stored record's `samplesheet_name` and `enabled`
    fields, through a new repository method, then replaces the records as today.
  - **A refused instrument file**: when any fetched instrument file is refused, the sync
    stores no instrument records (the stored ones stay as they are). Its result names each
    refused file and problem. Application profiles, test profiles and index kits are synced
    as usual. (Today a refused file is skipped, and its instrument's record is deleted with
    the rest, losing its on/off switch.)
  - The admin Config Sync page does not read instrument settings (checked: it only clears
    the cache), so it keeps working.

## Docs

- `docs/admin-guide/instruments.rst`:
  - the two facts and the rule, with the mask table, the new keys and their checks;
  - the built-in table and the Illumina links;
  - what the rule rests on (BCL Convert that acts on `IsReverseComplement`, control
    software that writes it, and `false` otherwise);
  - "the first workflow is the standard one; a new run or a changed instrument gets it";
  - the lab check before clinical use (section 4);
  - an **upgrade note**:
    - instrument files in the old format are refused;
    - a lab's own local file stops SeqSetup from starting until it is updated;
    - synced files must all be updated and synced, and until then run pages show the
      message and Mark Ready is refused;
    - an instrument the lab does not sync is not available while it syncs others;
  - the old error message quoted at lines 12-15 is replaced.
- `docs/user-guide/export.rst`: the note at lines 134-145 (it states today's wrong mask
  rule) is rewritten to the section 2 rule.
- `docs/user-guide/run-setup.rst`: the i5 workflow choice (when it appears, the standard
  one, when to change it).
- `docs/user-guide/override-cycles.rst`: a typed `OverrideCycles` is in reading order;
  SeqSetup writes the Index 2 part the way the reader needs.
- `docs/architecture/instruments.rst`, `docs/architecture/services.rst` and
  `docs/architecture/samplesheet-format.rst`: the read-direction table (three rows were
  wrong), the rules, and the example sheet's mask with its instrument named.
- No doc picture changes:
  - the docs-screenshot tests build their instrument records with the new keys;
  - no page they capture shows an i5 direction;
  - the run pages they capture use NovaSeq X Series, which has one workflow, so there is
    no new select and no new Setup-panel line.

## Tests

- **The rule against Illumina's tables**: for every built-in instrument and workflow, the
  read direction, the Index2 column direction, the Index 2 mask (an 8-base i5 on a 10-cycle
  read, and a symmetric `I10`) and the header line match sections 1 and 2.
- **Built-in sheets**: for every built-in instrument with its standard workflow, the v2
  sheet (and the v1 sheet for MiSeq and NovaSeq 6000) equals today's, apart from the header
  line on the five reversed-i5 instruments and the Index 2 mask in the mask table. Each
  difference is named in the test.
- **Workflows that differ**: MiSeq i100 read-first, MiniSeq Rapid kits and NovaSeq 6000
  v1.0 follow the rule in their checks and sheets.
- **The checks**:
  - an i5 that starts dark only when read reversed is now refused on NextSeq 500/550,
    NextSeq 1000/2000 and MiniSeq standard kits;
  - the same i5 passes on MiniSeq Rapid kits (a two-colour instrument reading the i5
    forward).
  - MiSeq and the HiSeqs run no colour checks (`color_balance_enabled: false`), as today.
- **The file rules**:
  - each rule of section 1 is refused at sync and in the local file (SeqSetup does not
    start);
  - the old keys are refused with the message;
  - every `config/instruments/*.yaml` and `config/instruments.yaml` passes;
  - for every record the sync stores, `from_dict(to_dict(x))` loads it;
  - the validator and the model agree on what they accept.
- **The run's workflow**:
  - the route stores a listed name, refuses another (400), refuses a missing field (400),
    and refuses a Ready run (403);
  - a new run and an instrument change store the standard name;
  - a duplicate and a template run keep the workflow;
  - instantiating with an unlisted workflow is refused;
  - an unlisted name stops Mark Ready with the message, and the select then shows it;
  - the export fingerprint changes with it;
  - the Setup panel and the validation report show it.
- **H-2**:
  - a run on an instrument missing from a non-empty synced set cannot be marked Ready and
    never gets local-file values;
  - an unreadable record and an old-format record each make run pages show the message,
    refuse Mark Ready with nothing saved and an audit event, and never use the local file;
  - the message also appears through the export paths;
  - a sync with one refused instrument file stores no instrument records, keeps the old
    ones and names the file;
  - a sync with all files good replaces old-format records (keeping a switched-off
    instrument switched off), and the next lookup works.
- **Browser**:
  - the workflow select appears for MiSeq i100 and not for NovaSeq X;
  - a change is saved;
  - switching MiSeq i100 → NovaSeq X removes the select.
- **Existing tests**:
  - Tests that pin the old keys or build instrument records without the new facts move to
    the new keys and still protect the same thing: `tests/unit/test_instruments.py`,
    `tests/unit/test_instrument_file_check.py`, `tests/unit/test_kit_cycle_limit.py`,
    `tests/unit/test_sync_name_rules.py`,
    `tests/integration/test_scheduled_sync_instrument_cache.py`,
    `tests/integration/test_group_1c.py`, `tests/integration/test_sheet_safety.py`,
    `tests/integration/test_sheet_followups.py` and `tests/browser/test_docs_screenshots.py`.
  - The expectations that change by design:
    - the read directions of the three corrected instruments;
    - the Index 2 masks pinned in `tests/unit/test_samplesheet_v2_exporter.py` (NovaSeq X
      `I8N2;I8N2` becomes `I8N2;N2I8`; NextSeq 500/550 `I8N2;N2I8` becomes `I8N2;I8N2`);
    - the header line on the five reversed-i5 instruments.

## Rollout

SeqSetup has never been deployed, so no stored run changes. A stored run without
`i5_workflow` uses the standard workflow. Synced instrument records stored by an older
SeqSetup cannot be used until all the lab's instrument files are updated and synced
(section 5); the shipped local file and example files are updated in this change.

## Not in this change

- A flow cell choosing its workflow automatically (decision 3). The built-in MiniSeq still
  lists only standard flow cells; a lab with Rapid kits adds its flow cells and picks the
  Rapid workflow.
- The read order of `OverrideCycles` in MiSeq i100 index-first runs (the instrument reads
  Index 1, Index 2, Read 1, Read 2). Whether its `RunInfo.xml` lists the reads in that
  order is not checked. Later list; a `RunInfo.xml` from an index-first run settles it.
- Whether the two-G dark-start rule applies to MiSeq i100 (decision 7). Later list.
- HiSeq runs on single-read flow cells, which read the i5 differently. Later list.
- How BaseSpace's BCL Convert app treats the header line on MiniSeq Rapid and NovaSeq 6000
  v1.0 sheets (not checked; the line is kept on forward sheets as today). Standalone BCL
  Convert and onboard DRAGEN do not use it.
- Writing `OverrideReads` or `Index2ColumnReverseComplement` into sheets.
- v1 sheets (bcl2fastq) for instruments other than MiSeq and NovaSeq 6000.
- The JSON export (review S-10).
- Custom instruments: no route creates them; `_format_custom_instrument` loses the two old
  keys and gains nothing. `InstrumentDefinition.to_instruments_format` has no callers and is
  removed.
- The rest of group A (A3: the sheet's shape at Mark Ready) and groups B–E.
