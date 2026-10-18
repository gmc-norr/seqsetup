# One strict check for every input SeqSetup reads

## The problem

Every input SeqSetup reads has its own parser and its own validator, written at
different times: application and test profiles (`services/profile_validator.py`),
instrument files (`services/instrument_validator.py`,
`models/instrument_definition.py`), index kit files (`services/index_parser.py`,
`services/index_kit_sync_parser.py`, `services/index_validator.py`), the database
settings file (`services/database.py`), pasted samples
(`services/sample_parser.py`) and LIMS worklists (`services/sample_api.py`).

They agree on some rules and not on others, and **none of the settings readers
refuses a key it does not know**. A misspelt key is ignored and the setting it
was meant to change falls back to a default without a word. Measured on
`cca4a12` (2026-10-18):

- An instrument file's flow cell with `lane: 2` (for `lanes`) is stored with one
  lane (`models/instrument_definition.py` `_from_file`: `get("lanes", 1)`).
- `colour_balance_enabled: true` (for `color_balance_enabled`) leaves the colour
  balance check off (`get("color_balance_enabled", False)`).
- A kit CSV with two columns named `index2` is accepted and the last column's
  sequence is stored; the admin guide says such a file is refused.
- `TestType: 5` in a test profile passes the validator, then the sync fails with
  `'int' object has no attribute 'lower'` and names no file
  (`services/github_sync.py:561`).
- A typo in `config/mongodb.yaml`'s `mongodb:` key silently means the default
  connection (`services/database.py`: `config.get("mongodb", {})`).
- Profiles and synced instrument files keep the last of a key given twice
  (`safe_load_strict`, `github_sync.py:736,822`); the local
  `config/instruments.yaml` is read with plain `yaml.safe_load`
  (`data/instruments.py:259`), so anchors are accepted there too.
- `default_cycles` and `index_cycle_options` in the local instruments file are
  not checked at all.
- A multi-instrument file ignores any key beside `instruments:` and replaces an
  instrument's own `name` with its map key without a word
  (`github_sync.py:867-872`).
- YAML changes values on its own before any check sees them: `version: 1.10` is
  the number 1.1, `name: no` is `False`, `012` is 10, `0x10` is 16, `1:20` is 80
  (base 60). Some readers turn these back into text, some refuse them, some
  crash. Two keys `10:` and `012:` are one key once read, so even the duplicate-key
  check in `utils/yaml_safety.py` lets the first one vanish.
- The bundled local instrument file and the shipped synced instrument files
  describe the same eleven instruments, and have drifted apart: eight local
  entries do not state `has_dragen_onboard`, which every synced twin states.

Fixing each of these on its own (the 2026-10-18 batch had three such steps)
leaves the next unknown key, the next type and the next file format to be found
the same way.

## The decision

The user decided on 2026-10-18:

- **Scope: every input.** Application and test profiles, instrument files
  (synced and the local file), index kit files in every upload format and the
  sync format, the database settings file, pasted samples and LIMS worklists.
- **Framework: Pydantic v2 in strict mode**, already a dependency (the forms and
  the API schemas use it, with Pydantic's default `extra="ignore"`). One rulebook
  per input.
- **Order: one input type at a time**, each on its own branch with its own checks
  and the user's word before merging. First the shared core together with
  instrument files; then profiles, kit files, the database settings file, and
  last pasted samples and LIMS worklists (already strict, see below).

Options not taken:

- **JSON Schema files checked with the `jsonschema` library.** Language-neutral,
  but a new dependency; rules that relate two keys are clumsy to write; the
  error messages are poor; and the checks that need code (DNA, pairing,
  versions) would stay in Python, so the rules would live in two places.
- **A hand-written key table per file.** No dependency, but it re-implements
  what Pydantic already does and has to be tested as a framework of its own.
- **Fixing each gap where it is found** (the stopped batch). See the problem.

The design was reviewed by an outside reviewer before any code was written
(see "Review" at the end); its findings are folded in below.

## The shape: one pipeline

Every input goes through the same four stages, and **the value each stage
produces is the only value the next one sees**:

1. **Read** the raw input into plain data, with the source location of every key,
   value and list item.
2. **Adapt** the source format to one canonical shape: aliases, a headerless
   paste, a LIMS field-name mapping, conversions the input type explicitly
   allows. Most settings files need no adapter.
3. **Validate** the canonical shape against the input type's rulebook.
4. **Convert** the checked result into the domain objects the app uses today. The
   converter builds from the checked result only, never from the raw data, and an
   accepted value must arrive unchanged (see "Values survive conversion").

If any stage finds an error, the input is refused with all the problems found,
and nothing is written.

The code lives in a new package, `src/seqsetup/input_rules/`. It imports nothing
that starts the app: no repositories, no `seqsetup.data.instruments` (which reads
the local instruments file at import) and no `services.github_sync` (which
imports it). The settings command can therefore use it with no database, no
network and no app start-up.

### 1. Read

A reader turns the raw input into plain data and a **location map**: from a path
to the line (and column) it came from. A path is a tuple of mapping keys and list
indexes, such as `("flowcells", "10B", "lanes")` or `("i5_workflows", 0, "name")`.
The map records, for every node: the line of a mapping key, the line of its value,
and the line of each list item.

**YAML** builds on the loaders in `utils/yaml_safety.py` (no anchors, no aliases)
and adds:

- **Only plain spellings of values.** A YAML scalar that is not quoted becomes a
  number, a yes/no value or null only when it is written in the one plain way:
  - a whole number: decimal digits with no leading zero (`0` alone is allowed),
    an optional leading `-`; `012`, `0x10`, `0o17`, `1_000` and `1:20` are
    refused ("write it as plain digits, or in quotes if it is text");
  - a decimal number: refused unless the rulebook asks for one (none does in
    step 1), with "put it in quotes" when it was meant as text (`1.10`);
  - yes/no: `true` or `false` (any case); `yes`, `no`, `on`, `off` are refused;
  - null: `~`, `null` and an empty value are refused where the rulebook does not
    allow a missing value, with "write a value";
  - a date or time (`2026-10-18`) is refused: "put it in quotes".
- **Keys given twice are refused after they are read, not only as written.** Two
  keys that read as one value (`10:` and `012:`, `1:` and `1.0:`, `1:` and
  `true:`) are refused as one key given twice. Every repeat in the file is
  reported, each with its line.
- **What is kept.** The decoded value goes on through the pipeline. The text of
  each scalar as written is kept apart from it, for messages only (see
  "Sensitive inputs").

**CSV and TSV** readers (built in the kit and paste steps) return rows with their
line numbers, and refuse a column name given twice before any row is read.

If the reader finds a problem, it reports every such problem in the file and the
later stages do not run: a file whose structure cannot be trusted is not checked
further.

### 2. Validate: the strict base

`class StrictRules(pydantic.BaseModel)` with
`model_config = ConfigDict(extra="forbid", strict=True, frozen=True,
validate_default=True)`:

- `extra="forbid"`: a key the rulebook does not name is refused. This constrains
  a model's fields only; a field that is a map (`dict[str, ...]`) accepts any
  key unless the rulebook says which keys it may have. Every such map in a
  rulebook states its key rule.
- `strict=True`: no conversion between str, int, float and bool.
- `validate_default=True`: a default is checked like a written value.
- **No `Literal` of numbers and no `set`.** Strict mode still matches `true` and
  `2.0` against `Literal[1, 2]`. A choice among numbers is a strict whole number
  followed by a membership check; a "set" in a file is a list whose items must be
  distinct. The guard test refuses a `Literal` with a non-text value.
- **Shared building blocks**, each defined once: a plain name (the rule the
  readers use today), version text (a string, never a number), text of at most
  256 characters, a whole number with a stated range, true/false, and
  Illumina's application names (the list now kept in
  `tests/unit/test_shipped_examples_fit.py:23` and
  `tests/unit/test_dragen_section_names.py:26`, moved into `src/` with a comment
  saying where the names come from and how to add one).
- **A guard test** imports every model in `input_rules` and fails when one does
  not derive from `StrictRules`, loosens its config, or uses a `Literal` with a
  non-text value.

**Rules relating several keys** (the colour fields depend on `chemistry_type` and
`color_balance_enabled`; a reagent kit limit names a kit some flow cell offers)
are not Pydantic model validators, which stop at the first failure and give no
key. Each is a separate check function that runs after field validation, on the
fields it needs, and returns problems with an explicit path. Every such check
runs, so independent problems are all reported.

### 3. Problems

`InputProblem(file, line, path, message, level)`, with `level` `"error"` or
`"warning"`.

- **Every independently discoverable problem is reported**: all reader problems
  of a file; all field errors of a rulebook (Pydantic gives them together); every
  cross-key check whose fields passed. A cross-key check whose fields failed does
  not run (it would only repeat them).
- **Locations.** Pydantic's error location is mapped to the location map: a
  mapping key's line for an unknown key or a bad map key (Pydantic's `[key]`
  suffix); the value's line for a bad value; the item's line for a list item; for
  a missing key, the line of the mapping it is missing from (line 1 for the top
  level); for a cross-key check, the path it names. A test covers each kind.
- **Messages** say the key path as written (`flowcells > 10B > lane`) and a plain
  sentence per error type: an unknown key "is not a key this file can have
  (check the spelling)"; a missing key "is required"; text given a number "must
  be text: put it in quotes"; a choice "must be one of: 2-color, 4-color"; a
  check's own message as written.
- **Warnings** come from a separate function per rulebook, run only on a value
  that passed; they never block.

### Sensitive inputs

The database settings file can hold a connection string with a password, and
`services/database.py` deliberately never repeats a YAML parser's message
(`_yaml_refusal`), which can quote it. So, from step 1 on:

- every message is built by `input_rules` from the path, the line and the error
  type; **neither PyYAML's message nor Pydantic's own message or input value is
  shown, logged or audited as is**;
- a value may be quoted in a message only when the input type marks it safe to
  show; the database settings file marks none of its values safe;
- keeping the original text of a scalar (above) does not make it safe to show.

### 4. Values survive conversion

- **Every number's range is the narrowest range its downstream code accepts
  without changing it.** Where the app clamps a value (`RunCycles` clamps cycle
  counts to 0-1000, `models/sequencing_run.py:245`; the cycle fields of a run are
  refused above 600, `routes/runs.py:476`), the rulebook refuses what would be
  clamped or refused later, so an accepted file never turns into another value
  on the way. Step 1 lists every number in the instrument rulebook with the code
  that consumes it and its range.
- **A round-trip test** converts checked files, including values at each range's
  edges, into the domain objects and compares every field with the checked
  value. Normalisation that is meant (for example a sequence uppercased) is named
  in the test.
- **The checked result is not changed after it is checked.** `frozen=True` is
  shallow: a list or map inside a checked model can still be changed. The
  converter copies what it needs into the domain objects, and no code keeps or
  changes a checked result after conversion.

### 5. The domain models stay a backstop

The domain models keep their own checks (`__post_init__`, `__setattr__`), the
backstop CLAUDE.md requires at the model boundary. They do not all check what
they hold today (`InstrumentDefinition.from_dict` accepts a stored flow cell
whose `lanes` is not a number), so:

- **a rule moves from an old validator into a rulebook, it is not copied**, and
  the old validator's tests are kept and pointed at the new path with the same
  guarantee;
- **a rule the domain model enforces stays in the domain model**; where both
  layers need one rule, both call one pure function, so the rule exists once;
- limits shared with the models (256 characters, the plain-name rule) are
  imported from one place.

**Rules that need more than one file or the stored data stay outside the
rulebooks:** two instrument files for one instrument (`_duplicate_instruments`),
a profile version given twice (`_refuse_repeated_app_versions`), tests differing
only in capitals, a kit's name and version with another content
(`_refuse_changed_or_repeated_kits`), index collisions between samples. Those of
them that need no database are moved into pure functions in `input_rules`, which
the sync and the settings command both call; the ones that need the stored data
stay in the sync.

### 6. Where problems are shown

- **Configuration sync.** The sync returns its result with its problems, so each
  caller (a sync started by hand, or by the scheduler) has exactly that sync's
  problems. Each refused file gets its list. The sync status keeps today's
  message and adds a `problems` list (`{file, line, path, message, level}`);
  Admin > Configuration sync shows it as a table. As today, a refused file keeps
  the stored records it would have replaced. Warnings are shown there too, not
  only logged.
- **The audit trail.** Every sync's audit row carries its problems, whether the
  sync was started by hand or by the scheduler (today a manual sync's row has the
  outcome and count only: `routes/admin/config_sync.py:171-177`). An audit row's
  details are dropped whole above 64 KiB (`models/audit_event.py`,
  `MAX_DETAILS_BYTES`), so the problems put in a row are cut to fit well under
  that size, counted in encoded bytes, and the row always keeps the outcome, the
  number of problems and the number left out. The sync page shows them all.
- **Start-up.** A local file with an error stops start-up with every problem and
  its line (`InstrumentConfigError`, today naming the field but not the line).
- **The settings command** (below).

### 7. The settings command

`pixi run check-settings <folder>` (`python -m seqsetup.input_rules.cli`):

- checks a settings folder laid out as the sync reads it (the shipped `config/`
  is the example; options name other paths), with the same rulebooks and the same
  database-free cross-file checks the sync uses;
- prints one problem per line, `file:line: path: message`, warnings marked;
- exits 1 when there is an error, 0 otherwise;
- needs no database, no network and no running app, and ships in the Docker
  image, so the lab's settings repository can run it on every change;
- `--schema <dir>` writes a JSON Schema per rulebook (`model_json_schema()`) for
  editors. The schema is a help, not the authority: it cannot express keys given
  twice, value spellings, anchors or the cross-key checks. The command is the
  authority.

A test runs the command in a fresh subprocess, with `INSTRUMENTS_CONFIG` pointing
at a broken file and no database, and asserts that it works and that
`seqsetup.data.instruments` and `seqsetup.services.github_sync` were never
imported.

It grows with each step: in step 1 it checks instrument files only.

## Step 1: the core and instrument files

### The documents

Every shape of instrument document the app accepts has its own rulebook, and the
outer document is checked before any instrument is taken out of it:

- **a synced single-instrument file** (one instrument at the top level);
- **a synced multi-instrument file**: `instruments:` is its only key, a map of a
  name to an instrument. An instrument inside it may leave out `name`; if it
  states one, it must equal its map key (today the map key silently wins);
- **the local file** (`config/instruments.yaml`): `instruments` (as above),
  `default_cycles` and `index_cycle_options`.

Each instrument is then checked by the one instrument rulebook, with its
locations kept.

### The instrument rulebook

**Rule: a fact that changes a sheet or a check must be written out. Any other
default is documented in the admin guide and tested.**

| Key | Required | Rule |
|---|---|---|
| `name` | yes in a single-instrument file; the map key in a multi-instrument or local file | plain text |
| `samplesheet_name` | yes | plain name |
| `version` | yes in a synced file (today a logged warning only); not in a local entry (the shipped local file has none) | version text |
| `chemistry_type` | yes (today defaults to `2-color`) | `2-color` or `4-color` |
| `sbs_chemistry` | no | label |
| `has_dragen_onboard` | yes (today defaults to false) | true/false |
| `i5_workflows` | yes | today's rules (`instrument_definition.py:37-61`): a list of `{name, i5_read_orientation}`, orientation `forward` or `reverse-complement` |
| `runinfo_marks_i5_reversed` | yes | true/false |
| `color_balance_enabled` | yes (today defaults to false) | true/false |
| `dye_channels`, `base_colors`, `channel1_name`, `channel1_bases`, `channel2_name`, `channel2_bases`, `dark_base` | yes on a 2-color instrument with colour balance on (today a missing one is only a warning: `instrument_validator.py:140-175`); allowed and checked on a 2-color instrument with it off; refused on a 4-color instrument, where nothing reads them | today's value rules; `base_colors` has exactly A, C, G, T; an unusual dye channel name stays a warning |
| `error_tendencies` | no | label |
| `samplesheet_versions` | no; absent means `[2]`, as the admin guide says (9 of the 11 shipped synced files leave it out) | a non-empty list of distinct whole numbers, each 1 or 2 |
| `onboard_applications` | yes | map of an Illumina application name to `{software_version: version text}` |
| `flowcells` | yes, at least one | map of a name to `{lanes, reagent_kits, reads, description}` |
| `flowcells > * > lanes` | yes (today defaults to 1) | whole number, range set by its consumers (see below) |
| `flowcells > * > reagent_kits` | yes | non-empty list of distinct whole numbers, range set by its consumers |
| `flowcells > * > reads` | no | whole number, 0 or more |
| `flowcells > * > description` | no | label |
| `reagent_kit_max_cycles` | no | today's rules (`instrument_validator.py:234-268`): a map of a kit label (a whole number) to the most cycles allowed (a whole number, at least the label); a label no flow cell offers is a warning |
| `i5_read_orientation`, `samplesheet_v2_i5_orientation` at the top level (`OLD_I5_KEYS`) | refused | with today's message (`_refuse_bad_i5_facts`), not the generic unknown-key one |

Every other key is refused.

**The local file's cycle sections** — neither is checked today:

- `default_cycles`: a map of a reagent kit's cycles (a whole number) to
  `{read1, read2, index1, index2}`, each a whole number within what a run's cycle
  fields accept (`routes/runs.py:476-500`: 0 to 600; Read 2 = 0 is a single-end
  run). Read 1 must be at least 1 unless the build finds a supported use of 0, and
  records the evidence.
- `index_cycle_options`: a non-empty list of distinct whole numbers, each one an
  index cycle count a run accepts.

**Ranges.** Every number in the table is listed in the step's notes with the code
that consumes it and the range that code accepts without clamping or refusing;
the rulebook uses that range (section 4).

### What else changes in step 1

- **The shipped local file states every required fact.** The eight local entries
  that leave out `has_dragen_onboard` (NextSeq 500/550, MiniSeq, NovaSeq 6000,
  GAIIx, HiSeq 2000/2500, HiSeq 4000, HiSeq X, MiSeq) get `has_dragen_onboard:
  false`, the value they read as today and the value their synced twins state; a
  test shows each converts to the same `InstrumentDefinition` before and after.
- **A drift test** compares each bundled local entry with its shipped synced twin
  (`config/instruments/*.yaml`) and fails on any fact that differs.
- The local file is read by the new reader and stops start-up listing every
  problem with its line. Start-up keeps today's three cases apart: the default
  folder missing or closed (a warning, shown on Admin > Instruments), a file
  named by `INSTRUMENTS_CONFIG` that is missing (stops start-up), and a visible
  file that cannot be read (stops start-up, naming the `OSError`; today an
  `ELOOP` escapes `_present`, `data/instruments.py:225-238`, as a raw traceback).
- `reload_config` (`data/instruments.py:371`) has no caller in `src/` and would
  not clear the validation cache: removed, with the tests that exist only for it.
  (Both moved here from the stopped batch's step 12, which touched the same file.)
- `validate_instrument_yaml`'s rules move into the rulebook (section 5); the
  dye-channel warning becomes a rulebook warning, shown on the sync page.
- `_duplicate_instruments` becomes a pure function in `input_rules`, used by the
  sync and the settings command.
- A synced instrument file with an error is refused as today: no instrument from
  that sync is stored and the stored ones stay (`github_sync.py:350-355`).
- `docs/admin-guide/instruments.rst` gets the full key table (there is none
  today); a test fails when the rulebook has a key that page does not name.
- The settings command, checking instrument files.

### How step 1 is proved

- Red tests first, for every rule: an unknown key refused with its line, also
  nested in a flow cell; a key given twice, also two spellings of one key
  (`10:` / `012:`); each refused value spelling (`012`, `0x10`, `1:20`, `1_000`,
  `1.10`, `yes`, `~`, a date); an anchor; `[true, 2.0]` for
  `samplesheet_versions`; each required key; the colour-field rule; the
  multi-instrument wrapper (an extra key, a `name` that differs from its map
  key); each number at and past its range's edges; the local file's two cycle
  sections.
- A test per location kind (mapping key, value, list item, map key, missing key,
  cross-key check).
- The guard test, the round-trip test, the drift test, the command's isolation
  test, the audit size test (many long problems still leave a row with counts).
- The shipped instrument files and the shipped local file pass through the new
  reader (today's tests load them with plain `yaml.safe_load`).
- The existing instrument tests (about 100) keep passing; any changed test keeps
  its guarantee and is listed.
- Break checks: each rule switched off in turn turns a test red.
- The full check: the 78 Sample Sheets are unchanged.
- Before merging, the settings command is run on the lab's real settings
  repository, and the user sees what it would refuse.

## Later steps (each adds its details to this note, or a note of its own)

2. **Profiles.** The application name must be one of Illumina's. The `Settings`
   and `Data` sections are maps copied into the sheet; `extra="forbid"` does not
   constrain their keys, so their key policy is decided in that step (restricting
   them to the keys Illumina documents per application needs those lists).
   `TestType: 5` is refused, not a crash. A yes/no value in a profile's `Data`
   section (`DifferentialExpressionEnable: False` in
   `config/profiles/application_profiles/dragen/DragenRnaIdt.yaml:14`) reaches
   the sheet as text: what is written is decided there.
3. **Index kit files**, every format, each through its own adapter to one
   canonical kit shape: replaces the stopped batch's step 8. A column name given
   twice; `is_fixed_layout: 'no'`; a missing name or version silently taking the
   file name or `1.0`; names cut at 256 characters (`models/index.py:226`); a `:`
   in a name or version (the stored id is `name:version`); the generic "Failed to
   parse file".
4. **`config/mongodb.yaml`**: a misspelt `mongodb:`; an empty file. Its values are
   never shown in a message (see "Sensitive inputs").
5. **Pasted samples and LIMS worklists.** These already refuse the whole input and
   name the rows, and their behaviour must not change unless a gap is found, which
   is then decided on its own. They keep explicit adapters for what they accept
   today: a headerless paste, column and field aliases, the LIMS field-name
   mapping, a LIMS sample ID sent as a JSON number (read as text today), and
   unrelated LIMS metadata (ignored today, except a field that looks like an
   index or a lane, which is refused). The strict rulebook checks the adapted
   rows, not the raw ones.

Suggested by the review and left for a later decision: one canonical instrument
file format for the bundled and the synced definitions, with the local cycle
defaults in a file of their own. In step 1 the drift test holds the two copies
together instead.

## What does not change

- No Sample Sheet changes: the 78-sheet corpus stays identical.
- The domain models keep their invariants.
- The rules that need several files or the stored data stay where they are.
- No new dependency.

## Review

An outside review of the first version of this note (commit `cd1ea6c`) gave
four P1, seven P2 and one P3 findings, all confirmed and folded in above:
the local file leaving out `has_dragen_onboard` (P1); YAML changing numbers and
merging keys before any check (P1); strict mode accepting `true` and `2.0` as 1
and 2 (P1); numbers with no upper bound, clamped later, and Read 2 = 0 (P1);
`frozen=True` being shallow and defaults unchecked (P2); the multi-instrument
wrapper (P2); error locations and stopping at the first cross-key failure (P2);
the audit trail's 64 KiB limit (P2); the settings command importing the sync
(P2); adapters for pasted samples and LIMS worklists (P2); messages that can
quote a password (P2); the wording on defaults, and `Data` for `Settings` (P3).
