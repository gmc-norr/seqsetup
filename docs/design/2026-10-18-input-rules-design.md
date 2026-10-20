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
- **No explicit tags.** A value written with a tag (`!!int "012"`, `!!bool "yes"`,
  `!!float`, `!!str`, `!!binary`, `!!set`, `!!omap`, `!!pairs`, `!!timestamp`, a
  bare `!` or a local `!tag`) is refused, so a tag cannot bring back a spelling
  the rules above refuse. No shipped file uses one.
- **Keys given twice are refused after they are read, not only as written.** Two
  keys that read as one value (`10:` and `012:`, `1:` and `1.0:`, `1:` and
  `true:`) are refused as one key given twice. Every repeat in the file is
  reported, each with its line.
- **What is kept.** The decoded value goes on through the pipeline. The text of
  each scalar as written is kept apart from it, for messages only (see
  "Sensitive inputs").
- **Half a character is refused.** A quoted `"\ud800"` reads as half of a
  character, text MongoDB cannot store; in a key it once stopped a sync after
  the reference data was written (review of the build, below).
- **Every file gives problems, never an exception.** A control character (a form
  feed, NUL), a number past Python's digit limit and lists nested past its
  recursion limit each become a problem with its place.

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
- `strict=True`: no conversion between str, int and bool. Strict mode still
  turns a whole number into a float (9007199254740993 becomes
  9007199254740992.0), so **no rulebook has a `float` field**. When a later step
  needs a decimal number, it is read as text and parsed as a `Decimal` with a
  stated precision and range, never as a float.
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
  not derive from `StrictRules`, loosens its config, loosens a single field
  (`Field(strict=False)` or any other per-field override of the strict
  settings), has a `float` field, uses a `Literal` with a non-text value, takes
  `Any`, or has a validator that runs before the type check
  (`BeforeValidator`, `PlainValidator`, `WrapValidator`, or a field or model
  validator in any mode but `after`: `BeforeValidator(int)` reads `"012"` as 12).

**Rules relating several keys** (the colour fields depend on `chemistry_type` and
`color_balance_enabled`; a reagent kit limit names a kit some flow cell offers)
are not Pydantic model validators, which stop at the first failure and give no
key. Each is a separate check function that returns problems with an explicit
path. **They run only on a fully checked result:** when field validation fails,
Pydantic gives back the errors and no partial result, so the cross-key checks
do not run, and the file's answer says that further checks run once these
problems are fixed. When field validation passes, every cross-key check runs, so
independent cross-key problems are all reported together. No check ever reads
the raw data.

### 3. Problems

`InputProblem(file, line, column, path, message, level)`, with `level`
`"error"` or `"warning"`, and `column` where the reader knows it (always for a
YAML syntax error; two unfinished lists on one line differ only by column).

- **What is reported**: all reader problems of a file; else all field errors of
  a rulebook (Pydantic gives them together); else all cross-key problems (see
  "Rules relating several keys"). Each stage runs only when the one before
  found nothing, and the answer says so.
- **A cap per file.** A file stops collecting at 1000 problems and adds one
  saying how many more it found, so a broken or hostile file cannot fill the
  memory or the stores below.
- **YAML syntax errors** get a fixed explanation per kind of parser error (a list
  or map not closed, a tab, an unexpected character, ...), with the line and
  column; unknown kinds get "is not valid YAML here". PyYAML's own text
  is never shown (see "Sensitive inputs").
- **Locations.** Pydantic's error location is mapped to the location map: a
  mapping key's line for an unknown key or a bad map key (Pydantic's `[key]`
  suffix); the value's line for a bad value; the item's line for a list item; for
  a missing key, the line of the mapping it is missing from (line 1 for the top
  level); for a cross-key check, the path it names. A test covers each kind.
- **Paths.** A map key is always text in a problem's path and a list index is a
  number, shown "item 1": a map key read as a number once read as a list item
  (`default_cycles > item 301` for the key `300`).
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
- **a key name can be a secret too**: Pydantic puts an unknown key's name in the
  error location (a connection string written as a key comes back whole). In a
  sensitive input, a path shows only the names the rulebook itself defines; any
  other key or map key is shown as "an unknown key" with its line and column;
- keeping the original text of a scalar (above) does not make it safe to show.

### 4. Values survive conversion

- **Every number's range is the narrowest range its downstream code accepts
  without changing it, storage included.** Where the app clamps a value
  (`RunCycles` clamps cycle counts to 0-1000, `models/sequencing_run.py:245`; the
  cycle fields of a run are refused above 600, `routes/runs.py:476`), the
  rulebook refuses what would be clamped or refused later. MongoDB stores a
  whole number in 64 bits, so no range goes past 2^63 - 1 (a larger `reads`
  passes the model and then fails to save). Step 1 lists every number in the
  instrument rulebook with the code that consumes it, its storage, and its range.
- **A round-trip test** converts checked files, including values at each range's
  edges, into the domain objects, **saves them as the app does (`to_dict`, BSON
  encoding), reads them back (`from_dict`)**, and compares every field with the
  checked value. Normalisation that is meant (for example a sequence uppercased)
  is named in the test.
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

Open after step 1: two rules exist in both layers, the kit limit (the model's
`checked_kit_cycle_limits`; the rulebook's `KIT_CYCLES` and its cross-check) and
a workflow named twice ignoring case (the model's `_i5_workflows_problems`;
`_instrument_findings`). The model needs them for stored records and the
rulebook for a file's lines; moving each into one pure function both call is
left for the profiles step.

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
  message, which names each refused file and its first problem only, and adds
  a `problems` list (`{file, line, path, message, level}`) that has them all; a
  message holding every problem was once cut before the refusals after it and
  "Mark Ready stays paused", which the scheduler reads;
  Admin > Configuration sync shows it as a table. As today, a refused file keeps
  the stored records it would have replaced. Warnings are shown there too, not
  only logged.
- **Bounded stores.** The sync status is one MongoDB document (16 MiB at most) and
  an audit row's details are dropped whole above 64 KiB (`models/audit_event.py`,
  `MAX_DETAILS_BYTES`); a long enough report fills either (100,000 unknown keys
  come to about 17 MB). So each store gets a budget in encoded bytes for
  **everything** it holds, today's message included: the sync status keeps at
  most 1 MiB of problems, an audit row at most 32 KiB of details in all. What does
  not fit is left out from the end, and both always keep the outcome, the number
  of problems and the number left out. An audit row's report is measured as
  `audit()` keeps it, each web address in it already made `[address removed]`,
  which can make a text three times longer. The page says how many are not shown and
  that the settings command lists them (up to the per-file cap).
- **The audit trail.** Every sync's audit row carries its problems, within that
  budget, whether the sync was started by hand or by the scheduler (today a
  manual sync's row has the outcome and count only:
  `routes/admin/config_sync.py:171-177`; a scheduled sync's row carries the whole
  message, which alone can pass 64 KiB and lose the row's details).
- **Start-up.** A local file with an error stops start-up with every problem and
  its line (`InstrumentConfigError`, today naming the field but not the line).
- **The settings command** (below).

### 7. The settings command

`pixi run check-settings <folder>` (`python -m seqsetup.input_rules.cli`):

- checks a settings folder laid out as the sync reads it (the shipped `config/`
  is the example; options name other paths), with the same rulebooks and the same
  database-free cross-file checks the sync uses, and reads the files the sync
  reads: every name ending `.yaml` or `.yml` in the folder and those below it.
  GitHub lists a link to a folder as a link, which the sync skips, and a link
  to a file as a file whose text is the link's target path, which the sync
  reads and refuses (checked on a live listing, 2026-10-18); the command
  skips the first and reads the second as that text (sol's design review of
  step 2, P2-4);
- fails when the instrument folder is not there or holds no instrument file,
  rather than pass having checked nothing; `--instruments` names a folder inside
  the settings folder;
- prints one problem per line, `file:line:column: path: message` (the column
  where it is known), warnings marked, every problem it collected (up to the
  per-file cap, then the count of the rest);
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

**Rule: a fact that changes a sheet or a check must be written out.** There is
one named exception: `samplesheet_versions`, which may be left out and then means
`[2]` (the admin guide's documented default; 9 of the 11 shipped synced files
leave it out). A new exception must be named here, documented in the admin guide
and tested. Labels (`sbs_chemistry`, `error_tendencies`, a flow cell's `reads` and
`description`) may be left out.

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
| `onboard_applications` | yes | map of an Illumina application name to `{software_version: version text}`; the version is required |
| `flowcells` | yes, at least one | map of a name to `{lanes, reagent_kits, reads, description}` |
| `flowcells > * > lanes` | yes (today defaults to 1) | whole number, 1 to 8 (see below) |
| `flowcells > * > reagent_kits` | yes | list of distinct whole numbers, 1 to 2000 each; `[]` is allowed and means the flow cell sets no kit limit (`services/run_builder.py`) |
| `flowcells > * > reads` | no | whole number, 0 to 2^63 - 1 (storage) |
| `flowcells > * > description` | no | label |
| `reagent_kit_max_cycles` | no | today's rules (`instrument_validator.py:234-268`): a map of a kit label (a whole number) to the most cycles allowed (a whole number, at least the label); a label no flow cell offers is a warning |
| `i5_read_orientation`, `samplesheet_v2_i5_orientation` at the top level (`OLD_I5_KEYS`) | refused | with today's message (`_refuse_bad_i5_facts`), not the generic unknown-key one |

Every other key is refused.

**The local file's cycle sections** — neither is checked today:

- `default_cycles`: a map of a reagent kit's cycles (a whole number) to
  `{read1, read2, index1, index2}`: `read1` 1 to 600; `read2`, `index1` and
  `index2` 0 to 600 (`routes/runs.py:476-500`; Read 2 = 0 is a single-end run).
  The outside review confirmed these survive the route's parser, the cycle
  calculator and a new run unchanged. Code that tolerates Read 1 = 0 is not a
  supported workflow, so Read 1 stays at least 1.
- `index_cycle_options`: a non-empty list of distinct whole numbers, each one an
  index cycle count a run accepts.

**Ranges.** Every number has the range its consumers accept unchanged (section 4),
recorded with its source in `input_rules/instruments.py`:

- a flow cell's `lanes`: 1-8. The run page draws a box per lane
  (`range(1, num_lanes + 1)` in the lane panel and the LIMS import), and no
  Illumina flow cell has more than eight lanes.
- a reagent kit's cycles (`reagent_kits`, the keys of `reagent_kit_max_cycles`
  and of `default_cycles`): 1-2000, the reagent kit field's own range
  (`routes/runs.py`: `max(1, min(..., 2000))`); a kit above it would be read as
  2000 and then not found among the flow cell's kits.
- `default_cycles`: read 1 1-600; read 2 and both indexes 0-600.
- `index_cycle_options`: 1-600.
- a flow cell's `reads` and a kit's most cycles: up to 2^63 - 1, MongoDB's limit;
  nothing reads them as a bound.

The local file's three top-level keys are all required: the shipped file has
them, and without `default_cycles` or `index_cycle_options` the app fell back
to defaults nobody wrote.

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
  `1.10`, `yes`, `~`, a date); each explicit tag (`!!int "012"`, `!!bool "yes"`,
  `!!binary`, `!!set`); an anchor; `[true, 2.0]` for
  `samplesheet_versions`; each required key; the colour-field rule; the
  multi-instrument wrapper (an extra key, a `name` that differs from its map
  key); each number at and past its range's edges; the local file's two cycle
  sections.
- A test per location kind (mapping key, value, list item, map key, missing key,
  cross-key check), and syntax errors that differ only by column.
- The guard test (including a per-field `strict=False` and a `float` field), the
  round-trip test through BSON and back, the drift test, the command's isolation
  test, the store-budget tests (a report far over each budget, with a long
  message, still leaves the sync status under its budget and an audit row with
  its details and counts), the per-file cap, and a sensitive-input test (a
  credential written as an unknown key never appears in a message, log or audit
  row).
- The shipped instrument files and the shipped local file pass through the new
  reader (today's tests load them with plain `yaml.safe_load`).
- The existing instrument tests (about 100) keep passing; any changed test keeps
  its guarantee and is listed.
- Break checks: each rule switched off in turn turns a test red.
- The full check: the 78 Sample Sheets are unchanged.
- Before merging, the settings command is run on the lab's real settings
  repository, and the user sees what it would refuse.

## Step 2: application and test profiles

### Decided by the user (2026-10-18)

- **Application names.** A profile whose `ApplicationType` is `Dragen` (in any
  case, as today) must name one of Illumina's applications
  (`ILLUMINA_APPLICATION_NAMES`), so `DragenGermlin` is refused. Any other type
  (`External`, `Cloud`, ...) keeps any plain name, as the admin guide documents
  for a downstream tool's section. (The short note above said Illumina's names
  only; the guide's external profiles were missed.)
- **The keys inside `Settings` and `Data` stay open**: any plain name, as today.
  Illumina's key lists change with each DRAGEN version, and a stale list would
  block a lab's valid key; the instrument's software judges the names. Their
  shape is checked in full (below).
- **A true/false value is written as today**, `True` or `False`: step 2 changes
  no Sample Sheet. Whether DRAGEN wants `true` or `True` is a later item of its
  own, after a look at Illumina's documents.

### What a new file needs

A new profile, test, instrument or version of one is checked by the same rules
and needs no code change. Code changes only for what changes what the app does:
an application Illumina adds (one line in `ILLUMINA_APPLICATION_NAMES`, with
its source), or a new fact SeqSetup reads from an instrument file (its rulebook
field comes with the code that reads it).

### The structure every profile has

Every key of both documents is named; any other key is refused. The keys
inside `Settings` and `Data` are open, but their shape is not.

**An application profile** (one per file):

| Key | Required | Value |
|---|---|---|
| `ApplicationProfileName` | yes | filled text, 1-256 characters |
| `ApplicationProfileVersion` | yes | filled text, 1-256, a PEP 440 version |
| `ApplicationName` | yes | a plain name (letters, digits, `_`, `-`), 1-256; one of Illumina's when the type is `Dragen` |
| `ApplicationType` | yes | filled text, 1-256 |
| `Settings` | when `Dragen` | a map of a plain name to a sheet value; empty allowed |
| `Data` | when `Dragen` | as `Settings` |
| `DataFields` | when `Dragen` | a list of plain names |
| `Translate` | no | a map of a plain name to a plain name |

**Filled text** holds at least one character that is not a space: a value of
spaces only is refused, as `_is_empty` refuses it today. The value is stored
as written, never trimmed. The type is `Dragen` when its text, trimmed and in
small letters, is `dragen` (today's `.strip().lower()`).

A **sheet value** is text of at most 4,096 characters, a whole number within
64 bits, or `true`/`false`. Text holds no hidden character (a line break, a
tab, an invisible control) and does not start with `[`, even after spaces.
`''` is an empty cell; a key with nothing after it is refused ("needs a value:
write '' if it should be empty", today's wording). An empty section (`Settings:` with nothing under it) means
none: for `Translate` in every profile, and for the other three in a profile
whose type is not `Dragen`, as today; a `Dragen` profile's `Settings`, `Data`
and `DataFields` must be maps and a list, as today.

**One setting has a value rule of its own: `SoftwareVersion`**, the one the
app reads (the validation service compares it with the instrument's onboard
versions and sorts the versions a run asks for). It is a plain version (text of
letters, digits, `.`, `_` and `-`, 1-256), the rule the instrument's
`software_version` follows; a whole number such as `SoftwareVersion: 4` is
refused. Today it is accepted, and a run with `4` in one profile and `"4.3.6"`
in another stops the run check with `TypeError: '<' not supported between
instances of 'str' and 'int'` (`services/application_profile_validator.py`,
`sorted(versions_map.items())`). That sort also compares the versions as text,
so a profile stored before this rule cannot stop the check either. The other
setting names stay open.

**Errors in a value of several kinds** (a sheet value) are reported once, at
the value's own path: a missing value "needs a value: write '' if it should be
empty"; a value of another kind "must be text, a whole number or true/false";
a value of a matching kind that breaks a bound gets that bound's message. Step
1's checker gives one error per kind, at paths with Pydantic's names for the
kinds (`Settings > Threads > constrained-str`); the checker drops a segment
that names no key in the data and merges the errors at one path.

**A test profile** (one per file):

| Key | Required | Value |
|---|---|---|
| `TestType` | yes | filled text, 1-256 (a sample's test ID is at most 256) |
| `TestName` | yes | filled text, 1-256 |
| `Description` | yes | filled text, 1-4,096 |
| `Version` | yes | text, three whole numbers joined by dots (`PROFILE_VERSION_RE`) |
| `ApplicationProfiles` | yes | a list of at least one reference |

A reference holds `ApplicationProfileName` (filled text, 1-256) and
`ApplicationProfileVersion` (filled text, 1-256, a PEP 440 version or
specifier; `SpecifierSet("")` and `SpecifierSet(" ")` are valid specifiers, so
"filled" is checked first), and nothing else. A test's `Version` is bounded by
its own rule (three numbers of at most 9 digits).

**The rules relating keys move from `services/profile_validator.py`**, with
their substance and their tests (section 5): the mismatch values (0, 1 or 2 in
`Settings`; also blank or `na` as a `Data` default, under the column `Translate`
gives it); a `Sample_ID` column; no column written twice, whatever its case; in
the `BCLConvert` profile no name both in `Settings` and among the columns, and no
setting that changes how BCL Convert reads the i5 (`is_i5_rule_setting`); a
name SeqSetup fills itself spelled its one way (`SPELLED_*`); the three
`Dragen` sections. `profile_validator.py` is removed. The `SPELLED_*` names
move from `services/sheet_plan.py` into `services/sheet_text.py`, which the
rules already use and which imports nothing of the app: `sheet_plan` imports
`cycle_calculator`, which imports `data.instruments` and its start-up, so with
a broken `INSTRUMENTS_CONFIG` merely importing `SPELLED_SETTINGS_ANY` stops
with `InstrumentConfigError`, and the settings command could not run.
`sheet_plan` imports them from there; the command's isolation test also
asserts `services.sheet_plan` and `services.cycle_calculator` are not loaded.

**The rules across files** need no database and move into `input_rules` as
pure functions the sync and the settings command both call: a profile name and
version in two files (`_refuse_repeated_app_versions`); a test and version in
two files (`_refuse_repeated_test_versions`); two tests differing only in
capitals (`_refuse_tests_differing_only_in_capitals`).

### What changes for a lab

Every change is a refusal with its file, line and place; nothing is accepted
that was refused before, and no Sample Sheet changes. Each of these is accepted
on `58510df` (probed with the old validator, 2026-10-18):

- an unknown key, at the top of either document (`Setings:`, `Owner:`) or in
  a test's reference (`Note:`), ignored today;
- a whole number where text belongs: `ApplicationProfileVersion: 1`,
  `ApplicationType: 1`, `TestName: 5`, and `TestType: 5`, which passes the
  validator and then stops the sync with `'int' object has no attribute
  'lower'`, naming no file;
- `yes`, `no`, `on`, `off` as a value (today written `True`/`False`): "write
  true or false";
- a value YAML changes before any check: `012` in `Settings` is written as
  `10` today; and the tags, anchors, merge keys and repeated keys the reader
  refuses for every file (section 1);
- a `Dragen` profile with an application name that is not Illumina's
  (`DragenGermlin`);
- a value over 4,096 characters, or a name, type, test or version over 256
  (`1.0+` and 5,000 letters is a PEP 440 version, and `===` and 5,000 letters a
  specifier, both accepted today);
- `SoftwareVersion` written as a whole number (`SoftwareVersion: 4`).

The fresh review of `b21ea6f` found more, each accepted on `bd8c87f` (probed
2026-10-18, the old sync's `safe_load_strict` and `from_yaml`):

- a `SoftwareVersion` that is empty (`''`), true/false, or holds another
  character (`4.3.6+abc`);
- a list or map where text belongs (`TestType: [a]` was stored as a list,
  `ApplicationType: {a: b}` as a map);
- a whole number past 64 bits in `Settings` or `Data`, which passed the old
  check and stopped the sync's save after it had deleted the stored profiles;
- a `Settings`, `Data`, `DataFields` or `Translate` name over 256 characters;
- a `Dragen` profile naming an Illumina application in another case
  (`dragengermline`).

The shipped profiles pass unchanged, and the settings command is run on the
lab's settings repository before merging, as in step 1.

### Where it runs

- **The sync** reads each profile file with the reader and the rulebook in
  `_fetch_profiles_recursive` (today `safe_load_strict` and the old validator):
  its problems join the sync's list, shown on the Config Sync page and in the
  audit row; a refused file is named with its first problem, and a refused
  file keeps the stored profiles as today.
- **`ApplicationProfile.from_yaml` and `TestProfile.from_yaml`** stay the one
  builder of each model; they check their dict with the rulebook (the data
  path, without lines) and raise `ProfileValidationError` listing the problems.
  The sync and the command check the file's text first, with lines, and build
  from the checked value.
- **The settings command** checks `profiles/application_profiles/` and
  `profiles/test_profiles/` (`--application-profiles`, `--test-profiles`), the
  sync's default paths, reading what the sync reads (a `.yaml` or `.yml` ending
  in any case, as the sync takes it for profiles; a link to a file read as the
  link's target path and a link to a folder skipped, as for instruments in step
  1), and runs the cross-file rules. A missing profile folder is an error, as for instruments;
  `--no-instruments` is for a lab whose sync does not read instruments.
- **The stored profiles** (`from_dict`) and the Sample Sheet writer's backstops
  (`_escape_config_cell`, `_require_profile_mismatch`) are unchanged.
- **`docs/admin-guide/profiles.rst`** gets both key tables and the value
  spellings; a test fails when a rulebook key is missing from it.

### How step 2 is proved

- Red tests first: each unknown key refused with its line, also inside a
  reference; each required key, and each filled text given spaces only; each
  value kind in `Settings` and `Data` (text, a whole number, true/false; a
  list, a map, an empty value refused), each reported once at its own path; the
  Dragen name rule both ways, and `" dragen "` read as `Dragen`; an empty
  `Translate:` in a `Dragen` profile meaning none; `SoftwareVersion: 4`, and
  the validation service given a stored `4` beside `"4.3.6"`; `TestType: 5`;
  each bound at and past its edge, the two versions included.
- The old validator's tests (84 in `test_profile_validator.py`, and the profile
  tests in the files that build profiles through `from_yaml`) keep their
  guarantee on the new path; any changed test is listed.
- Every shipped profile gives the same model (`to_dict`, but its id and time)
  on the old path and the new, and survives the model, BSON and back.
- The cross-file rules, through the sync and through the command; a linked
  profile file refused by both.
- Break checks, the full check (the 78 Sample Sheets unchanged), a fresh
  review, and the lab's settings repository through the command.

## Step 3: index kit files, every format

### The formats, measured

Five file shapes reach `IndexKit` today, and the code that picks among them is
`IndexParser._detect_format` plus the file's ending
(`services/index_parser.py`), with the sync reading only the first:

| Shape | Read by | Name in the file | Version in the file | Mode when the file names none |
|---|---|---|---|---|
| **SeqSetup YAML** (`index_mode`, `index_pairs`, `i7_indexes`) | the sync (`index_kit_sync_parser.py`) and the upload (`_parse_sync_yaml`) | `name` | `version` | `unique_dual` |
| **Illumina YAML** (`Name`, `Version`, `IndexSequences`) | the upload (`_parse_illumina_yaml`) | `Name` | `Version` | Single with no i5, else Unique Dual |
| **Illumina TSV** (`[IndexKit]`, `[Indices]`) | the upload (`_parse_tsv`) | `[IndexKit]` `Name` | `[IndexKit]` `Version` | Single with no `IndexNumber 2` line, else Unique Dual |
| **plain CSV** (`name,index,index2,...`) | the upload (`_parse_csv`) | never | never | Single with no `index2` cell, else Unique Dual |
| **sectioned CSV** (`[i7]`, `[i5]`, `name,sequence,well`) | the upload (`_parse_combinatorial_csv`) | never | never | Combinatorial, always |

`services/index_validator.py` is **not** a file reader and **not** a backstop
for stored records: nothing validates a kit built by `IndexKit.from_dict`, and
its only two callers are the upload (`routes/indexes.py:220`) and the sync
(`github_sync.py:1095`) — the two paths the rulebook joins. It is a second
ingest-time check with rules of its own (semantic versions, the cycles equal to
every index's length, at least one index, no repeated name). It stays where it
is and keeps every rule it has; which layer owns which rule is written out
below.

### The shape: five adapters, one rulebook

Each shape gets its own **adapter**, and every adapter produces the same
canonical kit map — the keys of the SeqSetup YAML format, which is the one
`IndexKitYamlExporter` writes back. One **canonical kit rulebook**
(`input_rules/kits.py`) checks that map, and `build_kit` then makes today's
`IndexKit` from the checked value only.

- **YAML shapes** go through the step 1 reader (`read_yaml`), so they get the
  plain-value spellings, no tags, no anchors, keys-given-twice and every
  problem's line and column for nothing.
- **The two CSV shapes** go through a new **table reader**
  (`input_rules/table.py`) that keeps each row's own line number and **refuses
  a column name given twice before any row is read** — including two columns
  spelt the same, which `_columns_not_read` lets through today because it only
  compares two *different* spellings of one normal form.
- **The TSV shape stays line-oriented**, as it is today: its `[Indices]`
  section is positional (name, sequence, index number) and may have **no
  header at all** (`A1 ATTACTCG 1` as the section's first line reads as an
  index today; `test_a_file_with_no_header_line_still_reads_its_indexes` pins
  it), so a column-oriented reader would swallow an index. The adapter keeps
  today's header rule (a first content line carrying no sequence is the
  header) and today's per-line `IncompleteIndexRows`. `[IndexKit]` is read as
  key/value lines.
- **A name is stripped where it is stripped today.** The Illumina YAML strips
  each index name before counting a repeat (`' A '` is stored as `'A'`, and
  `'A'` with `'A '` in one list is refused as a repeat), and the TSV strips
  every cell. The adapters do that stripping, and the **stripped** text is what
  the canonical map carries — a meant normalisation in the sense of section 4,
  beside the uppercasing of a sequence. The rulebook itself trims nothing.
- The adapters keep every refusal the parsers make now, each with its own
  `KitFileRefused` subclass and the same text or more: a column that looks
  like an index or a lane but is not read, a cell under no column name, i5
  data in a Single kit, pairs in a Single kit, a list the mode does not read,
  indexes that do not pair up by name, a name given twice, a name or sequence
  YAML does not read as text, two keys for one list, an incomplete row, a line
  in a section this format does not read. **A refusal is never dropped and
  never made vaguer.**
- Kit files are **not sensitive**: no field can hold a credential (name,
  version, description, comments, DNA, well positions), so `values_safe=True`
  and a message may quote a value, as the parsers' messages do today. A quoted
  value is **cut to 60 characters**: `_refuse` quotes a scalar whole today, so
  a 100,000-character scalar gives a 100,109-character message, and with the
  upload's 1 MB cap that message is shown in the admin's HTML. The cut is a
  fix in `reader.py` that instrument and profile files share (both are
  `values_safe` too), with a test of its own.

### The canonical kit rulebook

| Key | Required | Rule |
|---|---|---|
| `name` | yes | filled text, 1-256, no part between `/` made only of dots |
| `version` | yes | filled text, 1-256, no `:`, no `/`, no part made only of dots |
| `index_mode` | yes | `unique_dual`, `combinatorial` or `single` |
| `description` | no | text, at most 256 |
| `comments` | no | text, at most 256 |
| `is_fixed_layout` | no (false when absent) | true/false |
| `adapter_read1`, `adapter_read2` | no | DNA text, `[ACGTN]` after uppercasing and stripping, at most 1000 |
| `default_index1_cycles`, `default_index2_cycles` | no | whole number, 1 to 600 |
| `default_read1_override`, `default_read2_override` | no | text of `Y I U N`, digits and `*`, at most 256 |
| `index_pairs` | at least one in `unique_dual`; empty or absent in the others | a list of at most 20,000 pairs |
| `i7_indexes` | at least one in `combinatorial` and `single`; empty or absent in `unique_dual` | a list of at most 20,000 indexes |
| `i5_indexes` | at least one in `combinatorial`; empty or absent in the others | a list of at most 20,000 indexes |

An **index** is `{name, sequence, well_position}`: `name` filled text 1-256,
`sequence` DNA text 1-1000 (`[ACGTN]` after uppercasing and stripping),
`well_position` text at most 256 or absent. A **pair** is
`{name, index1, index2, well_position}`: `name` filled text 1-256, `index1` an
index, `index2` an index or absent.

**A list the mode does not read is refused** as a cross-key check with the
adapters' own message, so the rule holds for a file reaching the rulebook by
any road. Only a **non-empty** unread list is refused — `i7_indexes: []` in a
unique_dual file passes today (`data.get(key)` is falsy) and no index goes
missing, so it still passes.

`created_by` and `source` are not file keys: the sync and the upload route set
them, as today. A kit file naming either is refused as an unknown key.

**Why these bounds.**

- `name`, `version`, `description` and `comments` are cut at 256 by
  `IndexKit.__setattr__`, so 256 is what is stored; above it the rulebook
  refuses, since a cut name is another name (CLAUDE.md).
- An index's `name` and `well_position` have **no cap at all** today: a name of
  5,000 characters is stored in full (measured) and rides onto a sample as
  `index1_name` and into the JSON export. 256 is the cap every other
  identifier in the app has (`MAX_SAMPLE_TEXT`).
- A `:` in the **version** makes the stored `_id` (`name:version`) hard to
  read, and `IndexValidator` already refuses it as not a semantic version — on
  both paths that store a kit (measured) — so the rulebook only says it sooner,
  by name and line. A `:` in the **name** is **not** refused: it is storable
  today (measured, `IndexValidator` passes it), nothing in `src/` ever splits
  a `kit_id`, and with a colon-free version the last colon of the `_id` still
  separates name from version, so two kits cannot share one document.
  Refusing it would make a lab rename such a kit, which makes a new kit and
  orphans the `index_kit_name` already stored on its samples. The other option
  — refuse a colon in both — is in the run's QUESTIONS for the user.
- `default_index*_cycles` is clamped to at least 1 by the model and must equal
  the length of every index in its slot
  (`IndexValidator._validate_index_cycles`), and a run reads at most 600 index
  cycles (`routes/runs.py`), so 1-600. A sequence may be longer than that:
  1-1000 is a sanity cap nothing reads as a bound, and a kit with indexes over
  600 bases can therefore never state its default cycles.
- `default_read*_override` is held to the `Y I U N` digits `*` alphabet by the
  model.
- **20,000 items a list.** Nothing bounds a kit's size today: 20,000 pairs make
  a 4.72 MB BSON document from a 2.63 MB file (measured, ratio 1.80), and the
  sync's 10 MB per-file cap would give about 18 MB — over MongoDB's 16 MiB,
  and the stored synced kits are deleted before the new ones are written
  (`github_sync.py:484-485`). 20,000 is some fifty times the largest shipped
  kit (384 pairs).

### Which rules live in two layers, and why

| Rule | Owner | Also in |
|---|---|---|
| DNA alphabet `[ACGTN]` | the models (`Index.__post_init__`, `IndexKit.__setattr__`) | the rulebook, which says it by line; `IndexValidator` for the adapters |
| a sequence or a name is not empty | the rulebook | `IndexValidator` (at least one index, no empty sequence) |
| the default index cycles equal every index's length | `IndexValidator` | not in the rulebook: it needs the whole kit, and the rulebook only bounds the number |
| the version is a semantic version | `IndexValidator` | not in the rulebook, which bounds the text only |
| the text caps (256) | the rulebook, which refuses | the models, which cut — the backstop for a stored document |
| a kit name and version in two files, or changed under one name | `github_sync._refuse_changed_or_repeated_kits` | it needs the stored kits (CLAUDE.md); the settings command calls a pure `repeated_kit_versions` in `input_rules` for the two-files half |

### The adapters, key by key

- **SeqSetup YAML**: the canonical map already. Every key above, nothing else.
- **Illumina YAML**: `Name` -> `name`, `Version` -> `version`,
  `Description` -> `description`, `IndexSequences.i7Index1` (or `Index1`) and
  `.i5Index2` (or `.Index2`), each a map of a name to a sequence, into
  `i7_indexes` / `i5_indexes`, each name stripped. Two keys for one list stay
  refused, and so does a name or sequence YAML does not read as text — which
  the reader now refuses first, by its line.
- **Illumina TSV**: `[IndexKit]` gives `Name`, `Version`, `Description`;
  `[Indices]` gives name, sequence and index number (1 for an i7, 2 for an
  i5), positionally, every cell stripped. Every line outside those two sections
  stays refused with its line.
- **plain CSV**: the header's columns as `_CSV_*_COLUMNS` name them, through
  `_column_key`'s normal form, into `index_pairs` (or `i7_indexes` in Single
  mode), exactly as today.
- **sectioned CSV**: `[i7]` and `[i5]`, each `name,sequence,well`, into
  `i7_indexes` and `i5_indexes`.

### Which index mode the kit gets

The mode decides which indexes a sample can be given, so it is the one field
that must not be guessed. Today the **form's** picker always wins on the upload
path: `routes/indexes.py` sends `index_mode` with the default `"unique_dual"`,
never `None`, so `mode = index_mode or file_mode` never reads the file's key —
a file saying `index_mode: combinatorial` uploaded as Single is stored as a
Single kit, with no word (measured, and `IndexValidator` says nothing).

- The picked mode still wins, as today.
- A file that **names a different mode** than the one picked is **refused**,
  naming both — the only answer that invents nothing and changes no accepted
  case. A file that names the picked mode, or names none, is unchanged.
- For a **synced** file there is no picker, so `index_mode` is a required key.
- Where a shape has no `index_mode` key at all (the table above), the adapter
  synthesises exactly today's value, and the file is the only source.

### Where a name and a version come from

A kit's name and version are its identity: the stored `_id`, the URL of its
page, its download and its Delete, and what `_refuse_changed_or_repeated_kits`
compares between syncs. **A name or version nobody gave is never invented
without the person seeing it.**

- **A synced file** must write both: `name` and `version` are required keys,
  refused by name and line. Today a file with no `name` is stored under the
  file's name made into a title (`my_kit_file.yaml` -> `My Kit File`) and a
  file with no `version` under `1.0` (measured) — so the file's own name
  decides the identity a sync compares.
- **An upload** may give them in the file or in the form: `routes/indexes.py`
  already takes `kit_name` and `kit_version` text boxes
  (`templates/indexes/import.html`), and a value typed there wins over the
  file's, as today. **A file giving neither and a form giving neither is
  refused**, naming both places — including the two CSV shapes, which carry no
  key for either, so a CSV upload now needs the two boxes filled in. Today a
  CSV is stored under the upload's filename without its ending, and under
  version `1.0`; a filename such as `my:kit.csv` becomes the kit's name, and a
  300-character filename is cut to 256 (both measured). The other option —
  keep the filename for a CSV, since the shape never carries a name — is in
  the run's QUESTIONS.
- **The form's own boxes are checked by the same rules**, not only the file's
  keys: `kit_name`, `kit_version`, `kit_description`, `comments` and
  `adapter_read1/2` are refused, never cut, with a message naming the box.
  Today a 300-character Kit name is cut to 256 and an 8,000-base adapter is
  stored (measured). The two index-override boxes keep today's reading:
  `IndexValidator` already refuses a cycle count that is not every index's
  length.
- **A value with no line is reported as its source.** A name or version that
  comes from a box or from the upload's filename has no line in the file, so
  its problem names the box ("Kit name") or the file's name, with no line and
  no invented path.
- `normalize_version` (`"1"` -> `"1.0"`) stays exactly where it is, on the
  upload path only, after the check: it is the builder's business, and
  changing it would change the stored identity of a kit a lab uploads.
- **A pair's `id` keeps the name the file gave.** `IndexPair.id` is
  `f"{kit_name}_{pair_name}"` built while the file is read, and the form's name
  override is applied to `kit.name` afterwards, so a kit uploaded with a Kit
  name of `FormKit` from a file naming `FileKit` has `kit.name` `FormKit` and
  pair ids `FileKit_P1` (measured). `build_kit` keeps that order: the ids are
  in `fingerprint()`, so changing it would move the fingerprint of a file both
  versions accept.

### What a new file needs

A new kit file, or a new version of one, is checked by these rules and needs no
code change. Code changes only for a new fact SeqSetup reads from a kit file
(its rulebook field comes with the code that reads it) or a new file shape (its
own adapter).

### Where it runs

- **The sync** reads each kit file with step 2's pair,
  `check_index_kit_file(text, path) -> CheckResult` and
  `build_kit(value, filename)`, and extends `self.input_problems`, so every
  problem reaches the Config Sync page and the audit row within their byte
  budgets — `IndexKitSyncParser.parse`'s `Optional[IndexKit]` could carry only
  the first. A refused file keeps the stored kit of that name and version, as
  today, and `refused["name"]` stays `None` for a file no kit could be built
  from, so `_synced_kits_to_keep` keeps every unread synced kit — today's
  conservative behaviour, unchanged (in the run's OPEN ITEMS).
  `_refuse_changed_or_repeated_kits` and the kit fingerprint are unchanged:
  they need several files and the stored kits (CLAUDE.md).
- **The upload** (`routes/indexes.py`) shows every problem with its line, in
  the list fragment it already has for validation errors
  (`_error_fragment_list`), instead of one "Failed to parse file. Please check
  the format and try again." for everything. `KitFileRefused` keeps its
  `reason` for the audit row, and the new `KitFileProblems` carries one too:
  `repeated_names` when a problem is the reader's "given twice" one (its
  wording becomes a constant in `reader.py`), so the audit row keeps the grain
  it has today, and `kit_file_problems` otherwise. The route's catch-all stays
  for anything unforeseen.
- **`pixi run check-settings`** checks the kit folder too, with its own
  `--index-kits` folder option (default `index_kits`, the sync's
  `ProfileSyncConfig.index_kits_path`) and a `--no-index-kits` beside
  `--no-instruments`, reading what the sync reads: a `.yaml` or `.yml` ending
  in any case, every folder below, a link to a file read as the link's target
  path and a link to a folder skipped. A missing folder is an error, as for the
  other folders. The shipped example folder is `config/indexes`, so the shipped
  settings folder is checked with `--index-kits indexes`; the guide says so.
  The command runs `IndexValidator` on each built kit, as the sync does, and
  reports a kit name and version two files give (`repeated_kit_versions`).
- **The stored kits** (`IndexKit.from_dict`) are unchanged: a kit stored before
  this change still loads, cut names and all.

### What changes for a lab

Every change is a refusal with its file, line and place; nothing is accepted
that was refused before, and no Sample Sheet changes. Each of these is
**accepted on `6e99e1f`** (probed 2026-10-19 with the old parsers,
`probes/base_kits.py`, `probes/verify_review3.py`, `probes/colon_collision.py`;
"stored today" is what the kit then held, after `IndexValidator`):

| The file or the form says | Stored today | New |
|---|---|---|
| a CSV with two columns named `index2` | the last column's sequence | refused, naming the column and its line |
| a CSV with two columns named `name` | the second column's value (`DictReader` keeps the last) | refused |
| a sectioned CSV with two columns named `sequence` | the last one's | refused |
| `is_fixed_layout: 'no'` | `is_fixed_layout` = the text `'no'` | refused: must be true or false |
| `is_fixed_layout: 'yes'` / `'true'` / `'maybe'` | that text | refused |
| `is_fixed_layout: 1` / `0` | the number | refused |
| `is_fixed_layout: no` / `yes` (unquoted) | false / true | refused by the reader (step 1's rule) |
| a `name`, `version` or `description` of 300 characters | cut to 256 | refused, over 256 |
| a `Kit name`, `Kit version` or `Kit description` box of 300 characters | cut to 256 | refused, naming the box |
| an `Adapter Read 1` box of 8,000 bases | stored whole | refused, over 1000 |
| an index `name` or `well_position` of 5,000 characters | stored whole | refused, over 256 |
| `version: '1:0'` | refused by `IndexValidator` ("not a valid semantic version"), with no line | refused by the rulebook, naming the key and its line |
| a synced file with no `name` | the file's name as a title (`My Kit File`) | refused: `name` is required |
| a synced file with no `version` | `1.0` | refused: `version` is required |
| an uploaded YAML or TSV with no name and an empty Kit name box | the file's name without its ending | refused, naming the file's key and the box |
| an uploaded YAML or TSV with no version and an empty box | `1.0` | refused |
| an uploaded CSV with the two boxes empty | the filename without its ending, and `1.0` | refused: a CSV carries neither, so both boxes are needed |
| a pair with no `name` in a synced file | the invented name `Pair_1`, and the pair id `K_Pair_1` | refused: a pair's `name` is required |
| an index inside a pair with no `name` | the pair's name | refused |
| an unknown key (`ownr:`) in any of the three YAML shapes | ignored | refused: not a key this file can have |
| an `id:` key on a pair | ignored; the pair's id is built from the kit's name and the pair's. `IndexKitYamlExporter` never writes one | refused as an unknown key |
| a `name`, `version` or `index_mode` written as a number, a true/false, a list or a map | read as whatever it was, or the key quietly ignored: `version: 1` became the version `1.0` on the upload (the sync refused it), and `index_mode: 3` was replaced with the mode picked on the form | refused, naming the key and its line; a mode that is not the one picked is refused naming both |
| a CSV column named `sequence2` or `seq_2` | ignored: the i5 went nowhere and the kit was stored as i7-only | refused as a column that looks like an index but is not one this format reads |
| a CSV header naming one slot twice under two different names (`index` beside `sequence`, `name` beside `Sample_ID`) | the first name read, the other's values gone | refused, naming both |
| a TSV `[IndexKit]` line that is not `Name`, `Version` or `Description`, or that has one cell (a real template's `AdapterRead1`) | dropped without a word | refused with its line |
| `version: 1.10` (unquoted) | the version `1.1` | refused by the reader: put it in quotes |
| `version: 1.0` (unquoted) | the version `1.0` | refused by the reader too: a decimal is quoted, or it is not text |
| a plain CSV uploaded as Combinatorial, or an `[i7]`/`[i5]` CSV uploaded as Unique Dual | refused by `IndexValidator` after the fact, with no line ("Combinatorial index kit must contain at least one i7 index"; "Unique dual index kit must contain at least one index pair") | refused where the lists are built, naming the lists and the mode |
| `comments: 12` | the number 12 | refused: must be text |
| a SeqSetup YAML naming a mode other than the one picked on the upload | the picked mode, the file's key unread | refused, naming both |
| a SeqSetup YAML with no `index_mode` and only `i7_indexes` | already refused (`KitListsNotRead`) | the same, plus `index_mode` is required in a synced file |
| more than 20,000 pairs or indexes in one list | stored, and a large enough file cannot be saved at all | refused, naming the list |
| a plain-CSV upload of one line of text that is no kit | a kit with no indexes, refused by `IndexValidator` with no line | refused with the line of the unreadable row |
| broken YAML on upload | "Failed to parse file. Please check the format and try again." | every problem with its line and column |
| broken YAML in a sync | the file is dropped, "could not be read as an index kit" | the syntax problem with its line and column |
| `default_index1_cycles: '8'` in a sync | the file is dropped with `'>' not supported between instances of 'str' and 'int'` in the log | refused: must be a whole number, with its line |
| `i7_indexes` written as a map in a sync | dropped with `'str' object has no attribute 'get'` | refused: must be a list, with its line |

**One accepted file gives another kit.** A file whose `name` is written
**empty** (`name: ''`, `name: ~` or spaces only) and uploaded with the **Kit
name** box filled in: the pair ids were built from the file's empty value
(`_P1`, `None_P1`, `   _P1`) and are now built from the name the person
typed, so the kit's `fingerprint()` moves. Such a file is refused outright in
a sync, where there is no box, so no stored synced kit is touched; an
uploaded one is stored under ids that name something.

**What stays accepted**, measured, so the step changes nothing it need not:
a `:` in a kit **name**; a sequence or adapter written as a block scalar
(`sequence: |`), whose trailing newline the stripping takes; an **empty**
`i7_indexes: []` in a unique_dual file; a `[Indices]` section with no header
line; an index name with spaces around it, kept without them; a plain CSV
whose columns are spelt `INDEX` or `Index_2`.

### How step 3 is proved

- Red tests first, for every rule: each table row above, with the line the
  problem names; every required key; each bound at and past its edge; each
  kind of value in the wrong place; the colon rule for the version; the mode
  rules both ways; an index with no sequence, a sequence that is not DNA, a
  well position too long; each row of "What stays accepted".
- Every refusal the parsers make today, on the new path, with the same or a
  more exact message: the existing tests of `test_index_parser.py` (58),
  `test_kit_file_nothing_dropped.py` (44), `test_index_kit_sync_parser.py`
  (10), `test_index_validator.py` (32), `test_kit_sync_unique_keys.py` (5),
  `test_kit_fingerprint.py` (5), `test_kit_index_cycles_equal_length.py` (12)
  and `tests/integration/test_index_safety_net.py` keep their guarantee; any
  changed test is listed in STATUS.md with its reason.
- The guard test covers each new rulebook (it reads every model in the
  package).
- **A differential probe** (`probes/kits_diff.py`) runs `6e99e1f` and the tip
  on every kit file in the repository (`config/indexes/*`, every kit text in
  `tests/`, `docs/`) and on generated variants (keys removed, reordered,
  retyped, columns swapped and doubled, CRLF, a byte order mark, blank lines,
  comments): for every file both accept, the built kit must be the same in
  every field and in `fingerprint()`; every file only the base accepts must be
  a row of the table above; **a file only the tip accepts is a defect**. The
  seven shipped `config/indexes/*.yaml` and `combinatorial_example.csv` are in
  it, so "the shipped files are unchanged" is measured, as in steps 1 and 2.

  **Measured on 2026-10-19** (`probes/kits_diff.py`, 1,337 inputs: every
  shipped kit file in four modes with and without the form's boxes, the five
  shapes written out, and up to 40 generated variants of each -- including
  each scalar key present but empty, null or spaces only, and each written as
  a number, a true/false, a list or a map, the blind spots the fresh review of
  the build found): **308 give the same kit**, field for field and fingerprint
  for fingerprint; **692 are refused by both**; **331 are new refusals**, every
  one a row of the table above; **0 inputs only the tip accepts**; and **6
  kits differ**, all one case -- the empty name above.
- Break checks (`harness/rows_kits.py`), the full check with the 78 Sample
  Sheets unchanged, and a fresh code review.
- `docs/admin-guide/` gets the kit key table and the value spellings, with the
  messages this code writes; a test fails when a rulebook key is missing from
  the page.
- Before merging, the settings command is run on the lab's real settings
  repository and the user sees what it would refuse, as in steps 1 and 2.

## Step 4: the database settings file

`config/mongodb.yaml` holds the connection string SeqSetup uses, password and
all. It is the one **sensitive** input: a message about it may quote nothing
(section "Sensitive inputs"), and `services/database.py` already refuses to
repeat a YAML parser's message for exactly that reason (`_yaml_refusal`).

### What happens today, measured on step 3's tip

- `MONGODB_URI` set in the environment wins and the file is not read at all;
  `MONGODB_DATABASE` (default `seqsetup`) then names the database.
  `docker-compose.yml` sets both, so **the lab takes this path and never
  reads the file**.
- `MONGODB_DATABASE` set with **no** `MONGODB_URI` is dropped without a word:
  `_load_config` only reads it inside the `if mongo_uri` branch, so a file is
  read and the variable means nothing (measured).
- No `MONGODB_URI` and the file is **there** (the shipped case: the file is
  tracked, copied into the image by `Dockerfile` and mounted read-only by
  `docker-compose.yml`, and `pixi run serve` sets no `MONGODB_URI`):
  `yaml.safe_load(f)` then `config.get("mongodb", {})`. A misspelt top key
  (`mongdb:`) gives `{}`, and `init_db` then falls back to
  `mongodb://localhost:27017` and the database `seqsetup` — **a different
  server, with no word**. So does a `mongodb:` map that leaves out `uri` or
  `database`.
- No `MONGODB_URI` and **no file**: the same localhost default. **Unchanged**:
  it is what a checkout with the file removed does, and nothing in the
  shipped deployment relies on it.
- An **empty** file: `config.get` on `None` raises `AttributeError` —
  start-up stops, with a traceback and no words
  (`test_an_empty_config_file_still_stops_start_up`, added on purpose in
  `86b2037`).
- A file that **cannot be read** (no permission) or that is **not UTF-8**:
  an unhandled `PermissionError`, or a `UnicodeDecodeError` naming a byte of
  the file and its offset — which for a latin-1 password is a byte of the
  password (measured).
- A `uri` with **no scheme** is not refused by anyone: pymongo reads
  `localhost:27017`, `mongodb.example.invalid` and even `see .env` as **host
  lists** and connects to them with no authentication (measured with
  `connect=False`).
- A `database` holding a `.` or a space reaches `_client[database_name]`,
  which is **outside** `init_db`'s `try`, so it is an unhandled `InvalidName`
  with no log line. pymongo refuses exactly `' '`, `'.'`, `'$'`, `'/'`,
  `'\'`, `'"'` and NUL, bounds the length not at all, and accepts a tab and a
  zero-width space (measured).

### Where the code goes

`input_rules/database.py`, beside the other rulebooks: `DatabaseFileRules`
and `check_database_file(text, file)`, listed in `cli.SCHEMAS`. It imports
nothing of `services/database.py`, which pulls in pymongo, and
`seqsetup.services.database` joins the modules the settings command's
isolation test forbids.

### The rulebook

One document, `mongodb` its only key:

| Key | Required | Rule |
|---|---|---|
| `mongodb` | yes | a map, the only key the file may have |
| `mongodb > uri` | yes | text, 1-4,096 characters, no hidden character, beginning `mongodb://` or `mongodb+srv://` |
| `mongodb > database` | yes | text, 1-63 **bytes** of UTF-8, no hidden character, holding none of `. $ / \ "`, a space or NUL |

**Why these bounds.**

- A connection string is text; nothing in SeqSetup bounds it, and 4,096 is the
  cap the app gives a description. The **scheme** is required because pymongo
  reads a scheme-less value as a host list, so a hand edit to
  `localhost:27017` silently connects somewhere else with no authentication.
  `mongodb+srv://` works in production: dnspython is in the **default** pixi
  environment, not only `dev`.
- MongoDB's own limit on a database name is 63 **bytes**, so the bound is on
  the UTF-8 length: `"é" * 63` is 63 characters and 126 bytes, and both
  pymongo and a character bound let it through (measured).
- The seven characters are exactly the ones pymongo refuses, so the rulebook
  says it by name and line instead of letting `_client[name]` raise outside
  any `try`. `database` gets the **hidden-character** rule too: a tab or a
  zero-width space in it reaches every log line, the Admin > Logs page and
  every audit row.
- Both keys are **required**: a file that is there and does not write them is
  a file whose writer meant something, and falling back to another server is
  the one thing this step exists to stop.

`retired_keys` is empty: `git log --follow -- config/mongodb.yaml` has one
commit, and the file has held exactly `mongodb.uri` and `mongodb.database`
since the initial commit, so there is no older spelling to give its own
message.

### Sensitive: a message quotes nothing, whatever a validator says

`check_yaml(..., sensitive=True)` masks a problem's **path**; it does **not**
mask its message, and `check.py` passes a validator's own `ValueError` text
through verbatim (measured: a rule written `may not hold '/': {value!r}`
quotes the password). Step 4 is the first user of `sensitive=True` anywhere,
so the gap has never been reachable. Two things close it:

1. **The rulebook's own messages name no value** — they name the character or
   the bound, never the input.
2. **`check.py` scrubs a sensitive file's own text out of every message**: for
   a sensitive input it collects every string the file holds (every value and
   every map key, at every depth), longest first, and replaces any of 4
   characters or more wherever it appears in a message, as
   `database._safe` does for credentials. So a message cannot quote a value
   even if a future validator tries to. A test holds it for each problem kind.

### Where it runs

- **`_load_config`** reads the file with `read_text`, the reader and the
  rulebook, and raises one `ValueError` naming the file (its full path, as
  today) and listing every **error** with its line, column and place. A
  warning, if a rulebook ever has one, is logged and does not stop start-up,
  as step 1's loader does. The three cases it keeps apart stay: the
  environment wins, a missing file means the localhost default, and a file
  that is there must be right. Two more cases gain words: a file that cannot
  be read ("cannot be read (<reason>)") and one that is not UTF-8 ("is not
  UTF-8 text"), each naming the file and nothing else — step 1's wording.
- **It returns the plain two-key dict** `{"uri": …, "database": …}`, built
  from the checked value, so `init_db` reads both keys directly and its two
  `.get` fallbacks go: `config.get("uri", "mongodb://localhost:27017")` was a
  second silent localhost default.
- **`MONGODB_URI` and `MONGODB_DATABASE` keep exactly the meaning they have**
  -- the variables win over the file, and `MONGODB_DATABASE` alone still means
  nothing (recorded in the run's QUESTIONS; changing it is the user's call).
  Their **values** go through the same two rules, with the variable's name in
  place of a line, before any client is built: a `MONGODB_DATABASE` holding a
  `.` was an unhandled `InvalidName` from outside `init_db`'s `try`.
- **`_yaml_refusal` is deleted** -- the reader never repeats PyYAML's text, so
  the guard it was has moved into `input_rules` -- and its two tests are
  pointed at the new path with the same guarantee. The line of
  `docs/getting-started/deployment.rst` that quotes its wording is updated.
- **Every other guarantee of `database.py` is untouched**: the connection
  string is never logged (`_safe`, `_credentials`), the
  authentication-failure message still says where to look, and the timeouts
  are the same.
- **`pixi run check-settings`** checks a database file only when told to, with
  `--local-database <path>`, like `--local-instruments`: a settings repository
  does not hold one, and the command **never connects to anything**. It reads
  the path with `read_text`, not `cli._read`, whose "a link is its target
  path" rule is for a GitHub listing and would refuse a `mongodb.yaml` that is
  a secret mount (measured with `--local-instruments` on a symlink).

### No test reaches a real database

The suite's unguarded default **is** the clinical database: there is no
`tests/unit/conftest.py`, `pytest.ini` sets no environment, and
`_load_config` with no `MONGODB_URI` returns `mongodb://localhost:27017` from
the shipped file (measured). `tests/integration/conftest.py` patches `init_db`
and `get_db` per test, and no unit test calls them today, but step 4's tests
are the first to go near `_load_config`. So:

- **a session-wide autouse guard in `tests/conftest.py`**: it sets
  `MONGODB_URI=mongodb://127.0.0.1:1` for the whole suite, replaces
  `seqsetup.services.database.MongoClient` with a stub that records its
  arguments and raises, and resets `_client` and `_db` around every test --
  `init_db` returns early when `_db` is already set, so a test that forgets
  that passes while proving nothing;
- **a test that `services/database.py` is the only place in `src/` that
  builds a `MongoClient`** (true today: `database.py` lines 11, 18 and 152),
  so the one patched name is the whole of it;
- step 4's own tests call `_load_config` and `check_database_file` directly,
  and `init_db` only behind that stub, asserting afterwards which URI it was
  handed.

### What changes for a lab

| The file or the environment says | Today | New |
|---|---|---|
| a misspelt top key (`mongdb:`) | `mongodb://localhost:27017`, database `seqsetup`, with no word | start-up stops: `mongodb` is required, and `mongdb` is not a key this file can have |
| `mongodb:` with `uri` misspelt (`url:`) | the same silent localhost default | start-up stops, naming the key and its line |
| `mongodb:` with no `database` | the database `seqsetup`, with no word | start-up stops |
| an empty file | `AttributeError`, no words | start-up stops: "is empty", naming the file |
| a file that cannot be read | an unhandled `PermissionError` | start-up stops: "cannot be read (Permission denied)" |
| a file that is not UTF-8 | a `UnicodeDecodeError` naming a byte of the file and its offset | start-up stops: "is not UTF-8 text" |
| `uri: localhost:27017` (no scheme) | pymongo reads it as a host and connects with no authentication | refused: a connection string begins `mongodb://` or `mongodb+srv://` |
| a `database` holding a `.`, a space or a tab | an unhandled `InvalidName` from outside `init_db`'s `try`, or a tab in every log line | refused by name and line |
| a `database` of 63 characters but 126 bytes | accepted by SeqSetup and by pymongo; the server refuses it | refused: at most 63 bytes |
| a `uri` or `database` written as a number or a list | read as it was, then pymongo's own error | refused: must be text |
| a key given twice, a YAML tag, an anchor, a merge key | the last value kept, or the tag expanded | refused, as for every other settings file |
| `MONGODB_URI` or `MONGODB_DATABASE` holding such a value | the same unhandled errors, outside any `try` | refused, naming the variable |
| a file that is **there but cannot be opened** -- a dangling link (a secret mount is a link), a link loop, an unreadable parent | `Path.exists()` says no, so the local default, with no line in the log | start-up stops: "cannot be read" |
| `uri` written `MONGODB://…` or with no host | accepted here, then pymongo's own error from inside `init_db` | refused: the scheme is compared as pymongo compares it, and a host is required |
| a `uri` or `database` with a trailing newline (a secret read from a file keeps one) | accepted, and the newline reaches every log line | refused as a hidden character |
| `pixi run create-admin` or `use-local-sign-in` with bad settings | "Could not reach the database. Nothing was changed." | the settings refusal itself, naming the file, the line and the key |
| no file at all | `mongodb://localhost:27017` | **unchanged**, and one log line says so |
| `MONGODB_URI` set | wins over the file | **unchanged** |
| `MONGODB_DATABASE` set alone | dropped without a word | **unchanged** (in the run's QUESTIONS) |

No message, log line, status or audit row quotes a value of this file or of
either variable, or the name of a key the rulebook does not define. One
`INFO` line names **where** the settings came from -- the environment, the
file's path, or the local default -- so "falls back to localhost without a
word" is no longer true of any path.

### How step 4 is proved

- Red tests first: each row above; the five cases `_load_config` keeps apart;
  the scheme rule both ways (`mongodb://`, `mongodb+srv://`, none); the
  database-name bound at 63 and 64 bytes of a multi-byte character; each
  forbidden character; a password written as a **value**, as a **key**, inside
  a nested map and as a very long scalar, absent from every problem's
  **message** as well as its path, for every problem kind; a validator that
  tries to quote its input, scrubbed.
- The guard: the session-wide stub, the "only one `MongoClient` in `src/`"
  test, and the assertion that nothing was handed to a real client.
- The existing tests of `test_database_log_no_credentials.py` keep their
  guarantee; the two `_yaml_refusal` tests and the empty-file test are
  pointed at the new path and listed in STATUS.md with their reasons.
- The guard test covers the new rulebook. Break checks. The full check with
  the 78 Sample Sheets unchanged. A fresh review.

## Step 5: pasted samples and LIMS worklists

These are the most patient-critical inputs the app has, and they are already
the strictest: both refuse the **whole** input and name the rows
(`ZERO_SAMPLE_ID_RULE`, "Never silently discard rows" in CLAUDE.md), both
refuse a column or a field that looks like an index or a lane but is not one
they read ("A paste never guesses an index column"), and both refuse sample
text over 256 characters rather than cut it. **Their behaviour must not
change.**

### What this step is, and what it is not

The move is mechanical: `services/sample_parser.py: read_pasted_samples` and
`services/sample_api.py: parse_api_samples` keep their adapters -- a
headerless paste, the column and field aliases, the LIMS field-name mapping, a
sample ID sent as a JSON number, unrelated LIMS metadata ignored -- and the
**row** they have adapted is checked by one strict rulebook instead of by the
checks written inline. It is worth doing only if it changes **no outcome**:

- for every input the release before accepts, the same samples come out --
  every field, in order, with the same lanes, indexes, kit, test, test version
  and worksheet;
- for every input it refuses, this one refuses too, and the message says the
  same or more.

Neither of those can be argued; they have to be **measured**, over a corpus
wide enough that a difference shows. So this step builds the measurement
first, as its own deliverable, and the move only after.

### The guard, built first

`tests/unit/test_paste_and_worklist_outcomes.py` records what today's readers
do with a corpus written for it -- 107 paste texts, 81 worklist payloads and 3
read with a LIMS field mapping: header spellings and case, column order, tabs
against commas, CRLF, a byte order mark, trailing blank rows, quoted cells, a
number as an ID, extra metadata, long and short rows, 256 and 257 characters,
IDs of zeros, a multi-line cell, an unnamed column, one case for **every
column name the paste reads and every field name the LIMS import reads**,
more samples than a run holds, a double quote that is not closed, and -- the
case a fresh review of the first version showed was missing -- **three
samples each carrying its own i7 and i5**, so an index exchanged between two
rows is seen. For each one it asserts the outcome exactly: the samples field
by field (every field of `ParsedSample`, taken from the dataclass so a new one
is compared too), or the refusal's own exception type and words.

The first version of this file held one sample per index-carrying case, and a
fresh review wrote 24 behaviour-changing mutations of which **20 passed it**.
Every one of those is now a case or an assertion, and
`harness/rows_samples.py` keeps 16 of them as break rows.

That file is **what a move would be held to**, and it is useful on its own: it
holds the two readers to their behaviour whoever changes them next. It is not a
proof that a move is safe -- a fresh review of this design wrote the one
mutation it could not see, the DNA refusal deferred instead of raised inside
the row loop, and all 216 assertions passed while three real pastes changed
their message. Those cases are in it now (every immediate-against-deferred
fault pair, in both orders and on one row, and the cap against a deferred
fault both ways round), and the lesson stands: the file holds what it has a
case for, and a move must come with the cases its own shape needs.

### Where the rulebook would sit

`input_rules/samples.py`, one rulebook for **one adapted row**:

| Key | Rule |
|---|---|
| `sample_id` | filled text, not made only of zeros (`ZERO_SAMPLE_ID_RULE`); **the adapter refuses it over 256, never cuts it** |
| `test_id` | text; **the adapter refuses it over 256** |
| `worksheet_id` | text; **the adapter cuts it at 256**. LIMS-only: the paste has no such column and `ParsedSample` no such field |
| `test_version` | text matching `TEST_VERSION_RE` (`1`, `1.2`, `1.2.3`) or absent |
| `index1_sequence`, `index2_sequence` | DNA text of `[ACGTN]` after uppercasing. **The adapter cuts at 256, it does not refuse** (measured: a 300-base i7 is stored as 256 today, and a non-DNA character past 256 is cut away with it), so **the rulebook may not bound them** unless that is a listed accept-to-refuse change |
| `index_pair_name`, `index1_name`, `index2_name` | text; **the adapter cuts at 256** |
| `line` | the source line, which the adapter fills and nothing checks |

**Which stage owns the 256 is written out above, field by field**, because the
two readers do not agree: the sample text is **refused** over 256 and
everything else is **cut**. A rulebook bound where the adapter cuts would be an
accept-to-refuse change, which is what Q7 asks the user about.

**An unknown key is the one place this series' `extra="forbid"` does not
hold.** A LIMS row legitimately carries clinical metadata a lab's own system
needs, and a paste may carry a column SeqSetup does not read; both are
accepted today, and only a column or field that **looks like an index or a
lane** is refused. The adapters therefore pass the rulebook **only the keys it
names** and drop the rest -- they never hand it the row as the LIMS sent it.
This is deliberate, it is the one departure in the series, and it has to be
written down: a builder inheriting `StrictRules` without reading this would
refuse a worklist a lab sends every day. A `field_mappings` entry for a field
SeqSetup does not know puts that key into the adapted row today (measured),
and the guard has a case for it.

**Lanes are not in it**: neither reader gives a sample a lane -- they come
from `_picked_lanes` in `routes/samples.py` after the read -- so a rulebook
field for them would be a field nothing fills, and the guard above cannot see
one either. "No page gives a sample no lane" stays the route's rule.

The rules that are **about the worklist rather than the row** stay where they
are, because they need every row at once or the file's own words. The paste's
thirteen: the unreadable line, the multi-line cell, no header row with more
than two columns, a column that is not read, a first column taken as the ID, a
column with no header name, the delimiter, the header ranking, the rows with no
`sample_id`, the rows whose ID is all zeros, and the long-ID, long-test and
bad-version refusals that **name every such row in one message**, plus
`MAX_SAMPLES_PER_RUN`. The LIMS import's thirteen: the non-map row, a field
that looks like an index or a lane, two names for one index, two field names
differing only in capitals, the JSON-type check on each of seven fields, the
**repeated sample ID** (a true whole-worklist rule), the long-text refusals,
`MAX_SAMPLES_PER_RUN` and the field-name mapping.

Two of them are not symmetrical, and one row rulebook has to say which it
follows: **"a test version but no test"** is a LIMS rule the paste does not
have (measured: the same row reads as a sample with a version and no test on
the paste path and is refused on the LIMS path), and **one sample ID twice** is
refused by the LIMS reader while the paste reader accepts it and the route
refuses it later. Unifying either is a behaviour change; the guard records both
as they are.

The `sample_id` row of the table above is the *shape* of one ID; the reader
keeps the refusal that names **every** such row in one message.

### Why the move is not made in this step

Measured on step 4's tip: `read_pasted_samples` is one function of some 250
lines, and its refusals come in **three stages**, not one order (all
measured):

1. **Immediate**, inside the row loop, in code order: a non-DNA i7, a non-DNA
   i5, then the sample cap. The first offending **row** wins and the scan
   stops there.
2. **Deferred**, collected and raised after every row is read, in a fixed
   class order: a column with no header name, a row with no ID, a row whose
   ID is all zeros, a long ID, a long test, a bad test version.
3. **Reader stage**, before any row: an unreadable line, a multi-line cell, no
   header row with more than two columns, a column that is not read, a first
   column taken as the ID.

Two consequences, both measured and both in the guard. A paste holding a row
with no ID and another with a bad test version reports only the no-ID row and
does not mention the version at all. And the precedence of the **same two
classes flips** depending on whether they share a row: row 2 with no ID and
row 3 with a non-DNA i7 says "Invalid characters in index1"; the same two
faults **on one row** say "sample_id is required". So no scheme that merely
sorts a row's problems can reproduce today's words, and a Pydantic rulebook
reports a row's faults together -- not less information, but not the same
words either, and these are the two inputs whose words a lab reads under time
pressure.

So this step stops at the design and the guard, and the move waits for the
user's word on **which of three** it should be:

- **A**: keep today's words exactly. That means keeping today's **control
  flow** -- the rulebook's DNA and cap problems stop the scan at the offending
  row and the rest are collected -- not sorting a row's problems, which cannot
  do it.
- **B**: let a row report every fault it has, so a paste is fixed in one pass
  instead of one row at a time -- better for a lab under time pressure, and a
  change to the words of some refusals, each of which has to be listed and
  probed as steps 3 and 4 list theirs.
- **C**: no rulebook for these two inputs. Single-source what is actually
  duplicated -- `_VALID_DNA_RE`, written out in `sample_parser.py`,
  `sample_api.py` **and** `models/index.py`, and `_MAX_FIELD_LEN = 256`, a
  hand-copy of `MAX_SAMPLE_TEXT` -- and extract the shared row predicates as
  named functions both readers call, each keeping its own message and flow.
  Five of the six shared row rules already have one definition in
  `models/sample.py` which both readers import, so "the rules in one place" is
  **two things**, and C buys them with no change of words, no ordering
  question and no answer needed from the user.

All three are in the run's QUESTIONS. Option A was first written here as "run
the rulebook's problems through a fixed order per row"; a fresh review of this
design showed that cannot reproduce the flip above, and that what A would buy
is the two constants C buys more cheaply. **A rulebook's problem must never
reach a person as it is**: `pydantic.ValidationError` is a `ValueError`, which
`routes/samples.py` catches and writes straight into the banner, URL and all.


### What this step does change

One thing in `src/`, and it changes no behaviour: the LIMS import's table of
field names is lifted out of `parse_api_samples` into the module constant
`ALIAS_NAMES`, so the guard can walk it and fail when an alias is dropped --
which a fresh review showed was otherwise silent for the test and kit fields.
It is a **read-only** mapping of tuples: which LIMS field becomes a **sample
ID** is not something a caller or a test may rewire, and a single appended name
would make a patient's name the sample ID (a fresh review of this design
measured exactly that before the table was frozen). Everything else is the
guard, the design and the three questions.

### The user's word (2026-10-20)

**C**, and **B for Q7**; the run's picks for Q1-Q5 stand as built.

- **One DNA rule.** `VALID_DNA_RE` in `models/index.py`; the paste, the LIMS
  import and the forms (`forms/validators.py`, a fourth copy written
  `[ACGTN]*` with `fullmatch`, the same rule) import it. The LIMS import's
  bound is `MAX_SAMPLE_TEXT` by name, as the paste's already was.
  `tests/unit/test_dna_rule_and_bound_written_once.py` fails on a copy. The
  "looks like DNA" patterns of the paste preview and the kit reader are other
  rules and stay. No row predicate is extracted: the five shared row rules
  already have one definition in `models/sample.py`. The guard passed
  unchanged.
- **An index sequence over 256 characters is refused, never cut**, in both
  readers, naming its rows, in the deferred stage beside a long sample ID or
  test (so a row's long index stops its own later checks, and a bad sequence
  on another row is still said first): *"Row(s) 2: the i7 index is longer
  than 256 characters. SeqSetup does not shorten it; fix it in the source."*
  and *"LIMS row(s) 1: the i7 index is longer than 256 characters. SeqSetup
  does not shorten it. Fix the upstream record(s) before retrying."* The cut
  could take a character that is not DNA away with it. This is the one
  accept-to-refuse change of step 5: the guard's record changes for the five
  cases that held a long sequence, and fourteen cases are added (256 read
  whole, 257 refused, an i5, two rows named, a long index beside a bad
  sequence on another row and on its own row, in both orders).

## Later steps (each adds its details to this note, or a note of its own)

2. **Profiles**: built as step 2, above.
3. **Index kit files**: built as step 3, below.
4. **`config/mongodb.yaml`**: built as step 4, below.
5. **Pasted samples and LIMS worklists**: designed and measured as step 5,
   below; no code moved (see "Why the move is not made in this step").

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

A second round on `4436058` gave one P1, six P2 and one P3, all confirmed and
folded in: explicit YAML tags bringing back refused spellings (P1); cross-key
checks with no partial result to run on (P2); float conversion and per-field
strictness overrides (P2); the 64-bit storage limit and a round trip through
BSON (P2); byte budgets for the whole audit row and the sync status, which a
long report fills (P2); unknown key names carrying a secret into a message (P2);
the column of a syntax error (P2); the one named exception to "facts are written
out" (P3). It also confirmed that all 27 shipped YAML files read the same under
the new spelling rules, that the eight added `has_dragen_onboard: false` values
change nothing, and the cycle ranges.

A fresh review of the built step 1 (`95af352`) gave one P1, four P2 and nine
P3, all confirmed: a problem record MongoDB could not store (a key past 64 bits
or half a character) stopped the sync after it had written the reference data,
with no audit row and, when scheduled, no finish time (P1); a map key read as a
number shown as a list item (P2); a control character, a very long number or
deep nesting escaping as an exception (P2); an empty colour list passing with
colour balance on, which switched the dark-cycle check off (P2); the settings
command passing having checked nothing, and reading files the sync does not
(P2); past the cap, warnings refusing a file; the audit report growing past its
row when addresses are cleaned; the sync message holding every problem; the page
hiding the count when no problem fitted; four loopholes in the guard test; the
converter and the `index_cycle_options` upper bound untested; the Illumina names
in the tests taken from `src`; stale text (P3). All are fixed with a test each,
except two left as they are: the two rules kept in both layers (see "The domain
models stay a backstop"), and the `samplesheet_versions` default, which the
rulebook states and the model applies (the converters pass only the keys a file
writes; `test_samplesheet_versions_is_the_one_named_exception` holds the result
to `[2]`). Break row N27 also showed the size check inside `bounded_report`'s
loop untested; a test now counts how often the whole report is measured.

Found while testing a long sync message: the log scrubber's connection-string
rule (`services/log_capture.py`, `_URL_CREDENTIALS`) tried every letter of a
word as the start of a scheme, so its time grew with the square of a word's
length (20,000 letters 2.5 s, a million over an hour). Every log line and every
audit row goes through it, so one long key in a settings file stalled the
logging and the sync. It now starts only where a run of scheme characters
starts, and a test holds it to scrubbing exactly what it scrubbed before.

A review of step 4's design (`7525748`) gave three P1, six P2 and five P3, all
confirmed by my own probes and folded in above: `sensitive=True` masks a
problem's path but not its message, and `check.py` passes a validator's own
text through verbatim, so the one rule step 4 adds was the one place a
password could leak -- step 4 is the first user of `sensitive=True` anywhere
(P1); the test suite's unguarded default is the real database on
localhost:27017, and a one-file fixture is not a guarantee (P1); the
environment path, the only one the lab takes, was left unchecked, so a
`MONGODB_DATABASE` holding a `.` stayed an unhandled `InvalidName` from
outside `init_db`'s `try` (P1); a `uri` with no scheme is read by pymongo as a
host and connected to with no authentication (P2); MongoDB's 63 is bytes, not
characters (P2); an unreadable or non-UTF-8 file still ended in a bare
traceback naming a byte of the file (P2); what `_load_config` returns, and
`init_db`'s second silent localhost fallback (P2); where the rulebook lives,
and the settings command's import rule (P2); `_yaml_refusal`'s fate and the
path it names (P2); the empty-file test added on purpose (P3); a
`--local-database` symlink (P3); no hidden-character rule for `database` (P3);
errors versus warnings and an invented `retired_keys` (P3); and a measurably
false reason for keeping the missing-file fallback (P3).

A review of step 3's design (`332ce45`) gave three P1, eight P2 and six P3,
all confirmed by my own probes and folded in above: both Illumina readers strip
an index name before the repeat check, so "never trimmed" would lose that
refusal (P1); a TSV `[Indices]` section may have no header line, which a
column-oriented table reader would swallow (P1); the upload's picker always
wins over the file's `index_mode`, so a file naming another mode is stored as
the picked one with no word (P1); a pair's `id` keeps the file's name while
`kit.name` takes the form's, so building from the checked value would move an
accepted file's fingerprint (P2); the import form's own boxes see no rulebook
(P2); a CSV's name comes from the upload's filename, which has no line (P2);
`IndexKitSyncParser.parse`'s `Optional[IndexKit]` cannot carry problems, where
step 2 extends `self.input_problems` (P2); `IndexValidator` is an ingest check,
not a stored-record backstop, and five rules would live in two layers (P2); no
bound on how many indexes a file may hold, so a 10 MB synced file would give a
document over MongoDB's 16 MiB after the stored kits are deleted (P2); five
refusals missing from the lab table (P2); step 1 and 2's two merge gates
dropped (P2); three table rows wrong against the code (P3); the colon rule's
stated reason unreachable (P3); `--index-kits` defaulting to a folder the
shipped settings folder does not have (P3); the audit row's reason growing
coarser (P3); a refused scalar quoted whole into the admin's HTML, which is a
step 1 and 2 fault too and is fixed in the reader (P3); a sequence bound and a
cycles bound that cannot both be reached (P3). Three were answered by doing
less than asked: a `:` in a kit **name** stays accepted (it is storable today,
nothing splits a `kit_id`, and refusing it would orphan the `index_kit_name`
stored on its samples), `refused["name"]` stays `None` for a file no kit could
be built from (today's conservative behaviour), and an empty unread list and a
block-scalar sequence stay accepted.

A review of step 2's design (`1a40e31`) gave four P2 and three P3, all
confirmed and folded in above: `SoftwareVersion` needs a value rule, since the
validation service sorts mixed versions (P2); text of spaces only and a blank
version specifier, refused today, would pass a plain length bound (P2); the
`SPELLED_*` names sit in a module whose imports run the instrument start-up
(P2); GitHub serves a link to a file as the link's target path, so the sync
refuses it while step 1's command skipped it (P2, fixed in step 1 as
`bd8c87f`); an empty `Translate:` in a `Dragen` profile (P3); no bound on the
two version strings (P3); errors in a value of several kinds reported once
per kind at invented paths (P3). It found no forced Sample Sheet change: all
seven shipped profiles gave the same model through both readers and
survived BSON.
