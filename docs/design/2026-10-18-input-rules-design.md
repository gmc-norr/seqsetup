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
  column; unknown kinds get "the file is not valid YAML here". PyYAML's own text
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
| `ApplicationProfileName` | yes | text, 1-256 characters |
| `ApplicationProfileVersion` | yes | text, a PEP 440 version |
| `ApplicationName` | yes | a plain name (letters, digits, `_`, `-`), 1-256; one of Illumina's when the type is `Dragen` |
| `ApplicationType` | yes | text, 1-256 |
| `Settings` | when `Dragen` | a map of a plain name to a sheet value; empty allowed |
| `Data` | when `Dragen` | as `Settings` |
| `DataFields` | when `Dragen` | a list of plain names |
| `Translate` | no | a map of a plain name to a plain name |

A **sheet value** is text of at most 4,096 characters, a whole number within
64 bits, or `true`/`false`. Text holds no hidden character (a line break, a
tab, an invisible control) and does not start with `[`, even after spaces.
`''` is an empty cell; a key with nothing after it is refused ("write `''` for
an empty cell"). For a type other than `Dragen` an empty `Settings:` (and the
other three) means none, as today.

**A test profile** (one per file):

| Key | Required | Value |
|---|---|---|
| `TestType` | yes | text, 1-256 (a sample's test ID is at most 256) |
| `TestName` | yes | text, 1-256 |
| `Description` | yes | text, 1-4,096 |
| `Version` | yes | text, three whole numbers joined by dots (`PROFILE_VERSION_RE`) |
| `ApplicationProfiles` | yes | a list of at least one reference |

A reference holds `ApplicationProfileName` (text, 1-256) and
`ApplicationProfileVersion` (text, a PEP 440 version or specifier), and nothing
else.

**The rules relating keys move from `services/profile_validator.py`**, with
their substance and their tests (section 5): the mismatch values (0, 1 or 2 in
`Settings`; also blank or `na` as a `Data` default, under the column `Translate`
gives it); a `Sample_ID` column; no column written twice, whatever its case; in
the `BCLConvert` profile no name both in `Settings` and among the columns, and no
setting that changes how BCL Convert reads the i5 (`is_i5_rule_setting`); a
name SeqSetup fills itself spelled its one way (`SPELLED_*`); the three
`Dragen` sections. `profile_validator.py` is removed.

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
- a value over 4,096 characters, or a name, type or test over 256.

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
  in any case, as the sync takes it for profiles; never a link), and runs the
  cross-file rules. A missing profile folder is an error, as for instruments;
  `--no-instruments` is for a lab whose sync does not read instruments.
- **The stored profiles** (`from_dict`) and the Sample Sheet writer's backstops
  (`_escape_config_cell`, `_require_profile_mismatch`) are unchanged.
- **`docs/admin-guide/profiles.rst`** gets both key tables and the value
  spellings; a test fails when a rulebook key is missing from it.

### How step 2 is proved

- Red tests first: each unknown key refused with its line, also inside a
  reference; each required key; each value kind in `Settings` and `Data`
  (text, a whole number, true/false; a list, a map, an empty value refused);
  the Dragen name rule both ways; `TestType: 5`; each bound at and past its
  edge.
- The old validator's tests (84 in `test_profile_validator.py`, and the profile
  tests in the files that build profiles through `from_yaml`) keep their
  guarantee on the new path; any changed test is listed.
- Every shipped profile gives the same model (`to_dict`, but its id and time)
  on the old path and the new, and survives the model, BSON and back.
- The cross-file rules, through the sync and through the command.
- Break checks, the full check (the 78 Sample Sheets unchanged), a fresh
  review, and the lab's settings repository through the command.

## Later steps (each adds its details to this note, or a note of its own)

2. **Profiles**: built as step 2, above.
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
