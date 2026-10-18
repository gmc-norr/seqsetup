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
- YAML changes types on its own: `version: 1.10` is the number 1.1, `name: no`
  is `False`, `012` is 10. Some readers turn these back into text, some refuse
  them, some crash.

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

## The shape

New package `src/seqsetup/input_rules/`. It imports nothing that starts the app
(no repositories, no `seqsetup.data.instruments`, which reads the local file at
import), so the settings command can use it with no database and no network.

### 1. Readers

A reader turns the raw input into plain data **and records where each key came
from**: `key_lines`, a map from a key path (a tuple such as
`("flowcells", "10B", "lanes")`) to its line in the file.

- **YAML** builds on the loader in `utils/yaml_safety.py`
  (`_NoAnchorSafeLoader` / `_UniqueKeySafeLoader`). It refuses anchors and
  aliases, and it records **every** key given twice (rather than stopping at the
  first), each with its line. A yes/no value must be written `true` or `false`
  (any case): YAML 1.1's `yes`, `no`, `on` and `off` are refused, since `name: no`
  would otherwise reach a text key as `False`. The reader keeps the text of
  each scalar as written, so a message can quote it (`1.10`, not `1.1`).
- **CSV and TSV** readers (built in the kit and paste steps) return rows as
  `(line, {column: text})` and refuse a column name given twice, before any row
  is read.

If the reader finds a problem (a syntax error, a key given twice, an anchor, a
yes/no spelling), it reports every such problem and the rulebook is not run: a
file whose structure cannot be trusted is not checked further.

### 2. The strict base

`class StrictRules(pydantic.BaseModel)` with
`model_config = ConfigDict(extra="forbid", strict=True, frozen=True)`:

- `extra="forbid"`: a key the rulebook does not name is refused.
- `strict=True`: no conversion between types: `"1"` is not an int, `1.1` is not
  text, `True` is not an int.
- Shared building blocks, defined once and used by every rulebook that needs
  them: a plain name (the rule the readers use today), version text (a string,
  never a number), text of at most 256 characters, a positive whole number, and
  Illumina's application names (the list now kept in
  `tests/unit/test_shipped_examples_fit.py:23` and
  `tests/unit/test_dragen_section_names.py:26`, moved into `src/` with a comment
  saying where the names come from and how to add one).
- **A guard test** imports every model in `input_rules` and fails when one does
  not derive from `StrictRules` or loosens its config.

### 3. Problems

`InputProblem(file, line, key, message, level)` with `level` `"error"` or
`"warning"`.

`check(rulebook, data, key_lines, file)` runs the rulebook and returns either the
checked value or the list of problems. Pydantic reports every error of a model at
once; the translator turns each into one `InputProblem`:

- the key path as written (`flowcells > 10B > lane`);
- the line of that key, or for a missing key the line of the mapping it is
  missing from (line 1 for the top level);
- a plain message per Pydantic error type: an unknown key "is not a key this
  file can have (check the spelling)"; a missing key "is required"; text given a
  number "must be text: put it in quotes (YAML read 1.10 as the number 1.1)"; a
  choice "must be one of: 2-color, 4-color"; a rulebook's own validator message
  as written.

Warnings come from a separate function per rulebook, run only on a value that
passed; they never block.

### 4. Every entry point does the same

read → check → if there is any error: refuse with **all** the problems and write
nothing → only then build the domain object as today (`from_yaml`, `from_dict`).

- The domain models keep their own checks (`__post_init__`, `__setattr__`): they
  are the backstop CLAUDE.md requires, at the model boundary.
- **A rule moves, it is not copied.** A rule that moves into a rulebook is removed
  from the old validator, so it is kept in one place. The old validator's tests
  are kept and pointed at the new path, with the same guarantee.
- Limits shared with the models (256 characters, the plain-name rule) are
  imported from one place, so the two layers cannot drift apart.
- **Rules that need more than one file or the stored data stay where they are:**
  two instrument files for one instrument (`_duplicate_instruments`), a profile
  version given twice (`_refuse_repeated_app_versions`), tests differing only in
  capitals, a kit's name and version with another content
  (`_refuse_changed_or_repeated_kits`), index collisions between samples.

### 5. Where problems are shown

- **Configuration sync.** Each refused file gets its list of problems. The sync
  status keeps today's message and adds a `problems` list
  (`{file, line, key, message, level}`); Admin > Configuration sync shows it as
  a table. As today, a refused file keeps the stored records it would have
  replaced. Warnings are shown there too, not only logged.
- **The audit trail.** Every sync's audit row carries its problems, whether the
  sync was started by hand or by the scheduler (today a manual sync's row has the
  outcome and count only: `routes/admin/config_sync.py:171-177`). A row carries at
  most 200 problems and says how many more there were.
- **Start-up.** A local file with an error stops start-up with every problem and
  its line (`InstrumentConfigError`, today naming the field but not the line).
- **The settings command** (below).

### 6. The settings command

`pixi run check-settings <folder>` (`python -m seqsetup.input_rules.cli`):

- checks a settings folder laid out as the sync reads it (the shipped `config/`
  is the example; options name other paths), with the same rulebooks, and the
  cross-file rules that need no database;
- prints one problem per line, `file:line: key: message`, warnings marked;
- exits 1 when there is an error, 0 otherwise;
- needs no database, no network and no running app; it ships in the Docker
  image, so the lab's settings repository can run it on every change;
- `--schema <dir>` writes a JSON Schema per rulebook (`model_json_schema()`) for
  editors. The schema is a help, not the authority: it cannot express keys given
  twice, anchors, yes/no spellings or every rule relating two keys. The command
  is the authority.

It grows with each step: in step 1 it checks instrument files only.

## Step 1: the core and instrument files

### The instrument rulebook

One rulebook for an instrument, used by both synced formats
(`_parse_instruments_yaml`, `github_sync.py:852`: an `instruments:` map or one
instrument per file) and by each entry of the local file.

**Rule: a key that changes a sheet or a check must be written out; only labels
may be left out.** Today several of them fall back to a default when absent.

| Key | Required | Rule |
|---|---|---|
| `name` | yes (synced); the map key (local) | plain text |
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
| `samplesheet_versions` | no (absent means `[2]`, as the guide says) | a non-empty set of 1 and 2 |
| `onboard_applications` | yes | map of an Illumina application name to `{software_version: version text}` |
| `flowcells` | yes, at least one | map of a name to `{lanes, reagent_kits, reads, description}` |
| `flowcells > * > lanes` | yes (today defaults to 1) | positive whole number |
| `flowcells > * > reagent_kits` | yes | non-empty list of distinct positive whole numbers |
| `flowcells > * > reads` | no | whole number, 0 or more |
| `flowcells > * > description` | no | label |
| `reagent_kit_max_cycles` | no | today's rules (`instrument_validator.py:234-268`): a map of a kit label (positive whole number) to the most cycles allowed (a whole number, at least the label); a label no flow cell offers is a warning |
| `i5_read_orientation`, `samplesheet_v2_i5_orientation` at the top level (`OLD_I5_KEYS`) | refused | with today's message (`_refuse_bad_i5_facts`), not the generic unknown-key one |

All 11 shipped synced files and the shipped local file already write every key
marked required. Every other key is refused.

**The local file** (`config/instruments.yaml`) has three top-level keys:
`instruments` (a map of instrument name to the rulebook above), `default_cycles`
(a map of a reagent kit's cycles to `{read1, read2, index1, index2}`: read
cycles at least 1, index cycles 0 or more — the build checks these bounds
against how the app uses them and records the evidence) and
`index_cycle_options` (a non-empty list of distinct positive whole numbers).
Neither of the last two is checked today.

### What else changes in step 1

- The local file is read by the new YAML reader (anchors refused, keys given
  twice refused) and stops start-up listing every problem with its line.
- Every `OSError` while reading the local file is named in the start-up message;
  today an `ELOOP` escapes `_present` (`data/instruments.py:225-238`) as a raw
  traceback.
- `reload_config` (`data/instruments.py:371`) has no caller in `src/` and would
  not clear the validation cache: removed, with the tests that exist only for it.
  (Both moved here from the stopped batch's step 12, which touched the same file.)
- `validate_instrument_yaml`'s rules move into the rulebook; the dye-channel
  warning becomes a rulebook warning, shown on the sync page.
- A synced instrument file with an error is refused as today: no instrument from
  that sync is stored and the stored ones stay (`github_sync.py:350-355`).
- `docs/admin-guide/instruments.rst` gets the full key table (there is none
  today); a test fails when the rulebook has a key that page does not name.
- The settings command, checking instrument files.

### How step 1 is proved

- Red tests first for every rule: an unknown key refused with its line, also
  nested in a flow cell; a key given twice; an anchor; a yes/no spelling; a
  number where text belongs; each required key; the colour-field rule; the local
  file's two unchecked sections.
- The guard test (every rulebook derives from `StrictRules`).
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
   and `Data` sections are copied into the sheet and accept any key today;
   restricting them to the keys Illumina documents per application needs those
   lists, and is decided in that step. `TestType: 5` is refused, not a crash. A
   yes/no value in `Settings` (`DifferentialExpressionEnable: False` in
   `config/profiles/application_profiles/dragen/DragenRnaIdt.yaml:14`) reaches
   the sheet as text: what is written is decided there.
3. **Index kit files**, every format: replaces the stopped batch's step 8. A
   column name given twice; `is_fixed_layout: 'no'`; a missing name or version
   silently taking the file name or `1.0`; names cut at 256 characters
   (`models/index.py:226`); a `:` in a name or version (the stored id is
   `name:version`); the generic "Failed to parse file".
4. **`config/mongodb.yaml`**: a misspelt `mongodb:`; an empty file.
5. **Pasted samples and LIMS worklists.** These already refuse the whole input
   and name the rows. They move onto the same readers, base and problems, so
   their rules and messages come from one place; their behaviour does not change
   unless a gap is found, which is then decided on its own.

## What does not change

- No Sample Sheet changes: the 78-sheet corpus stays identical.
- The domain models keep their invariants.
- The rules that need several files or the stored data stay where they are.
- No new dependency.
