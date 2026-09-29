# Sample Sheet follow-ups — design

Date: 2026-09-29. Branch `fix/sheet-followups`, from `main` at `add956b`; `main` at
`97dc047` (group 2b) merged in. Revised after the spec review (Astra, on `9412424`).

## Why

Earlier reviews (groups 1a and 1c) found five ways a value can reach the Sample Sheet
unchecked or changed, and the spec review found a sixth. All six were confirmed in the code
on 2026-09-29:

1. **A profile's mismatch value is not range-checked.** On the profile path
   (`SampleSheetV2Exporter._write_application_profile_section`), a sample without its own
   `BarcodeMismatchesIndex1/2` gets the profile's `Data` default, written as is. A synced
   profile with `BarcodeMismatchesIndex1: 3` puts `3` into the sheet, past the 0–2 limit
   group 1c set (BCL Convert allows at most 2). A `Settings` entry of that name is not
   checked either.
2. **YAML changes some profile values before SeqSetup sees them, and `str()` writes the
   result.** `4.10` is read as the number 4.1 and written as `4.1` (a software version
   can change this way). An empty value is read as `None` and written as the word `None`.
   A version such as `ApplicationProfileVersion: 1.10` becomes `1.1`, so two profile
   versions can collide. A required field left empty passes the "must not be empty" check,
   because `str(None)` is `"None"`. A value that is itself a mapping or a list
   (`Options: {SoftwareVersion: 4.10}`) passes sync and is written as Python text:
   `"{'SoftwareVersion': 4.1}"`.
3. **Two profile shapes break Mark Ready or the sheet.** An empty `Settings:` in a
   non-DRAGEN profile passes sync as `None`, and every Mark Ready that uses it then fails
   with a 500 (`None.items()`). An empty `Data:` fails the same way when there is no
   `DataFields` list, or when a column takes its value from `Data`. (An empty `Translate:`
   is already handled, and a DRAGEN profile with an empty `Settings:`, `Data:` or
   `DataFields:` is refused at sync today.) A profile whose data section has no `Sample_ID`
   column (no `Data` and no `DataFields`, or a list without it) writes rows with no sample
   name at all.
4. **Invisible characters pass.** The hidden-character rule (`sheet_text.hidden_characters`)
   covers control characters (Unicode Cc) and the line/paragraph separators only. Unicode
   *format* characters (Cf) pass: the zero-width space, byte-order mark, soft hyphen, and
   the direction marks and overrides, which can make a name display in a different order.
   Sample IDs are already safe (Mark Ready allows only letters, digits, `-` and `_`), but a
   sample's name, project and description, and the run's name and description, are not.
5. **The local instruments file is never checked.** Instruments synced from GitHub are
   checked by `validate_instrument_yaml`; `config/instruments.yaml` (or the file
   `_find_config_path` finds) is loaded with no check. A typo in `i5_read_orientation`
   falls back to `forward` without a word, and so does any lookup of a missing instrument —
   so a wrong i5 direction reaches the sheet silently.
6. **A sample's or run's own mismatch value is range-checked but not type-checked.**
   `Sample`, `SequencingRun` and `RunTemplate` clamp it to 0–2 but keep `True` or `1.5`,
   for example from a document in the database. Both sheet writers then write `True` or
   `1.5` with `str()` (v1 in `[Settings]`, v2 in `[BCLConvert_Data]` and in profile data
   rows). Every page and route passes a whole number, so only a value written into the
   database directly gets there.

The shipped profiles and the shipped instruments file pass every new check (probed
2026-09-29: no decimal numbers, no empty values, no mapping or list values; every data
section has `Sample_ID`; all 11 local instruments pass `validate_instrument_yaml`). The
shipped DRAGEN profiles use `na` as a `Data` default for several file settings (not for
mismatch columns); that stays allowed.

## Decisions

Made with the user:

1. **Refuse the risky profile values at sync; write everything else as today.** A number
   with a decimal point and an empty value are refused, with a message saying to quote the
   value. Whole numbers, `true`/`false` and text are written as they are today, so no
   sheet made from today's profiles changes. (Not chosen: reading every value as the text
   typed, which would also turn today's `KeepFastq,True` into `KeepFastq,true`.)
2. **A broken local instruments file stops SeqSetup from starting,** with a message
   naming the file, the instrument and each problem. (Not chosen: skipping the broken
   instrument, because a missing instrument silently means "forward" i5.)
3. Approved as presented: the mismatch range, empty sections read as empty, the Sample_ID
   column rule, a safety net in the sheet writer, and Cf characters counted as hidden.

Added after the spec review, inside those decisions:

4. A mapping or list value in `Settings` or `Data` is refused like a decimal number: only
   text, whole numbers and `true`/`false` are written, as decision 1 says.
5. A `Data` mismatch default may also be `na`. Illumina's DRAGEN sample sheet guide says
   per-sample settings that do not apply to a sample "must be blank or na". A `Settings`
   mismatch value stays 0, 1 or 2 only (the same guide).
6. A sample's, run's or template's own mismatch value must be a whole number, checked in
   the models (the project rule: models own their limits), not only in the writers.
7. DRAGEN profiles keep today's sync checks: an empty `Settings:`, `Data:` or
   `DataFields:` is still refused for them.

## 1. Profiles

### At sync

`services/profile_validator.py` refuses a profile file (the existing
`ProfileValidationError`, one message per problem) when:

- **Application profile, a `Settings` or `Data` value is a decimal number** (a YAML float,
  including `.inf` and `.nan`):
  `Field '<Settings|Data>' value for '<key>' is a number with a decimal point, which YAML may have changed (4.10 is read as 4.1). Put the value in quotes, for example "4.10".`
- **Application profile, a `Settings` or `Data` value is a mapping or a list:**
  `Field '<Settings|Data>' value for '<key>' is a <mapping|list>; a value must be text, a whole number or true/false.`
- **Application profile, a `Settings` or `Data` value is empty** (YAML `None`):
  `Field '<Settings|Data>' value for '<key>' is empty. Write '' if it should be empty.`
- **A version is a decimal number:** `ApplicationProfileVersion` of an application
  profile; `Version` of a test profile; each `ApplicationProfiles[i].ApplicationProfileVersion`
  of a test profile:
  `Field '<name>' is a number with a decimal point, which YAML may have changed (1.10 is read as 1.1). Put the version in quotes, for example "1.10".`
  (`<name>` is `ApplicationProfileVersion`, `Version`, or
  `ApplicationProfiles[<i>].ApplicationProfileVersion`.)
- **A required field is empty** (YAML `None`), in either kind of profile: the existing
  message `Field '<name>' must not be empty`. Today `None` passes as the text `"None"`.
- **A mismatch value is out of range.** A `Settings` entry named `BarcodeMismatchesIndex1`
  or `BarcodeMismatchesIndex2` must be 0, 1 or 2 (a whole number, or the text `"0"`, `"1"`
  or `"2"`). A `Data` entry whose column is one of those names — its own name, or the name
  `Translate` gives it — may be 0, 1, 2, blank (`''`) or `na`. `true`/`false` are refused
  (Python counts `true` as 1).
  - `Settings`: `Field 'Settings' value for '<key>' fills <column> and must be 0, 1 or 2 (BCL Convert allows at most 2 mismatches): <repr of the value>`
  - `Data`: `Field 'Data' value for '<key>' fills <column> and must be 0, 1, 2, blank or na (BCL Convert allows at most 2 mismatches): <repr of the value>`
- **The data section has no `Sample_ID` column.** The columns are found the way the sheet
  writer finds them (`profile.data_fields or list(profile.data.keys())`): the `DataFields`
  list when it has entries; otherwise (no `DataFields`, an empty `DataFields:`, or
  `DataFields: []`) the `Data` keys. Each is renamed by `Translate`. `Sample_ID` must be
  one of them:
  `The data section has no Sample_ID column. Add Sample_ID to DataFields (or to Data when DataFields is missing or empty).`

What happens to a refused file is unchanged. It is skipped, and its reason is a warning on
Admin → Logs. The sync then replaces all stored profiles of that kind with the ones that
passed, so a run that needs the refused profile is blocked at Mark Ready with "profile not
found". But if every application profile (or every test profile) is refused, the sync
stops with its existing error "Refusing to replace <n> existing application profiles with
0 fetched items" and replaces nothing: the profiles stored before stay in use. The sheet
writer's safety net (below) still checks those.

Checks that already run keep running first; a value reported by an earlier check (for
example a hidden character) may also be reported by a new one. Every problem is listed.

### Empty sections

An empty `Settings:`, `Data:` or `Translate:` means "none" (`{}`), and an empty
`DataFields:` means "none" (`[]`):

- in `ApplicationProfile.from_yaml`, after the validator has passed the file. So this
  applies to non-DRAGEN profiles; the validator still refuses these empty sections in a
  DRAGEN profile, as today;
- in `ApplicationProfile.from_dict`, for every profile already in the database.

So Mark Ready no longer fails on `None.items()`. (No `Data` and no `DataFields` is still
refused, by the Sample_ID rule.)

### In the sheet writer (safety net)

For a profile already in the database, `SampleSheetV2Exporter` checks the same things
again and raises `ValueError` rather than write the value. Mark Ready then stops with its
existing "Failed to generate exports" (500), and nothing is saved:

- a `Settings` or `Data` value that is a decimal number, empty (`None`), a mapping or a
  list, in `_escape_config_cell`:
  `A profile value must be text, a whole number or true/false, not <repr>`;
- a mismatch value taken from the profile:
  - a `Settings` entry that is not 0, 1 or 2:
    `<column> in the profile's Settings must be 0, 1 or 2: <repr>`;
  - a `Data` default (for a sample with no value of its own) that is not 0, 1, 2, blank
    or `na`: `<column> in the profile's Data must be 0, 1, 2, blank or na: <repr>`;
- a data section with no `Sample_ID` column:
  `The <ApplicationName>_Data section has no Sample_ID column`.

What the safety net cannot catch: a version YAML changed before this change. An
`ApplicationProfileVersion: 1.10` synced earlier is stored as the text `"1.1"`, which
looks exactly like a real 1.1. See **Rollout**.

## 2. Mismatch values of samples, runs and templates

- `Sample.__setattr__`, `SequencingRun.__setattr__` and `RunTemplate.__setattr__` refuse a
  `barcode_mismatches_index1` or `barcode_mismatches_index2` value that is not a whole
  number (`True`, `False`, `1.5`, `"1"`) with `ValueError`:
  `barcode_mismatches_index1 must be a whole number, not True`.
  This runs on construction, on every assignment, and when loading from the database.
- Unchanged: whole numbers are still clamped to 0–2, and a sample's `None` ("use the run's
  value, or the profile's default") is still allowed.
- Every page and route already passes whole numbers (`_parse_mismatches`, `_int_field`),
  so nothing a user does changes. A run, sample or template stored with such a value (only
  possible by editing the database) no longer loads: the page that needs it fails with a
  server error, and the log names the field.
- The sheet writers need no change: with this check they can never be given such a value.

## 3. Invisible characters

- `sheet_text.hidden_characters` also returns Unicode format characters (category Cf).
  This one change reaches every place that already uses the rule:
  - **Mark Ready:** the run's name and description, and each sample's name, project and
    description — an error that names each character by its code (`U+200B`), as today;
  - **both sheet writers** (v1 and v2, including `[Cloud_Data]`), as the safety net;
  - **profile sync** (every `Settings`, `Data`, `DataFields` and `Translate` key and value).
- The Mark Ready message (`ValidationService._hidden_character_message`) gains one
  sentence at the end, because these characters cannot be seen:
  `If you cannot see it, delete the text and type it again.` (`them` when there are several).
  The full message becomes, for example:
  *"Sample 'S1' has a hidden character in its name: U+200B. Hidden characters can break
  the Sample Sheet. Remove it before marking the run ready. If you cannot see it, delete
  the text and type it again."*
- Sample IDs are unchanged (they already allow only letters, digits, `-` and `_`).
- The cost: an emoji built from joined emoji, and a few scripts that need a joiner (such as
  Persian), can no longer be used in these fields.

## 4. The local instruments file

- When `data/instruments.py` loads its file (`_initialize_config`, at start and in
  `reload_config`), it checks the file and collects every problem:
  - the file can be read as YAML, and its top level is a mapping (an empty file is not);
  - `instruments`, when present, is a mapping, and each entry in it is a mapping;
  - each entry passes `validate_instrument_yaml`, using the map key as the instrument's
    `name` (the local file has no `name` field). If the check itself fails on a value of
    the wrong type (today `i5_read_orientation: []` and `channel1_bases: 42` raise
    `TypeError` inside it), that entry is reported as could not be checked, and the other
    entries are still checked.
- Any problem raises `InstrumentConfigError` (a new subclass of `ValueError` in
  `data/instruments.py`), so SeqSetup does not start. One message names the file and lists
  every problem:
  `<file name> has errors, so SeqSetup will not start: <problem>; <problem>; ...`
  A problem is one of:
  - `<instrument>: <field>: <message> (<value>)` (`(<value>)` only when the check reports
    a value);
  - `<instrument>: could not be checked: <error>`;
  - `<instrument>: must be a mapping`;
  - for the file as a whole: `cannot be read as YAML: <error>`, `must be a mapping at the
    top level`, or `'instruments' must be a mapping`.
  Today a file YAML cannot read, or one whose top level is not a mapping, already stops
  the start, but with a bare traceback.
- Warnings are ignored for the local file: every local entry lacks `version`, which the
  sync check reports as a warning.
- Start and reload: at start, a missing file still loads no local instruments, with a
  Python warning, as today. `reload_config()` runs the same checks; a missing file there
  still raises `FileNotFoundError`, as today. (Nothing calls `reload_config()` now.)
- Unchanged: `default_cycles` and `index_cycle_options` are not checked, and
  `validate_instrument_yaml` itself (the sync check) is not changed.
- A test keeps the shipped `config/instruments.yaml` passing.

## Docs

- `docs/admin-guide/profiles.rst`, **Validation**: the new sync rules (decimal numbers and
  empty values must be quoted; mapping and list values are refused; required fields may
  not be empty; a mismatch value is 0, 1 or 2 in `Settings`, and 0, 1, 2, blank or `na` in
  `Data`; a `Sample_ID` column in every data section; empty sections mean "none", except
  in a DRAGEN profile), the test-profile version rule, and what happens to a refused file
  (skipped; if every file of a kind is refused, the sync stops and keeps the old ones).
- `docs/admin-guide/profiles.rst`, **Example External Profiles**: the minimal external
  profile gains `DataFields: [Sample_ID]`; without it the new Sample_ID rule refuses it.
  The other examples already pass every new rule.
- `docs/admin-guide/instruments.rst`: the local file is checked at start the same way
  synced instruments are, and a mistake stops SeqSetup with a message naming it.
- `docs/user-guide/validation.rst`: the hidden-character entry names invisible characters
  (zero-width space, byte-order mark, direction marks) and quotes the new message.
- `ApplicationProfile.from_yaml`'s docstring example `ApplicationProfileVersion: 1.0`
  becomes `1.0.0` (the new rule would refuse `1.0`).
- No picture changes.

## Tests

Unit:
- `profile_validator`: each new refusal with its exact message: decimal value, mapping
  value, list value, empty value, each version field, empty required field, each mismatch
  case (including a `Translate`d column, `true`, and `na` in `Settings`), and no
  `Sample_ID` column (including one reached only through `Translate`). Guards that pass:
  whole numbers, `true`/`false` elsewhere, quoted `"4.10"`, `''`, `0`/`1`/`2`, `na` in a
  `Data` mismatch column; `DataFields` absent, empty and `[]` with `Data: {Sample_ID: ''}`;
  every shipped profile in `config/profiles/`. Unchanged: a DRAGEN profile with an empty
  `Settings:`, `Data:` or `DataFields:` is still refused. An unquoted
  `ApplicationProfileVersion: 1.10` and an unquoted `1.1` of the same profile are both
  refused, so they can no longer collide.
- `ApplicationProfile.from_yaml` / `from_dict`: empty sections become `{}` / `[]`
  (`from_yaml` for a non-DRAGEN profile; `from_dict` for a DRAGEN one too).
- `SampleSheetV2Exporter`: each safety-net refusal, from a profile built directly (not
  through the validator), including a mapping value; a `Data` mismatch default of `na` is
  written as `na`; a profile with an empty `Settings` writes an empty section and no
  longer fails. Every test of a `Data` mismatch default sets the sample's own values to
  `None`: a new sample's own value is 1, which would hide the default.
- Models: `Sample`, `SequencingRun` and `RunTemplate` refuse `True`, `False`, `1.5` and
  `"1"` on construction, on assignment and through `from_dict`; `0`, `1`, `2` (and a
  sample's `None`) pass; the clamp is unchanged.
- `hidden_characters`: U+200B, U+FEFF, U+00AD, U+200E, U+202E are hidden; plain letters,
  a no-break space and Latin/Greek/CJK letters are not.
- Both sheet writers (v1; v2 including `[Cloud_Data]`) refuse a sample name holding a
  zero-width space.
- `ValidationService`: a zero-width space in a sample's name is a Mark Ready error with the
  new sentence.
- `data/instruments.py`: the shipped file passes. Each of these raises
  `InstrumentConfigError` with the file name: a bad `i5_read_orientation`, an entry that is
  not a mapping, and a bad flowcell (each naming the instrument and field);
  `i5_read_orientation: []` and `channel1_bases: 42` (naming the instrument); a file YAML
  cannot read, an empty file, and a list at the top level. Two broken instruments are both
  listed in one message. At start a missing file still loads no instruments;
  `reload_config()` with a missing file raises `FileNotFoundError`.

Integration:
- Mark Ready on a run with a zero-width space in a sample's description is refused, with
  the message, and nothing is saved.
- Config sync of an application profile with `SoftwareVersion: 4.10` skips it and logs
  the reason; the same profile with `"4.10"` is synced and written as `4.10`. The GitHub
  fetches are replaced in the test, as `tests/integration/test_scheduled_sync_instrument_cache.py`
  does; only the file listing and the file text are faked, so the real parse and check run.
- Config sync into a database that already holds profiles: (a) one of two application
  profiles refused: the other is stored, the refused one is gone, and a run that needs it
  is blocked at Mark Ready with "profile not found"; (b) the only application profile
  refused: the sync stops with "Refusing to replace …" and the stored profile stays.
- Mark Ready with a stored profile holding `BarcodeMismatchesIndex1: 3` (inserted directly
  into the database) fails and saves nothing.
- A run stored with a sample mismatch value of `true` (written straight into the
  database) cannot be marked ready, and nothing is saved.

Break tests (in the plan): each new check removed in turn must turn a test red.

## Rollout

SeqSetup has never been deployed, so no real database holds profiles stored under the old
rules. The first deployment starts with an empty database and syncs under the new rules.
No migration code.

A development database synced before this change may hold changed values, including a
version stored as `"1.1"` that was `1.10`. Sync once after this change: a sync replaces
every stored profile, so the old ones go. If that sync stops because every application
profile is refused, fix the files and sync again.

## Not in this change

- YAML's other quiet changes to whole numbers (`010` is read as 8, `1:30` as 90) are
  accepted as today, and `true`/`false` are still written as `True`/`False`.
- Look-alike spaces (no-break space and similar): they show as a space.
- A clearer Mark Ready message than "Failed to generate exports" for the safety net, and a
  per-file error on the Config Sync page.
- The unused run-level mismatch route (`POST /runs/{id}/bclconvert`, group 4).
- YAML duplicate keys (the last one wins silently), and checks of `default_cycles` and
  `index_cycle_options`.
- An instrument that neither the synced list nor the local file knows still means
  "forward" i5 (for example one removed after a run was made).
- A version stored before this change (see **Rollout**).

## Merging with 2b

Group 2b is merged (`main` at `97dc047`) and `main` is merged into this branch. 2b changed
none of the files this change touches (checked: no source file or docs page in common), so
every claim above about the code still holds. If `main` moves again before this merges,
merge `main` in again (never a rebase) and run every suite again.
