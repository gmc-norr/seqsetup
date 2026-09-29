# Sample Sheet follow-ups — design

Date: 2026-09-29. Branch `fix/sheet-followups`, from `main` at `add956b`; `main` at
`97dc047` (group 2b) merged in.

## Why

Earlier reviews (groups 1a and 1c) found five ways a value can reach the Sample Sheet
unchecked or changed. All five were confirmed in the code on 2026-09-29:

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
   because `str(None)` is `"None"`.
3. **Two profile shapes break Mark Ready or the sheet.** An empty `Settings:` (or `Data:`,
   `Translate:`) in a non-DRAGEN profile passes sync as `None`, and every Mark Ready that
   uses it then fails with a 500 (`None.items()`). A profile whose data section has no
   `Sample_ID` column (empty `Data` and `DataFields`, or a list without it) writes rows
   with no sample name at all.
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

The shipped profiles and the shipped instruments file pass every new check (probed
2026-09-29: no decimal numbers, no empty values, every data section has `Sample_ID`, all 11
local instruments pass `validate_instrument_yaml`).

## Decisions (made with the user)

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

## 1. Profiles

### At sync

`services/profile_validator.py` refuses a profile file (the existing
`ProfileValidationError`, one message per problem) when:

- **Application profile, a `Settings` or `Data` value is a decimal number** (a YAML float,
  including `.inf` and `.nan`):
  `Field '<Settings|Data>' value for '<key>' is a number with a decimal point, which YAML may have changed (4.10 is read as 4.1). Put the value in quotes, for example "4.10".`
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
  `Translate` gives it — must be 0, 1, 2 or blank (`''`). `true`/`false` are refused
  (Python counts `true` as 1).
  - `Settings`: `Field 'Settings' value for '<key>' fills <column> and must be 0, 1 or 2 (BCL Convert allows at most 2 mismatches): <repr of the value>`
  - `Data`: `Field 'Data' value for '<key>' fills <column> and must be 0, 1, 2 or blank (BCL Convert allows at most 2 mismatches): <repr of the value>`
- **The data section has no `Sample_ID` column.** The columns are `DataFields` (or the
  `Data` keys when there is no `DataFields` list), each renamed by `Translate`;
  `Sample_ID` must be one of them:
  `The data section has no Sample_ID column. Add Sample_ID to DataFields (or to Data when there is no DataFields list).`

Everything else is unchanged, including: whole numbers, `true`/`false` and text are
accepted; a refused file is skipped, and its reason is a warning on Admin → Logs; a run
that needs a skipped profile is blocked at Mark Ready with "profile not found".

Checks that already run keep running first; a value reported by an earlier check (for
example a hidden character) may also be reported by a new one. Every problem is listed.

### Empty sections

An empty `Settings:`, `Data:` or `Translate:` means "none" (`{}`), and an empty
`DataFields:` means "none" (`[]`), in `ApplicationProfile.from_yaml` and in
`ApplicationProfile.from_dict` (profiles already in the database). The validator already
allows them. So Mark Ready no longer fails on `None.items()`. (An empty `Data` with an
empty `DataFields` is still refused, by the Sample_ID rule.)

### In the sheet writer (safety net)

For a profile already in the database, `SampleSheetV2Exporter` checks the same things
again and raises `ValueError` rather than write the value. Mark Ready then stops with its
existing "Failed to generate exports" (500), and nothing is saved:

- a `Settings` or `Data` value that is a decimal number or empty (`None`), in
  `_escape_config_cell`:
  `A profile value must be text or a whole number, not <repr>`;
- a mismatch value taken from the profile (a `Settings` entry, or a `Data` default for a
  sample with no value of its own) that is not 0, 1 or 2 (or blank, for `Data`):
  `<column> from the profile must be 0, 1 or 2: <repr>`;
- a data section with no `Sample_ID` column:
  `The <ApplicationName>_Data section has no Sample_ID column`.

A sample's own mismatch values are unchanged: the model already limits them to 0–2.

## 2. Invisible characters

- `sheet_text.hidden_characters` also returns Unicode format characters (category Cf).
  This one change reaches every place that already uses the rule:
  - **Mark Ready:** the run's name and description, and each sample's name, project and
    description — an error that names each character by its code (`U+200B`), as today;
  - **both sheet writers** (v1 and v2), as the safety net;
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

## 3. The local instruments file

- When `data/instruments.py` loads its file (`_initialize_config`, at start and in
  `reload_config`), every entry under `instruments` is checked with
  `validate_instrument_yaml`, using the map key as the instrument's `name` (the local file
  has no `name` field). `instruments` that is not a mapping, or an entry that is not a
  mapping, is an error too.
- Any error raises `InstrumentConfigError` (a new subclass of `ValueError` in
  `data/instruments.py`), so SeqSetup does not start. The message names the file and every
  problem:
  `<file name> has errors, so SeqSetup will not start: <instrument>: <field>: <message> (<value>); ...`
  (`(<value>)` only when the check reports a value.)
- Warnings are ignored for the local file: every local entry lacks `version`, which the
  sync check reports as a warning.
- Unchanged: a missing file still loads no local instruments (as today, with a Python
  warning). `default_cycles` and `index_cycle_options` are not checked.
- A test keeps the shipped `config/instruments.yaml` passing.

## Docs

- `docs/admin-guide/profiles.rst`, **Validation**: the new sync rules (decimal numbers and
  empty values must be quoted; required fields may not be empty; mismatch values 0, 1, 2
  or blank; a `Sample_ID` column in every data section; empty sections mean "none"), and
  the test-profile version rule. The examples already quote nothing that the rules refuse.
- `docs/admin-guide/instruments.rst`: the local file is checked at start the same way
  synced instruments are, and a mistake stops SeqSetup with a message naming it.
- `docs/user-guide/validation.rst`: the hidden-character entry names invisible characters
  (zero-width space, byte-order mark, direction marks) and quotes the new message.
- `ApplicationProfile.from_yaml`'s docstring example `ApplicationProfileVersion: 1.0`
  becomes `1.0.0` (the new rule would refuse `1.0`).
- No picture changes.

## Tests

Unit:
- `profile_validator`: each new refusal with its exact message (decimal value, empty value,
  each version field, empty required field, each mismatch case including a `Translate`d
  column and `true`, no `Sample_ID` column including one reached only through
  `Translate`); and guards: whole numbers, `true`/`false` elsewhere, quoted `"4.10"`,
  `''`, `0`/`1`/`2` pass; every shipped profile in `config/profiles/` still passes.
- `ApplicationProfile.from_yaml` / `from_dict`: empty sections become `{}` / `[]`.
- `SampleSheetV2Exporter`: each safety-net refusal, from a profile built directly (not
  through the validator); a profile with an empty `Settings` writes an empty section and
  no longer fails.
- `hidden_characters`: U+200B, U+FEFF, U+00AD, U+200E, U+202E are hidden; plain letters,
  a no-break space and Latin/Greek/CJK letters are not.
- `ValidationService`: a zero-width space in a sample's name is a Mark Ready error with the
  new sentence.
- `data/instruments.py`: the shipped file passes; a copy with a bad
  `i5_read_orientation`, with an entry that is not a mapping, and with a bad flowcell each
  raise `InstrumentConfigError` naming the instrument and field; a missing file still
  loads empty.

Integration:
- Mark Ready on a run with a zero-width space in a sample's description is refused, with
  the message, and nothing is saved.
- Config sync of an application profile with `SoftwareVersion: 4.10` skips it and logs
  the reason; the same profile with `"4.10"` is synced and written as `4.10`. The GitHub
  fetches are replaced in the test, as `tests/integration/test_scheduled_sync_instrument_cache.py`
  does; only the file listing and the file text are faked, so the real parse and check run.
- Mark Ready with a stored profile holding `BarcodeMismatchesIndex1: 3` (inserted directly
  into the database) fails and saves nothing.

Break tests (in the plan): each new check removed in turn must turn a test red.

## Not in this change

- YAML's other quiet changes to whole numbers (`010` is read as 8, `1:30` as 90) are
  accepted as today, and `true`/`false` are still written as `True`/`False`.
- Look-alike spaces (no-break space and similar): they show as a space.
- A clearer Mark Ready message than "Failed to generate exports" for the safety net, and a
  per-file error on the Config Sync page.
- The unused run-level mismatch route (`POST /runs/{id}/bclconvert`, group 4).
- YAML duplicate keys (the last one wins silently), and checks of `default_cycles` and
  `index_cycle_options`.

## Merging with 2b

Group 2b is merged (`main` at `97dc047`) and `main` is merged into this branch. 2b changed
none of the files this change touches (checked: no source file or docs page in common), so
every claim above about the code still holds. If `main` moves again before this merges,
merge `main` in again (never a rebase) and run every suite again.
