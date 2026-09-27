# Sample Sheet safety (group 1a) — design

Date: 2026-09-27. Approved in conversation ("ok to the 1a design").
Fixes security audit 2026-09 items N-10, N-11, the rest of N-12, and N-16.

## Problem

1. **Names from synced settings reach the sheet unchecked (N-10, N-11).** Three values
   from the GitHub config sync are written into the v2 Sample Sheet with no escaping:
   a profile's `ApplicationName` (the `[<name>_Settings]` / `[<name>_Data]` section
   headers), an instrument's `samplesheet_name` (`InstrumentPlatform,<name>`), and the
   BCL Convert `software_version` (`SoftwareVersion,<v>`, fallback path). A value with a
   line break adds lines or whole sections to the sheet, including extra sample rows.
   The sync validators only check that the name is present.
2. **Hidden characters reach the sheet (rest of N-12).** `_escape_csv` quotes `,` `"` LF
   and CR, but writes NUL and the other control characters raw. Mark Ready already
   refuses a *line break* in a sample's name, project or description
   (`line_break_in_sample_text`, fixed under N-07). It does not refuse other control
   characters there, and it does not check the run name or run description at all. The
   model turns CR/LF in those two into spaces, but every other control character passes.
3. **The run name form can wipe a field (N-16).** `POST /runs/{id}/name` writes both
   `run_name` and `run_description`, defaulting a missing one to `""`. The only form
   sends both, so users cannot hit it today, but it breaks the "partial updates update
   only what was submitted" hard rule. `run_description` is Sample Sheet content.

## Definitions

- **Plain name:** matches `[A-Za-z0-9_-]+` in full. Same alphabet as Sample IDs and the
  exporters' existing `_PLAIN_IDENTIFIER_RE`.
- **Plain version:** matches `[A-Za-z0-9._-]+` in full (e.g. `4.3.6`).
- **Hidden character:** any character in Unicode category `Cc` (U+0000–U+001F,
  U+007F–U+009F; includes tab, NUL, VT, FF, NEL) plus U+2028 and U+2029.

All three live in one new module, `src/seqsetup/services/sheet_text.py`, used by the
sync validators, the validation service and both exporters, so the rule has one source.
Its API:

- `PLAIN_NAME_RE`, `PLAIN_VERSION_RE` (compiled patterns, used with `fullmatch`)
- `hidden_characters(text: str) -> list[str]` — the distinct hidden characters in
  `text`, in order of first appearance.
- `describe(chars: list[str]) -> str` — e.g. `"U+0000, U+0009 (tab)"`, for messages.

## Design

### 1. Names from synced settings

**At sync (first line):**
- `validate_application_profile_yaml`: `ApplicationName` must be a plain name. Error:
  `Field 'ApplicationName' may only contain letters, digits, '_' and '-': '<value>'`.
- `validate_instrument_yaml`: `samplesheet_name` must be a plain name; every key of
  `onboard_applications` must be a plain name; a non-empty `software_version` string
  must be a plain version. Each is an error on its field.
- A file that fails is skipped exactly as invalid files are skipped today (logged at
  WARNING/ERROR, visible on Admin → Logs). Making skipped files visible on the Config
  Sync page is F29, not part of this change.

**At export (backstop):** the v2 exporter checks `ApplicationName` (both section
headers), `samplesheet_name` (`InstrumentPlatform`) and the fallback `SoftwareVersion`
before writing them, and raises `ValueError` naming the value if one is not plain.
This covers every source, including the local `config/instruments.yaml`, which is not
run through the validator at load.

Effect of the backstop: Mark Ready pre-generates the exports before it changes the
status. An exception there already returns HTTP 500 "Failed to generate exports",
logs the error, and leaves the run in Draft (`routes/runs.py` `update_status`). No
change to that path.

All names shipped today pass: every `samplesheet_name`, onboard application name and
`software_version` in `config/instruments.yaml`, and every `ApplicationName` in the
repo's YAML files and docs examples (checked 2026-09-27).

### 2. Hidden characters

**At Mark Ready (first line):** a new check in `ValidationService.validate_configuration`,
`_validate_hidden_characters`, category `hidden_character_in_text`, severity ERROR:
- For each sample: its name, project and description, counting only hidden characters
  that are *not* line breaks — line breaks keep their existing
  `line_break_in_sample_text` error, so one character is never reported twice. One
  error per sample, naming each field that has one.
  Message: `Sample '<id>' has a hidden character in its <fields>: <describe>. Hidden
  characters can break the Sample Sheet. Remove it before marking the run ready.`
- For the run: its name and description, counting every hidden character. One error
  naming each field.
  Message: `The run has a hidden character in its <fields>: <describe>. Hidden
  characters can break the Sample Sheet. Remove it before marking the run ready.`
- With more than one distinct character the message says `hidden characters` and
  `Remove them`. `<fields>` joins with ` and `, e.g. `project and description`.

The run-field part runs next to the run-name prerequisite, before the early return for a
run with no samples, so an empty run still gets it; the sample part runs next to the
existing line-break check.

Because Mark Ready and the Check panel both use `validate_run`, the new error shows in
the Check panel too. Nothing is removed from the text; the user fixes it.

Behaviour change, deliberate: a tab in any of these five fields now blocks Mark Ready.

**At export (backstop):** `_escape_csv` in both exporters raises `ValueError` when the
value holds a hidden character other than tab, LF or CR. Tab, LF and CR keep today's
handling (formula-guard prefix for a leading tab or CR; quoting for LF and CR), so no
existing output changes. `_escape_identifier` falls back to `_escape_csv`, so it is
covered too. The effect on Mark Ready is the same fail-closed 500 as above. The error
names the character codes only, never the text: the text can be patient data, and the
error is written to the log.

### 3. Run name form

`update_run_name` writes only the fields present in the form, using `"run_name" in form`
and `"run_description" in form`, like `update_sample`. If neither is present it returns
HTTP 400 `Nothing to save` and does not touch or save the run. The UI form still sends
both, so nothing visible changes.

## Docs

- `docs/user-guide/validation.rst`: add the new Mark Ready error next to the line-break one.
- `docs/user-guide/run-setup.rst`: say that hidden characters such as a tab in the run
  name or description are refused at Mark Ready.
- `docs/admin-guide/profiles.rst`: `ApplicationName` — letters, digits, `_` and `-` only;
  a profile file with anything else is skipped at sync.
- `docs/admin-guide/instruments.rst`: the same rule for the sample sheet name and onboard
  application names, and the version rule for `software_version`.

No UI change, so no screenshots are retaken.

## Testing

TDD: each rule gets a test that fails before the code change.

- `sheet_text`: plain name/version accept and refuse; `hidden_characters` finds NUL, tab,
  VT, FF, NEL, U+2028, U+2029, DEL and a C1 character, and finds nothing in plain text,
  accented letters and non-Latin scripts.
- Sync validators: a bad `ApplicationName`, `samplesheet_name`, onboard application name
  and `software_version` are each refused; a guard test loads every instrument in
  `config/instruments.yaml` and every profile YAML in the repo and asserts they still pass.
- Validation service: the new error per field, sample and run; a line break alone still
  gives only `line_break_in_sample_text`; a line break plus a NUL gives both, each once;
  plain text gives neither.
- Exporters: `_escape_csv` raises for NUL, VT, FF, NEL, U+2028; still quotes `,` `"` LF
  CR and still prefixes a leading tab; a bad `ApplicationName` / `samplesheet_name` /
  `software_version` makes `export` raise.
- Routes (integration): Mark Ready is refused, status stays Draft, for a hidden character
  in the run description; Mark Ready with a bad synced `ApplicationName` written straight
  to the database (bypassing the validator) returns 500 and the run stays Draft with no
  sheet stored. That test must also seed a synced instrument whose
  `onboard_applications` lists the same bad name, then call
  `clear_synced_instruments_cache()` and `clear_validation_cache()` — otherwise the
  existing `app_not_available` check refuses Mark Ready before the exporter runs. The test
  first asserts `validate_run` gives zero errors for the run, so a 500 can only come from
  the export guard; posting only `run_name` keeps the description and the reverse; posting
  neither returns 400 and leaves `updated_at` unchanged.
- Break tests: remove each guard in turn and confirm the matching test fails.
- The audit's own proofs for N-10, N-11, N-12 and N-16 are re-run and must now fail.

## Out of scope (recorded, not fixed here)

- `POST /runs/{id}/bclconvert` has the same wipe-a-missing-field bug, but nothing in the
  app posts to it. It goes with the other unreachable routes (group 4).
- F29: skipped sync files are visible only in the logs.
- The local `config/instruments.yaml` is not validated at load; only the export backstop
  covers it.
- `adapter_behavior` is written to the sheet raw, but no route sets it.
- No data migration: the app has never been deployed.

## Addendum after the independent review (2026-09-27)

The review found, and I reproduced, that a synced application profile's `Settings`
keys and values, `Data` keys and values, `DataFields` entries and `Translate` entries
reach the v2 sheet through `_escape_csv`, which quotes a line break but still writes it.
A line-oriented reader then sees extra lines, for example a fake sample row in
`[BCLConvert_Data]`. Same actor as N-10, on the production (profile-driven) path. The
user chose to close it in this change ("fix it here").

- **At sync:** `validate_application_profile_yaml` refuses any hidden character — tab,
  LF and CR included — in `Settings` keys and values, `Data` keys and values,
  `DataFields` entries and `Translate` keys and values, for every `ApplicationType`,
  looking inside nested lists and mappings. Error:
  `Field '<field>' has a hidden character in '<key or entry>': <describe>`.
- **At export (backstop):** the cells of a profile section that come from the profile
  (Settings keys and values, column names, Data default values) go through a new
  `_escape_config_cell`, which refuses any hidden character, tab/LF/CR included, and
  then applies `_escape_csv`.
- **One source:** `sheet_text.refuse_hidden_characters(value, allow="")` raises the
  `ValueError` (codes only, never the text). Both `_escape_csv` methods call it with
  `allow="\t\n\r"`; `_escape_config_cell` calls it with nothing allowed.

Review minors fixed in the same change: literal U+2028/U+2029 in source replaced with
escapes; the `instruments.rst` claim narrowed to what the writer checks; the shipped-config
guard test also covers `config/instruments/*.yaml`; the line-break-only test covers every
character in `_LINE_BREAK_CHARS`; the `_escape_csv` docstring count; `_require_plain`
accepts a non-string config value (e.g. an unquoted YAML number) by converting it with
`str`, as the old f-string did; import order; `run-setup.rst` wording (a line break in the
name or the description is saved as a space); a sentence on how to remove an invisible
character.

More out of scope, found by the review and not changed here: the v1 writer writes index
sequences raw (they are validated in the model); the fallback global `OverrideCycles` is
written raw (Mark Ready refuses a malformed one); Unicode format characters (zero-width
space, BOM, bidi controls) do not break the sheet's structure but can make two names look
the same — a follow-up.

## Addendum after the second review (2026-09-27)

The second review found, and I reproduced, that a synced profile `Settings` key such as
`[BCLConvert_Data]` is written as the line `[BCLConvert_Data],` — a section header of its
own, with the rows after it read as data. Quoting cannot help: the line starts with `[`.
Column names have the same problem. The user chose to close it here ("fix it here").

- **Names are plain.** Every name that reaches the sheet's structure — a `Settings` key, a
  `Data` key, a `DataFields` entry and both sides of `Translate` — must be text made only
  of letters, digits, `_` and `-`. At sync, `validate_application_profile_yaml` refuses
  any other name: `Field '<field>' has a name that may only contain letters, digits, '_'
  and '-': <name>`. A name that holds a hidden character is reported once, by the
  hidden-character rule. At export, the setting name and the column name go through
  `_require_plain(..., PLAIN_NAME_RE, "Setting name" | "Column name")`.
- **No value starts a section.** A `Settings` or `Data` value is written as a cell; as a
  data default in the first column it would start its line. `sheet_text.starts_a_section`
  (a leading `[`, after any spaces) is the one rule. At sync: `Field '<field>' value for
  '<key>' cannot start with '[': <value>`. At export, `_escape_config_cell` refuses it.
- **Shapes.** The writer reads `Settings`, `Data` and `Translate` as mappings and
  `DataFields` as a list for every `ApplicationType`, so the sync now refuses another
  shape for every type (empty is still allowed; the Dragen rule still requires the first
  three). Before, a wrong shape skipped the character checks.
- **Numbers are refused, not converted.** This reverses the first addendum's minor:
  `_require_plain` refuses a value that is not text, because `str(4.10)` is `'4.1'`. The
  sync already refuses a non-text `samplesheet_name` and `software_version`; it now also
  refuses a non-text `ApplicationName`.
- **Docs.** `profiles.rst` lists the three new rules and says that a YAML block value
  (`|`, `>`) ends in a line break and is refused, so use one line or `>-`.
  `run-setup.rst` says that pressing Enter in the description makes a line break, which
  is saved as a space; only the run name saves on Enter.

All six shipped application profiles pass the new rules (a test loads each one).

The third review found no Critical or Important issue. Fixed with it: `profiles.rst` says
that names must be text (quote `"1"`, `"yes"`, `"on"`), that `>-` must have no blank line
inside, that a `[` after spaces counts, and that a YAML list value is refused; a test
exports every shipped profile through the writer, so a writer rule stricter than the sync
is caught.

Follow-ups found by that review, not changed here (each is older than this change, and
none writes a bad sheet):

- An empty `Settings:` or `Data:` (loads as `None`) on a profile that is not Dragen passes
  the sync, then every Mark Ready of that test fails with a plain 500 "Failed to generate
  exports"; the cause is only in the log. Decide: treat empty as absent, or refuse it at
  sync.
- A number in a profile value is converted with `str` (`SoftwareVersion: 4.10` is written
  as `4.1`). Mark Ready catches it only when the instrument lists software versions.
- A `None` value is written as the text `None`.
- A profile with empty `Data` and `DataFields` writes a data header with no `Sample_ID`
  column; the sync accepts `DataFields: []`, even for Dragen.
- `ApplicationName: 123` is refused with "may only contain letters, digits…", which does
  not say that the problem is the missing quotes.
