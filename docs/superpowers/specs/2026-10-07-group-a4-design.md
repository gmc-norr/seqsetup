# Group A4: test versions — design

Date: 2026-10-07. Base: main `e65c60d` (group A3 merged). Branch `fix/group-a4`.
Source: project review finding S-12 (2026-10-03). Decisions: the user, during the A3
brainstorm (2026-10-05) and this brainstorm (2026-10-07).

## Why

Every sample names a test (`Sample.test_id`, for example `WGS`). The test profile with that
`TestType` says which application profiles write the sample's sheet sections. Today:

- **The test a sample gets depends on storage order.** `TestProfileRepository.get_by_test_type`
  (`repositories/test_profile_repo.py:15-23`) runs `find_one({"test_type": ...})` with no sort.
  The sheet plan (`services/sheet_plan.py:200-203`, the writer and the checks) and the
  application check (`services/application_profile_validator.py:76-79`) both use it. Measured
  on `e65c60d` with mongomock, two `WGS` files stored in two orders:

  ```
  stored ('1.0.0', '2.0.0') -> get_by_test_type('WGS') gives 1.0.0
  stored ('2.0.0', '1.0.0') -> get_by_test_type('WGS') gives 2.0.0
  ```

  Mark Ready checks against the same profile the writer uses, so nothing flags it.
- **A sample has no version.** No sample field, paste column, box or LIMS field carries one.
- **Sync accepts any version text.** `validate_test_profile_yaml`
  (`services/profile_validator.py:56-64`) asks only for a PEP 440 version. Measured on
  `e65c60d`: `1.0.0`, `1.0`, `1`, `1.0.0rc1`, `01.0.0`, `1.0.0.0`, `v1.0.0`, `1` (a number) and
  `1.0.0+local` are all accepted.
- **Two files with the same test and version both sync** (review probe
  `p13_duplicate_test_type.py`; each file is checked on its own).

Test profile files are read only by the sync (`services/github_sync.py:204-213`,
`_parse_test_profile` at 716-722). No other code reads them.

## Decisions

1. Every sample carries a **test version** next to its test.
2. A sample's version text is `1`, `1.2` or `1.2.3`. `1` means the newest synced 1.x.x, `1.2`
   the newest 1.2.x, and `1.2.3` exactly 1.2.3.
3. A sample with a test but no version: **Mark Ready refuses.**
4. A test profile's `Version` must be **three whole numbers** at sync. Two files with the
   **same test and the same version: both are refused.** **Any refused test file means no test
   profile is stored and the stored ones are kept**, as for instrument files (user, plan review
   of 68fc2c0): otherwise a refused newest file would make `1` quietly pick an older version.
5. The version text stays on the sample while the run is a Draft. **Mark Ready picks the
   exact version** at that moment, checks and writes with it, and **saves it on the Ready run**
   (user, question 1).
6. **A test and its version are set together.** Setting a test with an empty version box is
   refused. A sample never keeps an old test's version (user, question 2).
7. Inputs: a paste column and a "Version for rows without one" box; a version box beside the
   test in "Set test"; the run page's fix boxes; the single add-sample route; a LIMS field with
   an admin mapping box.
8. The Sample Sheet's text does not change. The API's JSON export carries no test today and is
   not changed (later list).
9. **A test file is read whatever the case of its `.yaml` / `.yml` ending** (user, plan review
   of 562b2e2): a `Wgs_1.3.YAML` was skipped without a word, so `1` kept the older version and
   the sync said success. Other files in the folder are skipped, as today.
10. **The config-sync page shows the last sync**: its time, status and message, red on an
    error; a manual sync's result is red when the sync did not succeed (user, plan review of
    562b2e2). Decision 4 keeps the stored test profiles; someone must see that it did.
11. **A Ready or Archived run's validation page says its checks are live** (user, plan review
    of 562b2e2): they use today's synced profiles, while its Tests line shows the versions its
    sheet was written with. The checks themselves do not change.
12. **A LIMS sample ID or test sent as a number with a decimal point, or as `true`/`false`, is
    refused** (user, plan review of 562b2e2; it was on the later list): JSON reads `23.10` as
    `23.1`, which would change a sample's identity without a word.

## §1 What is stored, and the rules

### The sample's version

- New field `Sample.test_version: str = ""` (`models/sample.py`), in `to_dict` / `from_dict`.
  Clone and templates copy it, since they copy samples through `to_dict` / `from_dict`
  (`services/run_builder.py:93-95`, `models/run_template.py:93, 142`).
- `Sample.__setattr__` enforces it on every assignment: `""`, or 1 to 3 whole numbers joined by
  dots, each `0` or without a leading zero and **at most 9 digits**
  (`^(0|[1-9][0-9]{0,8})(\.(0|[1-9][0-9]{0,8})){0,2}\Z`), so a version is at most 29
  characters. Surrounding spaces are stripped first. The value must be text (`str`); anything
  else, and any text that breaks the rule, raises `ValueError`. Nothing is shortened to fit:
  `test_version` is not one of the strings the model cuts at 256 (`models/sample.py:151-155`).

  ```
  A test version is 1, 2 or 3 whole numbers joined by dots, each at most 9 digits, like 1, 1.2 or 1.2.3: 'v1'
  ```

  The text before the colon is the constant `TEST_VERSION_RULE` in `models/sample.py`, shared by
  every message below. A message shows at most the first 40 characters of the value, then `…`.
- Why the limit (review of 311d730): without one, a 4,301-digit number passes the pattern and
  then raises when turned into a number (measured: `Exceeds the limit (4300 digits) for integer
  string conversion`); and an input cut at 256 characters can pass where the whole input would
  not (measured: a 302-character paste cell `1000…0v` passes once cut to 256).

### The test profile's version, at sync

- `validate_test_profile_yaml` adds: `Version` must be three whole numbers joined by dots, each
  `0` or without a leading zero and at most 9 digits
  (`^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\Z`). Otherwise:

  ```
  Field 'Version' must be three whole numbers joined by dots, each at most 9 digits, like 1.0.0: '1.0'
  ```

  The PEP 440 check and the decimal-number message stay; the PEP 440 check also catches the
  `ValueError` that a 4,301-digit number raises in it (measured), and both messages show at most
  40 characters of the value.
- After all test files are read, the sync looks for one test and version in more than one
  file. Every file of such a pair is refused, and logged as a warning:

  ```
  Test profiles refused: WGS 1.2.0 is in Wgs_a.yaml and Wgs_b.yaml. A test and version may be in one file only.
  ```

- **A refused test file stops every test profile change** (decision 4). A test file is refused
  when it breaks a rule above, cannot be read as YAML, is empty, has no download link, or does
  not give a test profile for any other reason; a sub-folder of the test profile folder that
  cannot be listed is refused too. Today such a file is skipped with a warning and the rest are
  stored (`_fetch_profiles_recursive`, `github_sync.py:504-530`); application profile files keep
  that behavior. When a test file is refused, the sync stores no test profile, keeps every
  stored one, still stores the application profiles, index kits and instruments as today, clears
  the validation cache as today, and ends with status `error` and this message (the instrument
  message, `github_sync.py:329-344`, is unchanged when only instrument files are refused, and
  follows the test sentence when both are):

  ```
  Test profile files were refused, so no test profiles were stored and the stored ones are kept: profiles/test_profiles/Wgs_new.yaml: Profile validation failed for 'Wgs_new.yaml': Field 'Version' must be three whole numbers joined by dots, each at most 9 digits, like 1.0.0: '1.2'; WGS 1.2.0 is in Wgs_a.yaml and Wgs_b.yaml. Synced 3 application profiles.
  ```

  (Measured on the prototype.) Each refused file is `<path>: <problem>`, in the order read; the
  problems the sync names itself are `is empty`, `has no download link`, `cannot be read as
  YAML: …` and, for a sub-folder, `<path>/: could not be listed: …`; a repeated test and version
  is `WGS 1.2.0 is in Wgs_a.yaml and Wgs_b.yaml`.

  The guard against replacing stored profiles with nothing (`_guard_against_destructive_replace`)
  runs as today when the test profiles are stored.
- **A test file is a file in the test profile folder whose name ends in `.yaml` or `.yml`, in
  any case** (decision 9): `Wgs_1.3.YAML` and `Rna.Yml` are read and checked like `Wgs.yaml`.
  Any other file there (a `README.md`) is skipped, as today. Today the ending must be lower case
  (`github_sync.py:538`), so a `.YAML` file is skipped without a word. Application profile,
  instrument and index kit folders are not changed.

### Where the sync's result is shown

- **The config-sync page** (`templates/admin/config_sync.html`, `routes/admin/config_sync.py`;
  decision 10). Every sync, manual or scheduled, already stores `last_sync_at`,
  `last_sync_status` and `last_sync_message` (`repositories/profile_sync_config_repo.py:17-33`);
  no page shows them. The status panel gains a last-sync line: the time (`| localtime`), the
  status in brackets and, below it, the message; `—` before the first sync:

  ```
  Last sync: 2026-10-08 10:12 CEST (error)
  Test profile files were refused, so no test profiles were stored and the stored ones are kept: …
  ```

  With status `error` the line sits in the red box the admin pages use for errors
  (`bg-red-100 border border-red-400 text-red-800`). A manual sync's result box, always green
  today (`config_sync.html:15-17`), is red when the sync did not succeed, and so is `Sync
  service not available`; `Configuration saved` stays green. This shows A2's instrument
  refusals too, which end the same way.

### Finding a sample's test profile

- One function, `resolve_test(test_profile_repo, test, asked)` in a new module
  `services/versioned_tests.py` (not `test_*.py`: with no `testpaths` set, pytest would collect a
  source file of that name). It returns a `ResolvedTest`: the profile, or the reason there
  is none. Both the sheet plan and the application check call it. `get_by_test_type` is
  removed: no other source code calls it. Three test fakes implement it
  (`tests/unit/test_samplesheet_v2_exporter.py:635`,
  `tests/unit/test_check_broken_samplesheets.py:103`, `tests/unit/test_validation.py:823`) and
  move to the new method.
- The repository gains `list_by_test_type(test)`: every stored profile of that test, no logic
  (repositories hold none).
- Matching: `asked` split on dots gives 1 to 3 numbers; a stored version matches when its first
  numbers equal them. The newest match wins, compared as numbers (1.10.0 is newer than 1.9.0).
- Stored records whose `version` breaks the sync rule above (three whole numbers, each at most
  9 digits) are not used. The pattern is checked before any text is turned into a number, so an
  oversized stored version is skipped and never raises. Such records can only come from a sync
  before this change; the next sync that refuses no test file replaces every test profile.
- Matching compares numbers, never text: `1` does not match 10.0.0 or 11.0.0, `1.2` does not
  match 1.20.0, and 1.10.0 is newer than 1.9.0.
- Reasons, each with the text the checks show (§3):
  - **No profile of that test** (`test_profile_not_found`, text unchanged):
    `No test profile found for test type 'WGS'`
  - **No version matches** (`test_version_not_found`):
    `No synced WGS version matches 1. Synced WGS versions: 2.0.0, 2.1.0.`
  - **The newest match is stored twice** (`test_version_stored_twice`; only data from before
    this change or written by hand can hold it):
    `WGS 1.2.0 is stored twice (Wgs_a.yaml, Wgs_b.yaml). Sync the profiles again.`
- Never "the first one the database returns".

## §2 Where the version is typed

No cut can make a version good (review of 311d730): every input refuses a version over 29
characters, and anything cut at 256 characters is still over 29, so it is refused, never
shortened into a valid one. The boxes are read with `.strip()` only, not with `sanitize_string`
(`routes/utils.py:87-97`); a LIMS value is checked by its JSON type before it becomes text.

### Paste and file (`services/sample_parser.py`, `routes/samples.py`, `services/paste_preview.py`)

- New header set `TEST_VERSION_HEADERS = {"test_version", "testversion", "test version",
  "test-version"}`. A column named only `version` is **not** read: a lab file may have another
  column of that name. `_is_header_row` and `_detect_column_mapping` learn the new set;
  `FIELD_LABELS` gains `"test_version": "Test version"`.
- Without a header row the columns stay `sample_id, test_id, index1, index2`
  (`_HEADERLESS_FIELDS`); a version needs a header.
- `ParsedSample.test_version`. A cell that breaks the rule refuses the whole paste, naming the
  rows, like a row without a sample ID. A cell over 256 characters, cut like every cell
  (`sample_parser.py:269-272`), is still refused (measured in the plan's break tests: checking
  the cell before the cut changes no outcome):

  ```
  Row(s) 3, 5: the test version is not right. A test version is 1, 2 or 3 whole numbers joined by dots, each at most 9 digits, like 1, 1.2 or 1.2.3.
  ```

- New box **"Version for rows without one"** (`default_test_version`) beside "Test for rows
  without one" (`templates/runs/_paste_form.html:29-39`). `_read_paste_input` checks it like the
  default test (`routes/samples.py:312-314`); a bad value is a 400:

  ```
  Version for rows without one: A test version is 1, 2 or 3 whole numbers joined by dots, each at most 9 digits, like 1, 1.2 or 1.2.3.
  ```

  Rows that have a version keep it. Each new sample with a test (its own, or the one from "Test
  for rows without one") gets `ps.test_version or paste.default_version`; a sample without a
  test gets no version from the box (decision 6).
- A row that takes the test picked in "Test for rows without one" and has no version, none in
  the row and none in the box, refuses the whole paste (decision 6; plan review of 562b2e2: such
  rows got the test and no version). A row with a version of its own may take the picked test.

  ```
  Row(s) 3, 5: the picked test needs a version. Fill in Version for rows without one, for example 1.
  ```

  The preview marks such a row Look with the note `The picked test needs a version.`, gives
  this text above the table, and offers no Add, as for a version without a test. Rows with a
  test of their own and no version are not refused here: Mark Ready asks for the version, and
  the run page's fix boxes set it (§2, §3).
- A row with a version of its own and no test (none in the row and none picked) refuses the
  whole paste (decision 6; review of plan 68fc2c0):

  ```
  Row(s) 3, 5: a test version needs a test. Give the row a test, or pick one in Test for rows without one.
  ```

- The preview shows a Version column, marks a picked version "(picked)" as it marks a picked
  test, and adds the note `No test version. Check will ask for one.` to a row with a test and no
  version (when test profiles exist, as for the test note). A row with a version of its own and
  no test is marked Look with the note `A test version needs a test.`; a notice above the table
  gives the refusal text above, and the preview offers no Add, as for a repeated ID. The
  preview's Add form sends the box back like `default_test_id`.
- The format help (`templates/wizard/_sample_paste_format_help.html`) and the paste hint name
  the `test_version` column.

### "Set test" for chosen samples (`POST /runs/{run_id}/samples/set-test-id`)

- The bulk panel (`templates/wizard/_bulk_lane_panel.html:50-56, 117-125`) gains a version text
  box beside the test list, and the hidden form a `test_version` field. `app.js`
  (`applyBulkTestIdForm`, `clearBulkTestIdForm`, 572-602) sends it; Clear sends both empty.
- `set_test_id_bulk` (`routes/samples.py:1220-1252`) reads `test_version` and:
  - both empty → clears test and version (Clear, and today's empty Apply);
  - a test and no version → 400 `Give the test version too, for example 1.`;
  - a version and no test → 400 `Pick a test for this version.`;
  - a version that breaks the rule → 400 with the rule text;
  - otherwise sets both on every chosen sample.

  The audit event `sample.bulk_test_id_set` gains `test_version`.
- The test list shows each test once (today it shows one entry per stored profile, so two
  versions would show `WGS` twice). Beside the box, a hint lists the synced versions:
  `Synced: WGS 1.0.0, 1.2.0 · RNA 2.0.0`. The same applies to the paste form's test list and the
  run page's fix box.

### The run page's fix boxes (`templates/runs/_validate_panel.html:83-102`, `routes/main.py`)

- Samples with no test: today's box gains the version box, and posts both to the same route
  (`Set test and version for the N samples without one:`).
- Samples with a test but no version: one box per test, posting that test's sample IDs, the
  test as a hidden field, and the version box (`WGS: set the version for the 3 samples without
  one:`). These boxes never change a sample's test. `routes/main.py` gains
  `_samples_without_version(run)`, grouped by test, beside `_samples_without_test`.
- **A box from a page that is out of date is refused** (review of plan 68fc2c0). Each box posts
  a hidden `only_if`: `no_test` for the first, `no_version` for the per-test boxes. Before
  writing, `set_test_id_bulk` checks every listed sample still in the run: with `no_test` it must
  have no test; with `no_version` its test must be the posted test and it must have no version.
  Otherwise nothing is saved, and the answer is a 409 naming the samples (10 names at most, then
  ` and N more`):

  ```
  These samples changed since this page was loaded: S2. Reload the page and try again.
  ```

  Measured on the prototype: without this, a per-test box loaded before another user set S2 to
  `RNA 2` set S2 to `WGS 1`. Another `only_if` value is a 400. "Set test" in the bulk panel posts
  no `only_if` and is unchanged: it is meant to change tests.

### The sample table (`templates/wizard/_sample_row.html:41, 167`)

- The Test cell shows the test and the version text, for example `WGS 1`. On a Ready or
  Archived run it adds the saved exact version: `WGS 1 (1.2.3)` (§3).

### Adding one sample (`POST /runs/{run_id}/samples`)

- `add_sample` (`routes/samples.py:380-418`, no page posts to it today) reads `test_version`,
  with the same rules as "Set test". The audit event `sample.added` gains `test_version`.

### Lab system (`services/sample_api.py`, `routes/admin/sample_api.py`)

- `parse_api_samples` reads `test_version` (aliases `test_version`, `testversion`; a mapped
  field name goes first, as for every field; a field that is `null` is passed over for the next
  name, as for every field). It checks the **raw JSON value** before the
  generic `str(val).strip()[:_MAX_FIELD_LEN] if val else ""` every other field gets
  (`sample_api.py:646-653`). Measured on `e65c60d`, that line turns JSON `1.10` into `"1.1"`
  (the wrong version), `0` into `""` and `true` into `"True"`. So, by JSON type:
  - absent or `null`: no version;
  - text: stripped, then the rule;
  - a whole number (not `true`/`false`): its digits, so `2` → `"2"` and `0` → `"0"`, then the
    rule (a negative number or one over 9 digits is refused);
  - a number with a decimal point: refused, since JSON has already read `1.10` as `1.1`;
  - `true`, `false`, a list or an object: refused.

  A refused value refuses the whole worklist, naming the sample, shown as
  `Worklist import rejected: ...`:

  ```
  Sample 'S1' has a test version that is not right ('v1'). A test version is 1, 2 or 3 whole numbers joined by dots, each at most 9 digits, like 1, 1.2 or 1.2.3.
  Sample 'S1' has a test version that is a number with a decimal point (1.1), which JSON may have changed (1.10 is read as 1.1). Send it as text, for example "1.10".
  Sample 'S1' has a test version that is not text or a whole number (true).
  Sample 'S1' has a test version but no test.
  ```

  The last one is for a sample with a version and no test (decision 6; review of plan 68fc2c0).

- **The sample ID and the test are checked by JSON type too** (decision 12). Measured on
  `e65c60d`: `{"sample_id": 23.10}` imports as `23.1`, `true` as `True`, a test `1.10` as `1.1`
  and a test `true` as `True`; `false` is refused as a missing sample ID; whole numbers keep
  their digits (`12345`, `7`). Now a number with a decimal point, `true` or `false` refuses the
  whole worklist (a missing sample ID names the row, so a bad one does too):

  ```
  LIMS row 3 has a sample ID that is a number with a decimal point (23.1), which JSON may have changed (1.10 is read as 1.1). Send it as text, for example "1.10".
  LIMS row 3 has a sample ID that is not text or a whole number (true).
  Sample 'S1' has a test that is a number with a decimal point (1.1), which JSON may have changed (1.10 is read as 1.1). Send it as text, for example "1.10".
  Sample 'S1' has a test that is not text or a whole number (true).
  ```

  Text and whole numbers are read as today. The other fields are not changed (later list).

- `import_worklist_samples` (`routes/samples.py:664-784`) sets `test_version`.
- The admin LIMS page gains a **Test version field** box (`field_test_version` →
  `field_mappings["test_version"]`), beside the four mapping boxes
  (`routes/admin/sample_api.py:55-68`, `templates/admin/sample_api.html:66-70`).
- iGene's worklist (`{sample_id: test_id}`, `sample_api.py:554-561`) has no version, so its
  samples arrive without one and are fixed on the run page. The broken Load Worklists button
  (later list) is not fixed here.

## §3 Mark Ready, what is saved, and where it is shown

### The checks

- New error `missing_test_version` (`services/validation.py`, beside
  `_validate_samples_have_test_id` at 246-250, under the same condition: profile repositories
  configured and samples present). Samples without a test are left to `missing_test_id`:

  ```
  2 sample(s) have a test but no test version: S1, S2. Set the version on the run page, for example 1.
  ```

  (5 names at most, then ` and N more`, as `missing_test_id` does.)
- The application check resolves each sample's test with `resolve_test`. A sample without a
  version is skipped there (it is reported above). The three reasons in §1 become application
  errors of those types, once per test and version text. `_application_error_detail.html` gains
  labels for the two new types.
- The sheet plan resolves with `resolve_test` too, grouping samples by test and version text.
  The writer's own texts (problem 1) gain:
  - `Sample S1 has no test version, so it would not be on the Sample Sheet.`
  - `Test 'WGS' 1 has no test profile.` (for every reason in §1)

  The sheet plan's other texts that name a test name its version text too, so two versions of
  one test can be told apart (review of plan 68fc2c0; today `BCLX 1.0.0 (test WGS) and BCLX
  2.0.0 (test WGS)`): `Test 'WGS' 1 lists …, which is not stored.`, `Test 'WGS' 1 has no
  BCLConvert profile, …`, `Test 'WGS' 1 lists 2 profiles for …`, and `… (test WGS 1) and … (test
  WGS 2) have different …`.

### What Mark Ready saves

- The sheet plan records, for each test and version text it resolved: the test, the text asked,
  the exact version and the file (`source_file`). `ValidationResult.test_versions` carries this
  list, in the order of first appearance.
- New run field `SequencingRun.test_versions_used: list[dict]` (keys `test`, `asked`,
  `version`, `file`), in `to_dict` / `from_dict`. Mark Ready sets it from the validation result
  that let the run through, beside `samplesheet_v1_withheld` (`routes/runs.py:686-697`).
  READY→DRAFT clears it (`routes/runs.py:698-710`). It joins `RUN_DIFF_IGNORED_KEYS`
  (`services/run_diff.py:12-16`), as `samplesheet_v1_withheld` did. It does not join
  `_FINGERPRINT_IGNORED_KEYS`: it is always empty on a Draft, where that comparison runs.
- The audit event `run.status.changed` of a Mark Ready gains `test_versions` (the same list), so
  the versions a sheet was written with stay in the audit trail after READY→DRAFT clears the
  run's copy (plan review of 562b2e2; today the event holds only the two statuses,
  `routes/runs.py:716-723`).
- **The plan's fingerprint** (A3) keys each test entry by test and version text, and already
  holds the resolved profile's content, version included. If a sync brings a newer match between
  the checks and the writing, the fingerprints differ and Mark Ready answers 409
  (`profiles_changed_during_export`) and saves nothing, as for any other profile change.

### Where it is shown

- **Validation page** (`templates/validation/page.html`, under the approval bar): `Tests: WGS 1
  uses 1.2.3 (Wgs.yaml) · RNA 2 uses 2.0.1 (Rna.yaml)` -- words, not an arrow, because the PDF's
  built-in Helvetica cannot draw one. For a Draft this is today's pick; a Ready or Archived run
  shows `test_versions_used`, the versions its sheet was written with (the page checks live).
  Under it, a Ready or Archived run with saved versions says so (decision 11; plan review of
  562b2e2: after a newer match is synced, the page's errors are those of the newer version):

  ```
  The checks below use today's synced profiles. This run's Sample Sheet was written with the test versions above.
  ```
- **Validation report** (pre-generated at Mark Ready): the JSON gains `"tests": [{"test",
  "asked", "version", "file"}]` (`services/validation_report.py:58-123`); the PDF's run lines
  (`_run_info`, 309-320) gain a `Tests` line. Its value is set as a paragraph (escaped), so it
  wraps inside its 12 cm column: a plain string does not wrap, and three tests with usual file
  names measure 18.5 cm (review of plan 68fc2c0).
- **The sample table** of a Ready or Archived run (§2).

## §4 Tests

Written first, each seen failing for its reason before the code.

- The sample's rule: every allowed form (`1`, `1.2`, `1.2.3`, `0`, `10.0.1`, spaces around,
  `999999999.999999999.999999999` = 29 characters) and refused ones (`v1`, `1.x`, `1.2.3.4`,
  `01`, `1.`, `.1`, `1..2`, `-1`, a 10-digit number, a 4,301-digit number, a value that is not
  text), at construction and on assignment; a refused 4,301-digit value raises the rule's
  `ValueError` and its message shows 40 characters.
- The sync rule: the nine measured values above (only `1.0.0` passes); a 10-digit and a
  4,301-digit number refused; a pair of files with one test and version: both refused and
  logged; each kind of refused test file (a bad `Version`, a pair, YAML that cannot be read, an
  empty file, a file with no download link, a sub-folder that cannot be listed, a refused file in
  a sub-folder) stores no test profile, keeps the stored ones
  (so `1` still gives the version it gave before), and ends with status `error` and the message;
  application profiles still stored; the instrument message unchanged; the destructive-replace
  guard still stops a sync that would leave no test profiles.
- Matching: `1`, `1.2`, `1.2.3` against a set with gaps; 1.10.0 over 1.9.0; numbers, not text
  (`1` against 1.0.0, 10.0.0, 11.0.0; `1.2` against 1.2.0, 1.20.0); no match; stored records
  with bad versions skipped, a stored 4,301-digit version included (no exception); the
  stored-twice reason.
- Each input: paste with a header column, the default box, a bad cell (whole paste refused,
  rows named), a 302-character cell `1000…0v` refused (it passes once cut to 256), no
  `version`-only column, a row with a version and no test (refused; the preview blocks it), the
  box's version not given to a row without a test; "Set test" (each of the five cases, and a
  300-character box refused, not shortened); both fix boxes (the per-test box never changes a
  test; each box from an out-of-date page refused with 409 and nothing saved); add-sample; LIMS
  (alias, mapped name, a `null` mapped field passed over, iGene dict with no version, a version
  with no test refused, and each JSON type: `"1.10"` kept, `2` → `"2"`, `0` → `"0"`, `1.10`
  refused, `true` refused, `-1` refused, `null` no version, a list refused, a 300-character text
  refused, not shortened).
- Mark Ready: refused for a missing version, for no match, for stored twice; passes with each
  form of text; saves `test_versions_used`; READY→DRAFT clears it; a sync between the checks and
  the writing that brings a newer match → 409, nothing saved; two samples asking for `WGS 1`
  and `WGS 2` in one run resolve to two profiles, each sample written with its own version's
  sections, and the application check reports a problem of one version for that version's
  samples only.
- The validation page, the JSON report and the PDF show the tests; the PDF's Tests line wraps
  inside its column.
- The storage-order bug: two `WGS` files stored in both orders give the same, newest match.
- From the plan review of 562b2e2:
  - the sync reads `Wgs_1.3.YAML` and `Rna.Yml`, and still skips a `README.md`;
  - the config-sync page: `—` before the first sync; after a refused sync, the last-sync line
    with `(error)` and the message, in the red box; after a good one, `(success)`, not red; a
    manual sync's result red when it refused files, green when it succeeded;
  - the paste: a row taking the picked test with no version refused, nothing added, and the
    preview offers no Add; a row with its own version may take the picked test;
  - the LIMS: a sample ID `23.10`, `true` and `false` refused; a test `1.10` and `true` refused;
    a whole-number sample ID and test kept as today;
  - the application check resolves the whole version text: with `1.0.0` naming a profile that
    is not stored and `1.1.0` clean, `1.0` is reported and `1.1` is not, and the reverse;
  - the Ready table with two version texts of one test (`1`, `2`): each sample shows its own
    exact version;
  - Mark Ready's audit event holds the test versions;
  - the Ready page's note: shown on a Ready and an Archived run, not on a Draft.
- Browser: the bulk panel's version box and Clear; the paste box; the fix boxes.
- Break tests: switch off each rule in turn; the tests named for it must turn red.

## §5 Docs

`docs/user-guide/samples.rst` (version column, boxes, fix boxes, the sample table),
`docs/user-guide/validation.rst` (the two errors, the Tests line), `docs/admin-guide/profiles.rst`
(`Version` three whole numbers; one file per test and version; a refused test file keeps the
stored test profiles; how a sample's text picks one),
`docs/admin-guide/sample-api.rst` (the Test version field), `docs/architecture/data-models.rst`
and `docs/architecture/services.rst` (the new field, `resolve_test`).

From the plan review of 562b2e2: `profiles.rst` (a `.YAML` ending in any case; the config-sync
page's last-sync line, red on an error); `validation.rst` (the Ready page's note);
`audit-trail.rst` (a Mark Ready's `run.status.changed` holds `test_versions`);
`sample-api.rst` (a sample ID or test sent as a decimal number or `true`/`false` is refused);
`samples.rst` (a picked test needs a version; a spreadsheet can turn `1.10` into `1.1`, so
format the `test_version` column as text and check the preview's Version column).

Doc pictures are made again. A picture may change only where it shows a part this design
changes: the paste form and preview, the bulk panel, the run page's fix boxes, the sample
table's Test cell (`WGS 1`), the validation page's Tests line, and the admin LIMS form's new
Test version field box (`admin/lims-settings.png`, taken of the whole form by
`tests/browser/test_docs_screenshots.py:1370-1374`), and the audit trail's Mark Ready events,
which now hold `test_versions` (`admin/audit-trail.png`; measured on the prototype: the
config-sync picture shows only the form, so the last-sync line does not change it). The plan
measures which pictures differ from main and names each one with the part that changed it;
any other difference is a defect. The doc-picture world gives its samples a version.

## §6 Rollout

SeqSetup has never been deployed. Drafts made before this change have samples without a
version; Mark Ready refuses them until a version is set, with the fix boxes on the run page.
Stored test profiles keep working until the next sync that refuses no test file, except any
whose version breaks the sync rule (not used, §1). A test file whose `Version` breaks the rule
makes the sync end with `error`, naming the file, until it is fixed. No migration.

## Later list (from this design)

- The API's JSON export carries no test or version (and `docs/architecture/services.rst` says
  the JSON export includes test IDs; it does not).
- An empty Apply in "Set test" clears the test, as it does today (now both test and version).
- Every other LIMS field (not the sample ID, test or version) goes through
  `str(val).strip()[:256] if val else ""` (`sample_api.py:652`): an index name sent as the JSON
  number `1.10` becomes `"1.1"`. A sample ID `0` still becomes empty and is refused as missing.
  Older than this design, not changed here.
- The LIMS worklist preview (`templates/wizard/_worklist_preview.html`) shows no version
  column (plan review of 68fc2c0).
- A refused sync keeps every stored test profile, also a version the lab removed on purpose in
  the same push; the message does not name the kept versions that are no longer in the
  repository (plan review of 562b2e2).
- A test file is named by its file name, not its path: two `Wgs.yaml` in two sub-folders read
  `WGS 1.2.0 is in Wgs.yaml and Wgs.yaml`; the refusal itself works (plan review of 562b2e2).
- `TestType` is matched exactly: a file with `TestType: Wgs` is another test than `WGS` (read
  in the code by the plan review of 562b2e2, not measured).
