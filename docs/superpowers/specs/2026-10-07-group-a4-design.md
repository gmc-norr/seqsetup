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
   **same test and the same version: both are refused.**
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

## §1 What is stored, and the rules

### The sample's version

- New field `Sample.test_version: str = ""` (`models/sample.py`), in `to_dict` / `from_dict`.
  Clone and templates copy it, since they copy samples through `to_dict` / `from_dict`
  (`services/run_builder.py:93-95`, `models/run_template.py:93, 142`).
- `Sample.__setattr__` enforces it on every assignment: `""`, or 1 to 3 whole numbers joined by
  dots, each `0` or without a leading zero (`^(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*)){0,2}\Z`).
  Surrounding spaces are stripped first. Anything else raises `ValueError`:

  ```
  A test version is 1, 2 or 3 whole numbers joined by dots, like 1, 1.2 or 1.2.3: 'v1'
  ```

  The text before the colon is the constant `TEST_VERSION_RULE` in `models/sample.py`, shared by
  every message below.

### The test profile's version, at sync

- `validate_test_profile_yaml` adds: `Version` must be three whole numbers joined by dots, each
  `0` or without a leading zero (`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z`).
  Otherwise:

  ```
  Field 'Version' must be three whole numbers joined by dots, like 1.0.0: '1.0'
  ```

  The PEP 440 check and the decimal-number message stay. A refused file is skipped and logged,
  as every refused profile file is today (the loop in `_fetch_profiles_recursive`,
  `github_sync.py:504-530`).
- After all test files are read, the sync looks for one test and version in more than one
  file. Every file of such a pair is refused: not stored, and logged as a warning:

  ```
  Test profiles refused: WGS 1.2.0 is in Wgs_a.yaml and Wgs_b.yaml. A test and version may be in one file only.
  ```

  The other test files sync. The guard against replacing stored profiles with nothing
  (`_guard_against_destructive_replace`) runs after this, unchanged.

### Finding a sample's test profile

- One function, `resolve_test(test_profile_repo, test, asked)` in a new module
  `services/test_versions.py`. It returns a `TestResolution`: the profile, or the reason there
  is none. Both the sheet plan and the application check call it. `get_by_test_type` is
  removed: no other source code calls it. Three test fakes implement it
  (`tests/unit/test_samplesheet_v2_exporter.py:635`,
  `tests/unit/test_check_broken_samplesheets.py:103`, `tests/unit/test_validation.py:823`) and
  move to the new method.
- The repository gains `list_by_test_type(test)`: every stored profile of that test, no logic
  (repositories hold none).
- Matching: `asked` split on dots gives 1 to 3 numbers; a stored version matches when its first
  numbers equal them. The newest match wins, compared as numbers (1.10.0 is newer than 1.9.0).
- Stored records whose `version` is not three whole numbers are not used. They can only come
  from a sync before this change; the next sync replaces every test profile.
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

### Paste and file (`services/sample_parser.py`, `routes/samples.py`, `services/paste_preview.py`)

- New header set `TEST_VERSION_HEADERS = {"test_version", "testversion", "test version",
  "test-version"}`. A column named only `version` is **not** read: a lab file may have another
  column of that name. `_is_header_row` and `_detect_column_mapping` learn the new set;
  `FIELD_LABELS` gains `"test_version": "Test version"`.
- Without a header row the columns stay `sample_id, test_id, index1, index2`
  (`_HEADERLESS_FIELDS`); a version needs a header.
- `ParsedSample.test_version`. A cell that breaks the rule refuses the whole paste, naming the
  rows, like a row without a sample ID:

  ```
  Row(s) 3, 5: the test version is not right. A test version is 1, 2 or 3 whole numbers joined by dots, like 1, 1.2 or 1.2.3.
  ```

- New box **"Version for rows without one"** (`default_test_version`) beside "Test for rows
  without one" (`templates/runs/_paste_form.html:29-39`). `_read_paste_input` checks it like the
  default test (`routes/samples.py:312-314`); a bad value is a 400:

  ```
  Version for rows without one: A test version is 1, 2 or 3 whole numbers joined by dots, like 1, 1.2 or 1.2.3.
  ```

  Rows that have a version keep it. Each new sample gets `ps.test_version or
  paste.default_version`, as the test does.
- The preview shows a Version column, marks a picked version "(picked)" as it marks a picked
  test, and adds the note `No test version. Check will ask for one.` to a row with a test and no
  version (when test profiles exist, as for the test note). The preview's Add form sends the
  box back like `default_test_id`.
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

### The sample table (`templates/wizard/_sample_row.html:41, 167`)

- The Test cell shows the test and the version text, for example `WGS 1`. On a Ready or
  Archived run it adds the saved exact version: `WGS 1 (1.2.3)` (§3).

### Adding one sample (`POST /runs/{run_id}/samples`)

- `add_sample` (`routes/samples.py:380-418`, no page posts to it today) reads `test_version`,
  with the same rules as "Set test". The audit event `sample.added` gains `test_version`.

### Lab system (`services/sample_api.py`, `routes/admin/sample_api.py`)

- `parse_api_samples` reads `test_version` (aliases `test_version`, `testversion`; a mapped
  field name goes first, as for every field). A value that breaks the rule refuses the whole
  worklist, naming the sample, shown as `Worklist import rejected: ...`:

  ```
  Sample 'S1' has a test version that is not right ('v1'). A test version is 1, 2 or 3 whole numbers joined by dots, like 1, 1.2 or 1.2.3.
  ```

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

### What Mark Ready saves

- The sheet plan records, for each test and version text it resolved: the test, the text asked,
  the exact version and the file (`source_file`). `ValidationResult.test_versions` carries this
  list, in the order of first appearance.
- New run field `SequencingRun.test_versions_used: list[dict]` (keys `test`, `asked`,
  `version`, `file`), in `to_dict` / `from_dict`. Mark Ready sets it from the validation result
  that let the run through, beside `samplesheet_v1_withheld` (`routes/runs.py:686-697`).
  READY→DRAFT clears it (`routes/runs.py:698-710`). It joins `_FINGERPRINT_IGNORED_KEYS`
  (`routes/runs.py:62-72`) and `RUN_DIFF_IGNORED_KEYS` (`services/run_diff.py:12-16`), as
  `samplesheet_v1_withheld` did.
- **The plan's fingerprint** (A3) keys each test entry by test and version text, and already
  holds the resolved profile's content, version included. If a sync brings a newer match between
  the checks and the writing, the fingerprints differ and Mark Ready answers 409
  (`profiles_changed_during_export`) and saves nothing, as for any other profile change.

### Where it is shown

- **Validation page** (`templates/validation/page.html`, under the approval bar): `Tests: WGS 1 →
  1.2.3 (Wgs.yaml) · RNA 2 → 2.0.1 (Rna.yaml)`. For a Draft this is today's pick.
- **Validation report** (pre-generated at Mark Ready): the JSON gains `"tests": [{"test",
  "asked", "version", "file"}]` (`services/validation_report.py:58-123`); the PDF's run lines
  (`_run_info`, 309-320) gain a `Tests` line.
- **The sample table** of a Ready or Archived run (§2).

## §4 Tests

Written first, each seen failing for its reason before the code.

- The sample's rule: every allowed form (`1`, `1.2`, `1.2.3`, `0`, `10.0.1`, spaces around) and
  refused ones (`v1`, `1.x`, `1.2.3.4`, `01`, `1.`, `.1`, `1..2`, `-1`), at construction and on
  assignment.
- The sync rule: the nine measured values above (only `1.0.0` passes); a pair of files with one
  test and version: both refused, logged, the rest stored; the destructive-replace guard still
  stops a sync that would leave no test profiles.
- Matching: `1`, `1.2`, `1.2.3` against a set with gaps; 1.10.0 over 1.9.0; no match; stored
  records with bad versions skipped; the stored-twice reason.
- Each input: paste with a header column, the default box, a bad cell (whole paste refused,
  rows named), no `version`-only column; "Set test" (each of the five cases); both fix boxes
  (the per-test box never changes a test); add-sample; LIMS (alias, mapped name, bad value
  refused, iGene dict with no version).
- Mark Ready: refused for a missing version, for no match, for stored twice; passes with each
  form of text; saves `test_versions_used`; READY→DRAFT clears it; a sync between the checks and
  the writing that brings a newer match → 409, nothing saved; two samples asking for `WGS 1`
  and `WGS 2` in one run resolve to two profiles.
- The validation page, the JSON report and the PDF show the tests.
- The storage-order bug: two `WGS` files stored in both orders give the same, newest match.
- Browser: the bulk panel's version box and Clear; the paste box; the fix boxes.
- Break tests: switch off each rule in turn; the tests named for it must turn red.

## §5 Docs

`docs/user-guide/samples.rst` (version column, boxes, fix boxes, the sample table),
`docs/user-guide/validation.rst` (the two errors, the Tests line), `docs/admin-guide/profiles.rst`
(`Version` three whole numbers; one file per test and version; how a sample's text picks one),
`docs/admin-guide/sample-api.rst` (the Test version field), `docs/architecture/data-models.rst`
and `docs/architecture/services.rst` (the new field, `resolve_test`).

Doc pictures are made again. A picture may change only where it shows a part this design
changes: the paste form and preview, the bulk panel, the run page's fix boxes, the sample
table's Test cell (`WGS 1`), and the validation page's Tests line. The plan measures which
pictures differ from main and names each one with the part that changed it; any other
difference is a defect. The doc-picture world gives its samples a version.

## §6 Rollout

SeqSetup has never been deployed. Drafts made before this change have samples without a
version; Mark Ready refuses them until a version is set, with the fix boxes on the run page.
Stored test profiles keep working until the next sync, except any whose version is not three
whole numbers (not used, §1). No migration.

## Later list (from this design)

- The API's JSON export carries no test or version.
- An empty Apply in "Set test" clears the test, as it does today (now both test and version).
