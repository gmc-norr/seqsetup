# Group A3: the Sample Sheet carries what Mark Ready checked — design

## Why

Findings from the 2026-10-03 project review, each re-run on `main` at `9be63ce` (after
groups A1 and A2) and still reproducing, plus three found while designing this change:

1. **A section can be written twice** (review S-1, DI-08). The v2 writer keys a section by
   the reference's profile name and version *text*
   (`services/samplesheet_v2_exporter.py:534`), and names it by the profile's
   `ApplicationName`. Two tests whose profiles share an `ApplicationName` — the shipped
   `DragenEnrichmentIdtGermline` and `DragenEnrichmentIdtSomatic`, or two BCLConvert
   profiles, or one profile referenced as `1.0` by one test and `~=1.0` by another — give
   two `[X_Settings]` and two `[X_Data]` sections. Mark Ready: 0 errors. Re-check:
   `duplicated sections: {'[DragenEnrichment_Settings]': 2, '[DragenEnrichment_Data]': 2}`.
2. **A patient can be left out of `[BCLConvert_Data]`** (review S-2 A, DI-08). A test whose
   profile list has no BCLConvert profile puts its samples in the DRAGEN sections only; their
   reads go to Undetermined. Re-check: `PAT2 in BCLConvert_Data: False | PAT2 in
   DragenGermline_Data: True`, `error_count: 0 warnings: 0`.
3. **A profile can drop or repeat a column** (review S-2 B, C). `Translate: {IndexI5: Index}`
   (a typo for `Index2`) passes the sync and writes the header `Sample_ID,Lane,Index,Index`:
   the i7 twice, no i5. A BCLConvert profile without `Lane` writes two samples that share a
   barcode in lanes 1 and 2 as two identical rows with no lane. Both: 0 errors.
4. **A sync during Mark Ready can make a Ready sheet with no samples** (review DI-07). The
   writer skips a test or profile it cannot find (`continue` at
   `samplesheet_v2_exporter.py:530-531` and `:540-541`), and the sync deletes all profiles
   before saving the new ones (`services/github_sync.py:276-280`). Re-check: `WINDOW status:
   ready`, the sheet holds only `[Header]` and `[Reads]` before the Cloud sections.
5. **The collision check and the sheet can use different mismatch numbers** (found while
   designing). The check uses the sample's number, else the run's
   (`services/index_collision_validator.py:37-60`; the warning at
   `services/validation.py:1018-1023` does the same). The sheet gives BCL Convert the
   sample's number, else the profile's Data default, else the profile's Settings value, else
   BCL Convert's default — and the run's number is never written on this path. A profile
   that says 2 lets two samples be checked at 1 and demultiplexed at 2. Illumina says DRAGEN
   "will detect all conflicts between samples at the beginning of the conversion run", so
   the likely outcome is a conversion that stops after the run; a reader that does not
   check would mix the two samples' reads. Either way Mark Ready passed a sheet it did not
   check.
6. **The v1 sheet drops per-sample settings** (review S-5). MiSeq and NovaSeq 6000 runs also
   get a v1 sheet, which writes only the run's mismatch numbers
   (`services/samplesheet_v1_exporter.py:94-100`) and no OverrideCycles. Re-check: samples
   with mismatches 0/0 get `BarcodeMismatchesIndex1,1` in v1; `v1 has OverrideCycles:
   False` for a UMI kit. Mark Ready: 0 errors. A v1 reader then demultiplexes with settings
   the checks did not use: UMI bases stay in the reads, and a pair checked at 0 mismatches
   is demultiplexed at 1.
7. **An index can be longer or shorter than the cycles read for it** (review S-8, and
   Illumina's rule below). A typed `Y151;I6N4;I10;Y151` makes the sheet read 6 i7 bases
   while the checks compare all 10; re-check: `i7 bases the sheet reads: ['ACGTAC',
   'ACGTAC']`, 0 collisions. A kit whose index cycles are fewer than its index's bases writes
   the same shape. Illumina says the index must have as many bases as the cycles read.
   `services/validation.py:887-895` calls that shape a valid sheet; Illumina says it is not.
8. **Ten safety pieces have no test** (review H-1, H-3). Each was switched off in its own
   copy of `src/` and the whole server suite run (3135 tests at `9be63ce`): the i7 and i5
   index-length checks, the mixed-indexing check, the three application-profile checks
   (application not on the instrument, version not on the instrument, two versions of one
   application), the i7 dark-start check, and the validation-cache clears after a sync
   (`github_sync.py:322`) and after an index kit is saved or deleted
   (`routes/indexes.py:229`, `:284`) — all ten: every test still passed. Only the i5
   dark-start check is caught (by A2's tests). The sync's clear matters: without it, a
   validation after a sync that removed a profile returns the old pass. The two kit clears
   have no effect on today's checks (no check reads index kits); the hard rules require them.

## What Illumina says

From the DRAGEN v4.3 product guide, BCL conversion
(<https://help.dragen.illumina.com/dragen-v4.3/product-guide/dragen-v4.3/bcl-conversion>):

- "DRAGEN/bcl-convert 4.1 and later supports the following settings as columns in the
  [BCLConvert_Data] section, allowing them to be specified differently for each sample:
  OverrideCycles, BarcodeMismatchesIndex1, BarcodeMismatchesIndex2, AdapterRead1,
  AdapterRead2, AdapterBehavior, AdapterStringency."
- "This feature is only supported on version two (v2) sample sheets, and no setting can be
  specified both globally and per-sample. Specifying OverrideCycles differently per-sample
  allows mixing of different pools into the same lane, but must still obey barcode mismatch
  constraints for all cycles that are used for demultiplexing by any sample in that lane.
  DRAGEN software will detect all conflicts between samples at the beginning of the
  conversion run, even between different pools."
- For the `index` column: "Length of string must match number of first index cycles in
  RunInfo.xml or number specified in OverrideCycles." The `index2` column says the same of
  the second index cycles.
- `BarcodeMismatchesIndex1` and `BarcodeMismatchesIndex2`: default 1, values 0, 1 or 2 (also
  on the BCL Convert Sample Sheet page,
  <https://support-docs.illumina.com/SW/BCL_Convert/Content/SW/BCLConvert/SampleSheets_swBCL.htm>).

What BCL Convert or DRAGEN do with a repeated section was not measured. After this change
SeqSetup never writes one.

## Decisions (the user's, 2026-10-05)

1. **One section per application.** Profiles for the same application in one run share
   one section when their Settings and their columns match; each sample's row keeps its own
   profile's values. When they differ, Mark Ready refuses and names both profiles.
2. **Every sample is in `[BCLConvert_Data]` exactly once (once per lane), and the sheet
   carries every value the checks used.** Missing BCLConvert profile, two profiles for one
   application in one test, a repeated column, a setting in two places, or a column a sample
   needs: Mark Ready refuses.
3. **The collision check uses the mismatch number the sheet gives BCL Convert** (Why 5).
4. **The writer checks again and stops** when a profile is missing or a rule above fails, so
   Mark Ready fails rather than writing a sheet with patients missing.
5. **No v1 sheet when it cannot carry the run's settings.** Mark Ready still works and the v2
   sheet is made. The validation page warns before Mark Ready; after Ready the v1 download,
   the API and the run page say why. Mark Ready does not ask an extra question.
6. **An index must have exactly as many bases as the cycles its OverrideCycles reads for
   it**, or Mark Ready refuses. This replaces group A2's narrower refusal of a shortened i5 on
   reverse-reading workflows (`i5_shortened_on_reversed_read`) and closes the later-list item
   about a 10-base i5 on an 8-cycle Index 2 read. Writing a shortened index is not offered.
7. **Tests for the ten untested pieces**, each proven by switching the piece off.
8. **Test versions (review S-12) are group A4**, right after A3; nothing here changes how a
   test profile is looked up.

## 1. The sheet plan: one resolver for the writer and the checks

A new module, `services/sheet_plan.py`, works out the application sections of a run's v2
sheet from the run and the two profile repositories. Mark Ready's checks and the v2 writer
both use it, so they cannot disagree about which samples go where.

**What it resolves.** For each sample with a test, in run order: the test profile (by test
type, as today), then each application profile the test references (by name and version
constraint, as today). It records, in order of first appearance:

- one **section** per `ApplicationName`, holding the distinct resolved profiles (a profile is
  identified by its name and its resolved version, not by the constraint text) and, for each
  profile, its samples — grouped by test in order of the test's first sample, each test's
  samples in run order (today's order);
- for each sample, its **BCLConvert profile**;
- the **problems** below.

**What it refuses** (each a problem; categories and texts under *Messages, exactly*):

1. A test profile or application profile that cannot be found. The checks already report
   these (`test_profile_not_found`, `profile_not_found` in
   `services/application_profile_validator.py`); the plan does not report them a second
   time, but the writer stops on them.
2. A test whose profiles include no BCLConvert profile (`ApplicationName: BCLConvert`).
3. A test with two or more profiles for one application.
4. Two profiles in one section whose Settings lines or column headers differ. The Settings
   lines compared are the ones the writer would write (name and written cell); the columns
   are the header after `Translate`, in order. Data defaults may differ: they are per row.
5. A profile whose data section writes one column name twice (after `Translate`), in any
   application.
6. In the BCLConvert section, a name both written in `[BCLConvert_Settings]` — from the
   profile's Settings or from the run's settings the writer adds (`NoLaneSplitting`,
   `CreateFastqForIndexReads`, `AdapterBehavior`) — and a column of `[BCLConvert_Data]`.
7. A sample whose BCLConvert profile has no column for a value the sample needs:
   - `Index` when the sample has an i7; `Index2` when it has an i5;
   - `Lane` when the sample is on some lanes only (its lane list is not empty and is not
     every lane of the flow cell);
   - `OverrideCycles` when its OverrideCycles (typed, else computed) is not the run's full
     reads written plainly (for example `Y151;I10;I10;Y151`);
   - `BarcodeMismatchesIndex1` / `BarcodeMismatchesIndex2` when the sample has its own number
     and the number BCL Convert would use without the column (the profile's Settings value,
     else 1) is different.

**Writing.** The writer writes one `[X_Settings]` and one `[X_Data]` per section, in order:
the Settings lines once (from the first profile; they are the same in every profile of the
section) with the run's BCL Convert settings added as today, one header, then the rows. Each
row is filled from its own profile (its `Translate` mapping and Data defaults), exactly as
`_write_application_profile_section` fills it today. A run whose tests share no application
gets the same sheet as today, byte for byte.

**Where it runs.**

- **Mark Ready's checks** (`ValidationService.validate_run`, when both repositories are
  given): the plan's problems 2–7 become ERROR configuration errors, and the collision checks
  use the plan's mismatch numbers (§2). Without the repositories (the fallback path, and
  checks run without profiles) nothing changes.
- **The v2 writer** (`SampleSheetV2Exporter.export` with both repositories): it builds the
  plan first and raises `ValueError` with the first problem's text if there is any problem
  (1–7), before writing anything. At Mark Ready that is today's "Failed to generate exports"
  refusal, so the run stays a Draft; the next Mark Ready shows the problem as an error.
- **The sync** (`services/profile_validator.py`, `validate_application_profile_yaml`): a
  profile file that writes a column twice (problem 5), or a BCLConvert profile with a name
  both in its Settings and among its columns (problem 6, profile part), is refused like any
  other bad profile file.

## 2. The mismatch numbers the collision check uses

On the profile path (both repositories given), for a sample in the BCLConvert section, the
number for index *n* is the one the sheet gives BCL Convert for that sample:

1. the cell the writer writes in the `BarcodeMismatchesIndexN` column, when the profile has
   that column and the cell is 0, 1 or 2 (the sample's own number, else the profile's Data
   default);
2. else the profile's Settings `BarcodeMismatchesIndexN`, when set (only possible without the
   column — §1 problem 6);
3. else 1, BCL Convert's default.

The pair rule is unchanged: the larger of the two samples' numbers. The collision errors,
the duplicate-index check and the "mismatch threshold" warning all use these numbers.
Without the repositories, the numbers are today's: the sample's, else the run's.

## 3. The v1 sheet (MiSeq, NovaSeq 6000)

A v1 sheet holds only the run's settings. `SampleSheetV1Exporter` gains a check that lists
why a run's v1 sheet cannot be made; the reasons are, for any sample:

- its own mismatch number for the i7 or the i5, different from the run's;
- its OverrideCycles (typed, else computed, expanded) differs from the one computed from its
  index lengths alone — no kit index cycles, no read patterns. This covers a typed value,
  UMI reads and kit index cycles.

When there is a reason:

- **The validation page** shows a WARNING, `no_v1_sheet`, on instruments that have a v1
  sheet. It does not stop Mark Ready.
- **Mark Ready** makes the v2 sheet, the JSON and the reports as today and stores no v1
  sheet.
- **The run page's export panel** shows the reason where the v1 download button would be.
- **The v1 download** (`/runs/{run_id}/export/samplesheet-v1`) answers 409 with the reason
  and never makes a sheet on the spot (`routes/export.py:106` makes one today when none is
  stored).
- **The API** (`/api/runs/{run_id}/samplesheet-v1`) answers 404, as today when there is no
  stored sheet, with the reason as its detail.

Otherwise the v1 sheet is unchanged.

## 4. An index has as many bases as the cycles read

For each sample and each index read the run performs, when the sample has that index: the
number of `I` cycles in that read's part of the sample's OverrideCycles (typed, else
computed) must equal the index's length. Otherwise Mark Ready refuses with
`index_length_differs_from_override_cycles`. This catches:

- kit index cycles fewer than the index's bases (a 10-base index with index cycles 8: `I8`);
- a typed value that reads fewer (`I6N4` on a 10-base i7) or more (`I10` on an 8-base i7);
- a typed value that reads none of an index the sample has (`N10` where its i7 is read).

Reported once: a sample whose OverrideCycles does not fit the run is reported by
`_validate_override_cycles_match_run`, and an index longer than the run's index read by
`index_exceeds_cycles`; this check skips both. Group A2's `_validate_shortened_i5`
(`services/validation.py:534-577`) and its category `i5_shortened_on_reversed_read` are
removed: every case it refused is refused by this check, on every instrument. The docstring
at `services/validation.py:887-895` that calls the shortened shape valid is corrected.

The comparisons in the collision and duplicate checks are unchanged: in a run that passes
this check, the bases they compare are the bases read.

## 5. Tests for the ten untested pieces

For each piece below, a test where it fires and Mark Ready refuses (or, for a cache clear,
where its effect shows), proven by switching the piece off and seeing that test fail:

- the i7 index-length check and the i5 index-length check (`index_length_mismatch`);
- the mixed-indexing check (`mixed_indexing`);
- application not on the instrument (`app_not_available`), version not on the instrument
  (`version_not_available`), two versions of one application (`version_conflict`);
- the i7 dark-start check;
- the sync's cache clear: a real sync, its downloads stubbed, that removes a test's profile;
  the next validation of a run on that test reports `profile_not_found`;
- the index kit save and delete clears: each bumps the validation cache's version.

## Messages, exactly

`<ids>` is the first five sample IDs, then ", and N more"; profiles are written `Name
Version` (for example `BCLConvertNextera 1.0.0`).

- `test_without_bclconvert_profile`: "Test '<test>' has no BCLConvert profile, so its <n>
  sample(s) would not be demultiplexed: <ids>. Add one BCLConvert profile to the test
  profile."
- `test_with_two_profiles_for_one_application`: "Test '<test>' uses <k> profiles for
  <application>: <profiles>. A test may use one profile per application."
- `profiles_differ_in_one_section`: "<application>: profiles <profile 1> (test <test 1>) and
  <profile 2> (test <test 2>) have different <Settings | columns | Settings and columns>,
  and a Sample Sheet has one [<application>_Settings] and one [<application>_Data] section.
  Put these tests in separate runs, or give the profiles the same Settings and columns."
- `repeated_column`: "Profile <profile> writes the column <column> more than once (from
  <fields>). Each column may appear once; check its DataFields and Translate."
- `setting_in_two_places`: "<name> would be set both in [BCLConvert_Settings] (<source>)
  and as a column in [BCLConvert_Data] (profile <profile>). BCL Convert allows a setting in
  one place only." — `<source>` is "profile <profile>" or "the run's setting".
- `bclconvert_column_missing`: "<n> sample(s) need a <column> column that BCLConvert profile
  <profile> does not have, because <reason>: <ids>. Add <column> to the profile's
  DataFields." — `<reason>`: "they have an i7", "they have an i5", "they are on some lanes
  only", "their OverrideCycles is not the run's full reads (<full reads>)", "they have
  their own i7 mismatch number", "they have their own i5 mismatch number".
- `index_length_differs_from_override_cycles`: "<n> sample(s) have an index whose length
  differs from the index cycles their OverrideCycles reads: <details>. BCL Convert needs each
  index to have as many bases as the cycles read for it. Use an index of that length, or
  change the OverrideCycles or the kit's index cycles." — `<details>`: the first five as
  "<id> (i7: <bases> bases, <cycles> read)" or "(i5: …)", then ", and N more".
- `no_v1_sheet` (WARNING): "No v1 sheet will be made for this run, because a v1 sheet holds
  only the run's settings: <reasons>. The v2 sheet is made as usual." After Ready (export
  panel, download, API): "No v1 sheet for this run, because a v1 sheet holds only the run's
  settings: <reasons>." — `<reasons>`, joined by "; ": "<ids> have their own mismatch
  numbers (the run's are i7 <m1>, i5 <m2>)" and "<ids> have OverrideCycles a v1 sheet cannot
  hold".
- Sync (profile file refused): "The data section writes the column '<column>' more than
  once: from <fields>. Each column may appear once (check DataFields and Translate)." and
  "'<name>' is both in Settings and a data column. BCL Convert allows a setting in one place
  only."

The validation page's labels: "No BCL Convert profile", "Two profiles for one
application", "Profiles differ", "Repeated column", "Setting in two places", "Missing
column", "Index length differs", "No v1 sheet".

## Docs

- `docs/admin-guide/profiles.rst`: one section per application and when profiles share it;
  one BCLConvert profile per test, one profile per application per test; the columns a
  BCLConvert profile needs and why; repeated columns and settings in two places refused at
  sync and at Mark Ready.
- `docs/user-guide/export.rst`: one section per application; when there is no v1 sheet and
  where the reason shows; the mismatch numbers the check uses.
- `docs/user-guide/override-cycles.rst`: the index-length rule replaces the A2 paragraph on a
  shortened i5.
- `docs/user-guide/index-assignment.rst`: kit index cycles must equal the index's length,
  or Mark Ready refuses.
- `docs/user-guide/validation.rst`: the new checks and the v1 warning.
- `docs/architecture/services.rst` and `docs/architecture/samplesheet-format.rst`: the sheet
  plan, and sections keyed by application.

## Tests

- **Sheet plan** (unit): each problem 1–7 found with its category and text, and a run
  without problems resolving to today's sections; sections keyed by resolved profile (`1.0`
  and `~=1.0` give one section); merged rows each filled from their own profile; the shipped
  germline and somatic enrichment profiles share one `[DragenEnrichment_Data]`.
- **Writer**: stops on each problem; a profile deleted between the checks and the writing
  (the DI-07 timing) makes Mark Ready fail and the run stays a Draft; today's sheets
  byte-identical for every built-in instrument with the shipped profiles.
- **Mismatch numbers**: a profile whose Data default is 2 makes a distance-3 pair collide;
  Settings-only and no-value cases use the Settings number and 1.
- **v1**: each reason found; Mark Ready stores no v1 sheet and still goes Ready; the warning,
  the export panel, the 409 download (no sheet made on the spot) and the API 404 detail.
- **Index length**: kit index cycles, typed fewer, typed more and typed none, refused on a
  forward and a reverse-reading instrument; the A2 shortened-i5 cases refused with the new
  category; reported once alongside `index_exceeds_cycles` and an OverrideCycles that does
  not fit the run.
- **Sync**: a repeated column and a setting in two places refuse the file.
- **The ten pieces** (§5), each proven by switching it off.
- **Break tests**: one mutation per new rule and per new test of §5, each turning its tests
  red.

## Rollout

SeqSetup has never been deployed, so no stored data needs moving. Runs already Ready keep
their stored sheets. A Draft that mixes profiles that differ, uses a test without a
BCLConvert profile, or has an index whose length differs from its cycles is refused at Mark
Ready with what to change. A MiSeq or NovaSeq 6000 run whose samples have their own settings
goes Ready without a v1 sheet.

## Not in this change

- Test versions and duplicate test types (review S-12): group A4.
- Writing an index shortened to the cycles read.
- The "both places" rule for DRAGEN sections (Illumina states it for BCL Convert); the
  i5 IndexOrientation setting in a profile (A2's E-1, later list).
- A sync that *replaces* a profile with another of a valid shape between the checks and the
  writing: the writer re-checks the plan's rules, not the instrument checks
  (application and version on the instrument).
- Review S-6 (the collision rule sums the two distances), S-9 (kit adapters), S-10 (JSON
  export), S-11 (profile sample columns); a UI for the run's mismatch numbers.
