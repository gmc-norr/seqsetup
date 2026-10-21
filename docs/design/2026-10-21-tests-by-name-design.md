# A sample's test names its test profile by TestName

## The problem

A sample's test is matched to a test profile's **TestType**
(`services/versioned_tests.resolve_test`, which asks
`TestProfileRepository.list_by_test_type`). Two test profiles with one
TestType and one version could not be told apart, so the sync and
`check-settings` refuse them both (`input_rules/profiles.repeated_test_versions`):
a sample could have got either.

The lab's settings have exactly that: `WGSRareDisease_1` and
`WGSRareDiseaseResearch_1` are both `TestType: WGS`, version 1.0.0 -- one
sequencing test, two downstream pipelines (the clinical and the research
nf-core/raredisease). `check-settings` on the lab's folder says *"WGS 1.0.0 is
in test_profiles/WGSRareDiseaseResearch_1.yaml and
test_profiles/WGSRareDisease_1.yaml"*, and the sync would store no test
profile at all.

## The user's word (2026-10-21)

- Several test profiles may share a TestType and a version.
- The LIMS (iGene) sends the **TestName** as a sample's test, such as
  `WGSRareDisease_1`.

## The decision

A sample's test names a test profile by its **TestName**, matched exactly,
letter case included, as TestType was. The version rule does not change:
`1` is the newest synced 1.x.x of that TestName, `1.2` the newest 1.2.x,
`1.2.3` exactly it. One file per TestName and version.

TestType stays a required key of a test profile file, so no settings file
changes. It is shown as a label beside the name, and never picks a profile.

## What changes

- **Finding a sample's test profile**: `resolve_test` asks the repository for
  the profiles of one TestName (`list_by_test_name`); its messages name the
  test the sample gives, as before.
- **The repeat rules** (sync and `check-settings`, one function each in
  `input_rules/profiles.py`): `repeated_test_versions` refuses a TestName and
  version given by two files; `differing_only_in_capitals` refuses two
  TestNames that differ only in letter case. Two files with one TestType and
  version but two TestNames are both stored.
- **What a sync keeps**: `_kept_test_versions_not_read` in
  `services/github_sync.py` compares TestName and version.
- **The pick-lists** -- the paste form's test, the bulk **Test ID** panel, the
  Check page's fix box and the versions hint -- offer each TestName once, with
  its versions; the value a pick saves is the TestName, shown as
  "TestName (TestType)" when the two differ. `offered_tests` groups by TestName.
- **The tests a page knows** (`routes/samples._test_types`, the paste preview's
  "unknown test" note, the default test of a paste) are the TestNames.
- **The Profiles and Config Sync pages** list test profiles by TestName, with
  their TestType.
- **Docs**: the user guide's samples page, the admin guide's test versions,
  and the lines of `CLAUDE.md` that say a test is matched by TestType.

## What does not change

- **The paste and LIMS readers.** A sample's test is the text its test column
  or the worklist's TestID gives, as before
  (`tests/unit/test_paste_and_worklist_outcomes.py` keeps every line). A
  column named `test_type` still fills it; the text is now looked up as a
  TestName.
- **The Sample Sheet.** The test profile a sample gets still decides its
  application profiles. The 78-sheet corpus uses SeqSetup's `Wgs.yaml`, whose
  TestType and TestName are both `WGS`, so every sheet stays the same.
- **The JSON export** writes the sample's test text, as before.
- **Stored runs.** A sample keeps its text. One whose text was a TestType that
  is no TestName gets the Check's existing *"No test profile found"* error
  until its test is set again; Ready and Archived runs keep their files.
  SeqSetup is not deployed yet, so no stored data is converted.
- **The mock LIMS.** Its `WGS` still names SeqSetup's example test.

## How it is proved

- Tests first: two profiles of one TestType and version with two TestNames
  are both stored by a sync and both pass `check-settings`; a sample naming
  each gets its own profile's application profiles in the sheet; one TestName
  and version in two files, and two TestNames differing only in capitals, are
  refused; a sample that gives a TestType that is no TestName is not matched.
- The lab's folder (`gmc-norr/config-files`, `test-profile-config/`, with the
  version fixes of 2026-10-21) passes `check-settings`.
- The full check: the 78 sheets unchanged, break rows on every changed rule,
  then a fresh review.
