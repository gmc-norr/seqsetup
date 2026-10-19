# Profiles shared with other tools, and the run's UUID in RunDescription

## The problem

The lab keeps its profiles in one repository that SeqSetup and other tools
read: `test-profile-config/` in `gmc-norr/config-files`. Each test profile
there lists two kinds of applications:

```yaml
TestApplicationProfiles:
  OnInstrument:
    - ApplicationProfileName: BCLConvertNextera
      ApplicationProfileVersion: 1
  DownstreamAnalysis:
    - ApplicationProfileName: NfCoreRareDisease
      ApplicationProfileVersion: 1
      DependsOn: BCLConvertNextera
```

`OnInstrument` lists what goes in the Sample Sheet. `DownstreamAnalysis` lists
the pipelines another tool runs after the sequencer (cleve, with the lab's
automation; it reads the same files and needs nothing from SeqSetup). The
application profile folder holds both kinds: the instrument's (DRAGEN, BCL
Convert) and the pipelines' (`ApplicationType: nextflow` or `snakemake`,
`ApplicationName: nf-core/raredisease`).

SeqSetup cannot read that repository today:

- A test profile must list its profiles under a flat `ApplicationProfiles:`;
  `TestApplicationProfiles` is an unknown key, so every test file is refused.
- A pipeline profile is refused (`ApplicationName` may hold no `/`), and one
  refused profile file stops the whole profile sync.
- Had it been read, SeqSetup would write every profile a test names into the
  Sample Sheet as its own `[Name_Settings]` / `[Name_Data]` pair, and the Check
  page would refuse a pipeline as "not available on" the instrument.

Separately, the run's link to SeqSetup does not survive the NovaSeq X. SeqSetup
writes the run's id, a UUID, as `Custom_UUID` in `[Header]`. The lab found
(cleve issue #27) that the NovaSeq X Plus accepts custom keys and sections in
an uploaded sheet but leaves them out of the sheet it runs with, so the UUID
never reaches the run folder. cleve reads the UUID from `RunDescription`, a
standard key, instead.

## The decision

The user's, 2026-10-19:

1. SeqSetup reads the lab's test profile layout, and only that one.
2. SeqSetup reads the one shared application profile folder and **skips** the
   profiles that are not for the instrument, by their type.
3. The old "external profile" feature ends: a profile whose `ApplicationType`
   is not `Dragen` (`External`, `Cloud`, or anything else) no longer writes a
   section into the Sample Sheet. The sheet holds only what the instrument
   handles. SeqSetup is not deployed, so no lab uses it.
4. The v2 Sample Sheet writes the run's UUID as `RunDescription` too, and keeps
   `Custom_UUID`.

The pipelines do not pass through SeqSetup: nothing about them goes into the
JSON export or the API.

## What changes

**Test profiles.** The list moves under `TestApplicationProfiles`:

- `OnInstrument` is required and lists at least one profile, each with exactly
  `ApplicationProfileName` and `ApplicationProfileVersion`, checked as the old
  list was (a PEP 440 version or specifier). It is the list SeqSetup uses:
  stored as the test's application profiles, as before, so nothing after the
  sync changes.
- `DownstreamAnalysis` is optional. SeqSetup checks only that it is a list of
  maps whose keys are plain names (letters, digits, `_`, `-`) and whose values
  are text (at most 4096 characters), whole numbers or `true`/`false`; it does
  not store, resolve or use
  them. That keeps the file readable without holding another tool's part to
  SeqSetup's version rules.
- Any other key under `TestApplicationProfiles` is refused, as everywhere.
- A file that still has the old top-level `ApplicationProfiles` is refused with
  a message saying to move the list under `TestApplicationProfiles` >
  `OnInstrument`.

**Application profiles.** Every file in the folder is first read with the
reader's rules (one YAML document, plain spellings, no key given twice, no
tags or anchors), as today; a file that fails is refused. Then:

- `ApplicationType` is `Dragen` (any case, spaces around it ignored, as the
  Dragen check already compares it): checked in full, as today, and stored.
- Not `Dragen`, but the `ApplicationName` is one of Illumina's application
  names (`BCLConvert`, `DragenGermline`, ...; in any case): **refused**, saying
  the type must be `Dragen`. A typo in the type must not make BCL Convert
  vanish from the sheet.
- Missing, or not text: refused, as today.
- Anything else: **skipped**. Not stored, nothing else in it checked. The sync
  lists each skipped file and its type on the Config Sync page and in its audit
  row; `pixi run check-settings` prints a line per skipped file and counts
  them apart from the files checked.

So every stored application profile is a Dragen profile with one of Illumina's
application names, and the Sample Sheet writer is unchanged. A test whose
`OnInstrument` names a skipped profile gets the Check page's existing "not
found" error for its samples.

**Sample Sheet v2.** `[Header]` always writes `RunDescription,<run id>`, after
`RunName`, through `_escape_identifier` (a UUID passes unchanged).
`Custom_UUID,<run id>` stays. The description typed in SeqSetup is no longer
written into the v2 sheet; it stays in SeqSetup, in the JSON export
(`run_description`), and in the v1 sheet's `Description`, which is unchanged.
On the 78-sheet corpus every v2 sheet should differ in its `RunDescription`
line only, and no v1 sheet at all; the build measures it.

**Shipped files and docs.** `config/profiles/test_profiles/Wgs.yaml` moves to
the new layout. The admin guide's profile pages describe the layout, the
skipped profiles and the end of external profiles; the sample sheet format
page shows `RunDescription` as the UUID.

## What the lab's files need

Checked with `pixi run check-settings` against `test-profile-config/` at
3d0db82:

- Test profiles: `Version: "1.0.0"` (three numbers); `OnInstrument` versions
  as text, e.g. `"~=1.0"` (a bare `1` matches only a profile whose version is
  the text `1`).
- The instrument profiles the tests name (`BCLConvertNextera`,
  `DragenGermlineIdtWgs`) added to the folder.
- Pipeline profiles: versions in quotes (`"1.0"`, `"1.3"`); the reader refuses
  an unquoted decimal in any file it reads.

## What does not change

- The Sample Sheet writer, the Check page's profile checks, the JSON export
  and the API.
- Stored test profiles: the model keeps its list of application profiles.
- The v1 Sample Sheet.
