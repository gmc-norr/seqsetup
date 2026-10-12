# A profile's Sample_Project / Sample_Name take the sample's own value — design

Date: 2026-10-12. Base: `ce53b18` (night run batch 1). Branch `fix/exports` (night run,
batch 2, item 2b). Decision: the user.

## The problem, measured

A profile may list any column it likes in its data section. The v2 writer fills the
columns it knows itself (`Sample_ID`, `Lane`, `Index`, `Index2`, `OverrideCycles`, the two
mismatch columns) and writes the profile's `Data` default for every other column, the same
text in every row. `Sample_Project` and `Sample_Name` are not among the names it knows, so
a profile that lists them writes one project and one name for the whole run — whatever the
samples carry.

Measured on this worktree (the night run's `scratch/probe_2b.py`) with a BCLConvert
profile whose `DataFields` list `Sample_Name` and `Sample_Project` and whose `Data`
defaults are `PROFILE_DEFAULT_NAME` / `PROFILE_DEFAULT_PROJECT`, on a NovaSeq X 10B run
(8 lanes, so each sample has 8 identical rows; one is shown). First seen at `ce53b18`;
this output is at `3d88447`, item 2a, which changes neither column:

```
samples as stored:
  S1: sample_name='Patient-A' project='ProjectA'
  S2: sample_name='' project=''

[BCLConvert_Data] as written today (the header and each sample's lane 1 row):
  Lane,Sample_ID,Sample_Name,Sample_Project,Index,Index2,OverrideCycles
  1,S1,PROFILE_DEFAULT_NAME,PROFILE_DEFAULT_PROJECT,ACGTACGT,ACGTTTGG,Y151;I8;I8;Y151
  1,S2,PROFILE_DEFAULT_NAME,PROFILE_DEFAULT_PROJECT,TGCATGCA,CCAATTGG,Y151;I8;I8;Y151
```

`Sample_Project` is what bcl2fastq and BCL Convert use as the output directory for a
sample's FASTQ files, and `Sample_Name` names the files inside it. Writing one project for
every sample puts every patient's reads in one directory under a name the operator never
typed; the v1 sheet, for the same run, writes each sample's own project and name
(`samplesheet_v1_exporter._write_data`). The two sheets of one run disagree.

## The rule

In the profile-driven writer (`SampleSheetV2Exporter._write_application_section`, which
writes every application's data section):

- a `Sample_Project` column holds the **sample's own project** when that is non-empty,
  and the profile's `Data` default when it is empty;
- a `Sample_Name` column holds the **sample's own name** when that is non-empty, and the
  profile's `Data` default when it is empty.

"Non-empty" is the stored string being non-empty — the same test the writer already
applies to `sample.index1_sequence` and to a sample's own mismatch number. Mark Ready
already refuses a sample name or project with a line break or any other hidden character,
so a non-empty value here is ordinary text.

The sample's value is written with `_escape_identifier`, as `Sample_ID` is and as the v1
sheet already writes both of these columns: a name made only of `[A-Za-z0-9_-]` is written
exactly, and anything else falls back to `_escape_csv`. The profile's default keeps going
through `_escape_config_cell`, which is the right check for a value an admin put in a
profile (it refuses a non-scalar, a hidden character and a leading `[`).

This applies in every application section, not only `BCLConvert`: the column dispatch is
shared, and a DRAGEN profile listing `Sample_Project` means the same thing.

`Translate` keeps working as before — the dispatch switches on the column name the sheet
gets, so `DataFields: [Proj]` with `Translate: {Proj: Sample_Project}` takes the sample's
project, and its default still comes from `Data[Proj]`.

## The Mark Ready checks that must agree

1. **The line-break and hidden-character checks already agree.**
   `ValidationService._SAMPLE_TEXT_FIELDS` is `("sample_name", "project", "description")`
   — "Free-text sample fields written to the Sample Sheet" — and both checks
   (`line_break_in_sample_text`, `hidden_character_in_text`) run on every sample of every
   run, whatever the profiles list. They already assume these two values can reach a
   sheet, which is true today through the v1 sheet. No change.

2. **The "spelled otherwise" check does not agree, and is changed.** `sheet_plan`'s
   `SPELLED_COLUMNS_BCLCONVERT` is "Names SeqSetup fills or reads itself, in the one
   spelling it uses" — another spelling is refused at Mark Ready, because the sheet would
   not then carry what the checks used. Once the writer fills `Sample_Project` and
   `Sample_Name`, a profile spelling one of them `sample_project` or `SAMPLE_NAME` would
   silently get the profile's default in every row again — exactly the defect above, one
   spelling away. So the two names join that machinery, as a new
   `SPELLED_COLUMNS_ANY = ("Sample_Project", "Sample_Name")` applied to **every**
   profile's columns, mirroring the existing `SPELLED_SETTINGS_ANY`: the writer fills them
   in every application's section, so a per-application list would under-cover.
   `SPELLED_COLUMNS_BCLCONVERT` is unchanged, and `Sample_ID` is left where it is.

   The same two lists are read by the sync-time check
   (`profile_validator._name_problems`), so a profile with the wrong spelling is refused
   when it is synced as well as at Mark Ready.

   This is the one part of the item not spelled out in the decision; it is included
   because without it the list's own stated rule becomes false.

## What does not change

- **Today's 78 Sample Sheets.** No shipped application profile lists either column, in any
  case. Measured with the night run's `scratch/shipped_columns.py`, which finds each
  profile's columns the way the writer finds them (`sheet_plan.data_columns`):

  ```
  BCLConvertNextera.yaml (BCLConvert BCLConvertNextera 1.0.0)
    columns: Sample_ID, Lane, Index, Index2, OverrideCycles, BarcodeMismatchesIndex1, BarcodeMismatchesIndex2, AdapterRead1, AdapterRead2
    Sample_Project / Sample_Name (any case): none
  DragenEnrichmentIdtGermline.yaml (DragenEnrichment DragenEnrichmentGermline 1.0.0)
    columns: Sample_ID, ReferenceGenomeDir, BedFile, GermlineOrSomatic, AuxNoiseBaselineFile, AuxCnvPanelOfNormalsFile, VariantCallingMode
    Sample_Project / Sample_Name (any case): none
  DragenEnrichmentIdtSomatic.yaml (DragenEnrichment DragenEnrichmentSomatic 1.0.0)
    columns: Sample_ID, ReferenceGenomeDir, BedFile, GermlineOrSomatic, AuxNoiseBaselineFile, AuxCnvPanelOfNormalsFile, VariantCallingMode
    Sample_Project / Sample_Name (any case): none
  DragenGermlineIdtWgs.yaml (DragenGermline DragenGermlineIdtWgs 1.0.0)
    columns: ReferenceGenomeDir, VariantCallingMode, QcCoverage1BedFile, QcCoverage2BedFile, QcCoverage3BedFile, QcCrossContaminationVcfFile, Sample_ID
    Sample_Project / Sample_Name (any case): none
  DragenRnaIdt.yaml (DragenRna DragenRna 1.0.0)
    columns: DifferentialExpressionEnable, ReferenceGenomeDir, RnaGeneAnnotationFile, RnaPipelineMode, DownSampleNumReads, VariantCallingMode, Comparison1, Comparison2, Comparison3, Comparison4, Comparison5, Sample_ID
    Sample_Project / Sample_Name (any case): none
  DragenSomaticIdt.yaml (DragenSomatic DragenSomaticIdt 1.0.0)
    columns: Sample_ID, ReferenceGenomeDir, VariantCallingMode, AuxNoiseBaselineFile, AuxSvNoiseBaselineFile, AuxCnvPopBAlleleVcfFile, AuxGermlineTaggingFile, AuxCnvPanelOfNormalsFile
    Sample_Project / Sample_Name (any case): none

  shipped profiles with a Sample_Project or Sample_Name column, any case: 0
  ```

  So no sheet SeqSetup writes today gains or loses a character, which the run's sheet gate
  proves: 78 sheets checked, 0 differ, 0 refused.

- The v1 sheet (which already writes each sample's own name and project), the JSON export,
  the `[Cloud_Data]` section's `ProjectName` (the **run** name, not a sample's project),
  and every other column's handling: a column the writer does not know still gets the
  profile's `Data` default for every row.
- Which samples go in which section, the mismatch numbers, and every other plan problem.

## Tests

- A profile listing `Sample_Project` and `Sample_Name` with `Data` defaults: a sample with
  its own project and name gets its own in both cells; a sample with neither gets the
  profile's defaults in both.
- One value empty and the other not: each cell is decided on its own.
- A `Translate`d field (`Proj` → `Sample_Project`) behaves the same, and takes its default
  from `Data[Proj]`.
- A DRAGEN (non-BCLConvert) profile listing the columns behaves the same.
- A project that is not a plain identifier is escaped, and a project with a comma does not
  shift the row's columns.
- A profile spelling either column otherwise (`sample_project`, `Sample_name`) is refused
  at Mark Ready and by the sync, naming the spelling SeqSetup uses — in a BCLConvert
  profile and in a DRAGEN one.
- A profile that lists neither column writes exactly what it writes today.
