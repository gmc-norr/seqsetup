# The DRAGEN RNA section is spelled DragenRna

## The problem

SeqSetup spelled the DRAGEN RNA application two ways:

- `DragenRna` — the shipped RNA application profile's `ApplicationName`, and
  so the section a profile writes: `[DragenRna_Settings]`, `[DragenRna_Data]`.
- `DragenRNA` — the hardcoded fallback writer
  (`SampleSheetV2Exporter._write_dragen_rna`), and the `onboard_applications`
  key of the shipped NovaSeq X instrument files (`config/instruments.yaml`,
  `config/instruments/novaseq-x-series.yaml`).

The profile check compares a profile's `ApplicationName` with an instrument's
`onboard_applications` keys exactly, so the shipped RNA profile could never
pass on a shipped instrument ("Application 'DragenRna' ... is not available").
A practice deploy found it (2026-10-17); `tests/unit/test_shipped_examples_fit.py`
pinned it as an open question.

## What Illumina writes

Illumina's NovaSeq X sample sheet version history (help.connected.illumina.com,
read 2026-10-17) names the sections `[DragenRna_Settings]` and
`[DragenRna_Data]`, beside `DragenGermline`, `DragenSomatic`,
`DragenEnrichment` and `DragenMethylation`; the NextSeq 1000/2000 history
names `[DragenRna_Settings]` and `[DragenRna_Data]` too. No Illumina page
found names a `[DragenRNA_Settings]` section. Illumina Connected Insights
accepts `[DragenRNA_Data]` as well as `[DragenRna_Data]` in the sheets it
reads, which is a reader being lenient, not the instrument's spelling. The
user's decision (2026-10-17): use the spelling Illumina uses.

## The change

- The fallback writer writes `[DragenRna_Settings]` and `[DragenRna_Data]`.
- The shipped instrument files offer `DragenRna`.
- `test_shipped_examples_fit.py` now requires every shipped profile's
  application to be offered by a shipped instrument, at its version, and
  every application a shipped instrument offers (the local fallback file
  included) to be spelled as Illumina spells it.
- `test_dragen_section_names.py` holds every section header the v2 writer
  names in its own code, and the section every shipped profile writes, to
  Illumina's names. It cannot see a lab's own profiles.

## What it changes in a sheet

Nothing a lab has received. The running application always writes the
profile-driven sections (`routes/runs.py` and `routes/export.py` pass both
profile stores), and those already used `DragenRna`. The fallback writer runs
only when the stores are missing, which the application never does, and no
page or import adds the onboard analysis it writes from.

A lab's own settings repository keeps its own spellings, and SeqSetup writes a
profile's `ApplicationName` as it is, without checking it against Illumina's
names:

- Instrument files saying `DragenRNA` with an RNA profile saying `DragenRna`:
  the run is refused at Mark Ready (`app_not_available`) until the two agree,
  as before.
- An RNA profile saying `DragenRNA`, written to match the shipped instrument
  key before this change: with the shipped instruments it is now refused at
  Mark Ready, loudly. With the lab's own instrument files also saying
  `DragenRNA`, it passes and the sheet carries `[DragenRNA_*]` sections, as it
  always did.
