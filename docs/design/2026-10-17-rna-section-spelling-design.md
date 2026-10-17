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

Illumina's NovaSeq X and NextSeq 1000/2000 sample sheet version histories
(help.connected.illumina.com, read 2026-10-17) name the sections
`[DragenRna_Settings]` and `[DragenRna_Data]`, beside `DragenGermline`,
`DragenSomatic`, `DragenEnrichment` and `DragenMethylation`. The user's
decision (2026-10-17): use the spelling Illumina uses.

## The change

- The fallback writer writes `[DragenRna_Settings]` and `[DragenRna_Data]`.
- The shipped instrument files offer `DragenRna`.
- `test_shipped_examples_fit.py` now requires every shipped profile's
  application to be offered by a shipped instrument, at its version.
- A test holds every section header the v2 writer can write to Illumina's
  names.

## What it changes in a sheet

Nothing a lab has received. The running application always writes the
profile-driven sections (`routes/runs.py` and `routes/export.py` pass both
profile stores), and those already used `DragenRna`. The fallback writer runs
only when the stores are missing, which the application never does, and no
page or import adds the onboard analysis it writes from. A lab whose own
instrument files say `DragenRNA` keeps them until it changes them: the check
refuses such a run loudly, it never writes a wrong sheet.
