# The JSON export gains the sheet's i5 and OverrideCycles — design

Date: 2026-10-12. Base: `ce53b18` (night run batch 1). Branch `fix/exports` (night run,
batch 2, item 2a). Decision: the user.

## The problem, measured

Two exports of the same run disagree about two values that decide how reads are assigned
to patients. Measured on this worktree at `ce53b18` (the night run's
`scratch/probe_2a.py`; shipped `BCLConvertNextera` / `Wgs` profiles, one dual-index
sample, i7 `ACGTACGT`, i5 `ACGTTTGG`):

```
--- NextSeq 500/550  (i5 read reverse-complement, RunInfo marks it False) ---
run id in both exports:        probe-run
i5 as typed:                   ACGTTTGG
i5 in the v2 sheet (Index2):   CCAAACGT
i5 in the JSON export:         ACGTTTGG
OverrideCycles in the v2 sheet: Y151;I8;I8;Y151
OverrideCycles in the JSON:     Y151;I8;I8;Y151

--- NovaSeq X Series  (i5 read reverse-complement, RunInfo marks it True) ---
run id in both exports:        probe-run
i5 as typed:                   ACGTTTGG
i5 in the v2 sheet (Index2):   ACGTTTGG
i5 in the JSON export:         ACGTTTGG
OverrideCycles in the v2 sheet: Y151;I8N2;N2I8;Y151
OverrideCycles in the JSON:     Y151;I8N2;I8N2;Y151
```

The two differences are mutually exclusive by construction, so one run cannot show both:
`I5Direction.index2_column_reversed` is "the i5 is read reversed **and** RunInfo.xml does
not mark it", `index2_mask_reversed` is "read reversed **and** RunInfo.xml marks it"
(`data/instruments.py`). Measured over every instrument and workflow of the shipped
`config/instruments.yaml` (the night run's `scratch/i5_states.py`):

```
the i5 differs (Index2 column reversed):
    HiSeq 4000 / Standard
    HiSeq X / Standard
    NextSeq 500/550 / Standard
    MiniSeq / Standard kits
    NovaSeq 6000 / v1.5 reagents
the OverrideCycles differs (Index 2 mask reversed):
    NovaSeq X Series / Standard
    MiSeq i100 Series / Read-first
    NextSeq 1000/2000 / Standard
neither differs (i5 read forward):
    GAIIx / Standard
    HiSeq 2000/2500 / Standard
    MiSeq / Standard
    MiniSeq / Rapid kits
    NovaSeq 6000 / v1.0 reagents
    MiSeq i100 Series / Index-first

totals: column 5, mask 3, neither 6, both 0
```

In the three "mask reversed" cases the written OverrideCycles differs from the stored one
only when the Index 2 part has something to reverse — an index shorter than its read
(`I8N2` becomes `N2I8`) or a UMI. An 8 bp index on 8 cycles gives `I8`, which reads the
same either way, which is why the measurement above uses an 8 bp index on 10 cycles.

Nobody reading the JSON export can tell which value the sequencer was actually given.

## The rule

The JSON export **adds**, per sample, the two values the v2 Sample Sheet writes:

| new key | what it holds |
|---|---|
| `samplesheet_index2` | the i5 exactly as the v2 sheet's `Index2` cell holds it |
| `samplesheet_override_cycles` | the OverrideCycles exactly as the v2 sheet's `OverrideCycles` cell holds it |

**Every existing key keeps its name, its place and its value.** `index2.sequence` and
`override_cycles` stay "as typed" (the i5 as the index kit lists it; the sample's own
OverrideCycles or the one calculated from the run's cycles, in reading order).
`bclconvert_settings.global_override_cycles` also stays exactly as it is — unadjusted,
like the per-sample `override_cycles` it summarises.

Both new keys are `null` when the sheet's cell would be empty, so they match the
convention of the "as typed" keys beside them: `index2` is already `null` for a sample
with no i5, and `override_cycles` is already `null` for a sample with no OverrideCycles.
A reader therefore never has to tell `""` apart from "no value".

Nothing about the Sample Sheet bytes changes, and no check changes. Only the JSON export
grows two keys per sample.

### The field names, and why

- `samplesheet_` as the prefix: the JSON export's keys are otherwise the run's and the
  sample's own stored values, and this prefix is the one word that says "this is what the
  Sample Sheet carries, not what was typed". It is the name the UI and the docs already
  use for that artefact (`generated_samplesheet_v2`, "Sample Sheet v2").
- `index2` and `override_cycles` as the suffixes: they are the v2 sheet's own column names
  (`Index2`, `OverrideCycles`) in the snake_case the JSON export uses everywhere. A reader
  comparing `index2.sequence` with `samplesheet_index2` is comparing two keys whose names
  differ by exactly the thing that differs in meaning.
- Both are flat keys next to `override_cycles`, not a nested `samplesheet: {...}` object:
  the comparison a reader makes is between two values on one level, and a new nesting
  level would be a new shape for API consumers to learn.
- Rejected: `index2_in_sheet` / `effective_index2` ("effective" already means something
  else in this codebase — `Sample.effective_index_sequence` is the cycles actually read,
  which is a third value again), and `index2_rc` (it names the mechanism, which is wrong
  for the NovaSeq X case where the sheet's i5 is **not** reverse-complemented but the
  OverrideCycles mask is).

## One computation, not two

The i5 flip and the OverrideCycles mask flip must not be derived a second time: a second
derivation is exactly the defect this item fixes, one layer down. `services/sheet_plan.py`
is where the v2 writer and Mark Ready's checks already share what the sheet will say, so
it gains the two functions that define the sheet's per-sample values:

```python
def sheet_index2(sample, run) -> str
def sheet_override_cycles(sample, run) -> Optional[str]
```

- `sheet_index2` is the i5 the `Index2` column holds: the stored i5, reverse-complemented
  when `run_i5_direction(run).index2_column_reversed`.
- `sheet_override_cycles` is the `OverrideCycles` column's value: the sample's own
  OverrideCycles, else the one calculated from the run's cycles (`_override_cycles`, which
  the plan's checks already use), with the Index 2 part reversed when
  `index2_mask_reversed`.

The two orientation primitives **stay where they are**, as
`SampleSheetV2Exporter._resolve_i5` and
`SampleSheetV2Exporter._adjust_override_cycles_for_instrument` — that is the code that
writes the sheet today, it is covered by `tests/unit/test_samplesheet_v2_exporter.py`
and `tests/unit/test_i5_rule.py`, and moving 50 lines of orientation arithmetic in a
clinical writer buys nothing. The two new functions call them (through the function-local
import `sheet_plan` already uses for `_run_settings`), and:

- `SampleSheetV2Exporter._write_application_section` — the production, profile-driven row
  loop — fills its `Index2` and `OverrideCycles` cells from the two new functions instead
  of from its own inline copies. This **removes** a duplicate: the loop's "the sample's
  OverrideCycles, else the calculated one" was a third copy of a step that already existed
  in `sheet_plan._override_cycles` and in `JSONExporter._serialize_sample`.
- `JSONExporter._serialize_sample` fills the two new keys from the same two functions.

So the flip is decided in one place and read in two, and a future reader of
`sheet_plan.py` sees the whole of what the sheet says about a sample.

`_write_bclconvert_data` — the fallback path used only when no profile repositories are
passed — keeps calling the primitives directly. Its OverrideCycles column exists only when
`infer_global_override_cycles(run)` is `None` (otherwise a single run-level
`OverrideCycles` goes into `[BCLConvert_Settings]`), so `sheet_override_cycles` does not
describe that path's cell and must not be put in front of it.

## What does not change

- The Sample Sheet v2 bytes. Proven by the run's sheet gate: 78 shipped-profile sheets, 0
  differ, 0 refused.
- The Sample Sheet v1 bytes, the validation report, and every Mark Ready check.
- Every key of the JSON export that exists today, its order in the object, and its value —
  tested by building the expected JSON from the code **as it is before the change** and
  comparing the whole old key set and every old value against it, for a run on an
  instrument of each of the three i5 states.
- `global_override_cycles`, which stays the unadjusted summary of the samples' own values.

## Tests

- A run on an instrument whose `Index2` column is reversed: `samplesheet_index2` is the
  reverse complement, `index2.sequence` is still as typed, and both equal the sheet's cell
  and the sample's stored sequence respectively.
- A run on an instrument whose OverrideCycles mask is reversed, with an 8 bp index on 10
  cycles: `samplesheet_override_cycles` is `Y151;I8N2;N2I8;Y151`, `override_cycles` is
  still `Y151;I8N2;I8N2;Y151`, and the first equals the sheet's cell.
- A run on an instrument that reads the i5 forward: both new keys equal their "as typed"
  neighbours.
- A sample with no i5: `samplesheet_index2` is `null`. A sample with no index at all:
  `samplesheet_override_cycles` is `null`.
- Every old key and value is unchanged, on all three kinds of instrument.
