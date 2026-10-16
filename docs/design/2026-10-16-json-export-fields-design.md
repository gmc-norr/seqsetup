# JSON export: the test, worksheet and mismatch fields

Finding F7 of the outside review of `f490536`.

## The problem

The JSON export is one of a Ready run's four stored exports and is served by
the API. `JSONExporter._serialize_sample` leaves out five things a sample
carries, and `_serialize_run` two:

| missing | where it is |
|---------|-------------|
| `test_id`, `test_version` | `Sample.test_id`, `Sample.test_version` — what picks the application profiles the Sample Sheet is written from |
| `worksheet_id` | `Sample.worksheet_id` — the LIMS worklist the sample came from |
| `index_kit_name` | `Sample.index_kit_name` — which kit the index came from |
| `barcode_mismatches_index1` / `_index2` | `Sample.barcode_mismatches_*` — the per-sample override |
| `test_versions_used` | `SequencingRun.test_versions_used` — the exact versions the checks passed |
| `i5_workflow` | the run's i5 direction, which decides how `Index2` is written |

The measured consequence (from the verifier's report): a sample whose i7
mismatch is **2** produces `BarcodeMismatchesIndex1,2` in the Sample Sheet,
while the JSON states only the **run-level** `1` under
`bclconvert_settings`. A downstream reader of the JSON gets a different
number from the sheet for the same sample. No sample sheet is wrong — the
sheet is right; the JSON is incomplete — but two exports of one run
disagree, and a reader cannot tell which is authoritative.

`README.md`'s export table says the JSON is "Complete run and sample data
including test IDs" — the one thing it is not.

## What this is not

The JSON export is **not** a second source of truth for the Sample Sheet.
`samplesheet_index2` and `samplesheet_override_cycles` already exist for
exactly that reason: they are read from `services/sheet_plan.py`, the one
place that decides them, "never derived again here, or the two exports of
one run could disagree" (the comment in `_serialize_sample`). Any field
added here follows the same rule.

## Options

**A. Add the sample's own values only.** Five sample keys and two run keys,
all read straight off the model. Smallest change, no new argument to the
exporter.

*Risk:* it does not close the measured gap for a sample with **no** override.
The sheet's cell then comes from the application profile's `Data` default
(`_profile_mismatch_cell` in the v2 writer), which the JSON would still say
nothing about: a reader would see `null` and the run default `1`, while the
sheet says whatever the profile set. The report's own wording — "effective
mismatches from the sheet plan" — rules this out on its own.

**B. Add the sample's own values *and* the effective ones from the sheet
plan.** `SheetPlan.mismatches` (`services/sheet_plan.py:95`) is already a
`dict[(sample id, index number) -> int]` of the resolved numbers, built
where the profile fallback is resolved. `ValidationService` already computes
that plan for every Mark Ready. So: expose it on `ValidationResult`, pass it
to `JSONExporter.export`, and emit it as
`samplesheet_barcode_mismatches_index1` / `_index2` beside the existing
`samplesheet_*` keys.

*Risk:* the JSON must then be written **after** the checks in
`_pregenerate_exports` rather than before, and the exporter grows two
optional keyword arguments. The live fallback for runs created before
pre-generation existed (`routes/export.py`) has no plan, so those two keys
are `null` there — the same shape `samplesheet_index2` already has when
SeqSetup cannot say what the sheet would write.

## Chosen: B

Because the point of the finding is that the JSON and the sheet disagree
about a number, and A leaves them disagreeing in the commonest case (a
profile that sets a default, a sample with no override of its own). B states
both numbers and labels them: `barcode_mismatches_index1` is "what this
sample overrides, or null", `samplesheet_barcode_mismatches_index1` is "what
the Sample Sheet writes". `test_versions_used` likewise has to be passed in,
because the JSON is written before `run.test_versions_used` is set.

The two new `samplesheet_*` keys are `null` rather than absent when unknown,
and `docs/api-reference/export.rst` already tells consumers to test for a
key's **presence** rather than read a missing key as a value — the same
contract covers these.

## Keys added

Per sample: `test_id`, `test_version`, `worksheet_id`, `index_kit_name`,
`barcode_mismatches_index1`, `barcode_mismatches_index2`,
`samplesheet_barcode_mismatches_index1`,
`samplesheet_barcode_mismatches_index2`.

Per run: `test_versions_used`, `i5_workflow`.

Nothing is removed and no existing key changes meaning or type, so a reader
of the old shape keeps working. A Ready or Archived run keeps serving the
JSON stored when it was marked Ready; only runs marked Ready after this
change carry the new keys.

**Not added**: the user/timestamp tracking the report also lists
(`created_by`, `updated_by`, `created_at`, `updated_at`). Those are about who
touched the record, not about what will be sequenced, and the audit trail
already answers them for a reader who is entitled to it. Left out
deliberately rather than overlooked.

## What proves it

`tests/integration/test_json_export_fields.py`: every new key present with
the right value for a run with a per-sample override, a run whose number
comes from the profile default, and a sample with no index at all; the old
keys unchanged; and the live fallback's two `samplesheet_*` keys `null`
rather than missing. Plus a test that the stored JSON of a run marked Ready
before this change is still served as it was.
