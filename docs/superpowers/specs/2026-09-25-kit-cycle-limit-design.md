# Kit cycle limit — design

## Problem

A run can ask for more cycles than its reagent kit holds and nothing says so:
Read 1 = 301, Read 2 = 301, Index 10 + 10 on a 300-cycle kit passes Check and
can be marked Ready. The sequencer would run out of reagent mid-run.

The kit label (300) is not the limit. Kits hold extra cycles beyond the label
(the default 151 + 151 + 10 + 10 = 322 on a 300-cycle kit is normal use), and
the extra depends on the kit and chemistry. The app has no exact figures, so
the lab supplies them.

## Decisions (user, 2026-09-25)

- Too many cycles is an ERROR: Check turns red and Mark Ready is refused.
- The limit is an exact number per instrument and kit, taken by the lab from
  Illumina's kit documentation. The app ships with none; with no number for a
  kit, that kit is not checked (same as today).
- One number per kit, not one per instrument, because the extra can differ
  between kit sizes. If a kit's limit differs between flowcells, the lab enters
  the smallest.

## Data

New optional instrument key, in both the GitHub-synced instrument files and
the fallback `config/instruments.yaml`:

```yaml
reagent_kit_max_cycles:   # kit label -> most cycles allowed, all reads together
  300: 338                # example only
```

- `services/instrument_validator.py`: must be a mapping of positive whole-number
  kit labels to whole numbers no smaller than the label. Anything else is a
  sync error (the instrument is skipped, as for any invalid field). A label no
  flowcell offers is a warning (likely a typo).
- `models/instrument_definition.py`: new field `reagent_kit_max_cycles:
  dict[int, int]`, checked on every assignment (same rule; raises ValueError).
  Stored in MongoDB with string keys (BSON requires them), read back as ints.
- `data/instruments.py`: `get_reagent_kit_max_cycles(platform, reagent_kit)`
  returns the number or None. A malformed value in the fallback YAML (which the
  sync validator never sees) is logged and treated as "no number".

## Rule

`services/validation.py`, `validate_configuration`: when the run has cycles
and its instrument has a number for its kit, and Read 1 + Index 1 + Index 2 +
Read 2 is larger than that number, add

- severity ERROR, category `cycles_exceed_kit`
- "Too many cycles: 340. A 300-cycle kit on NextSeq 1000/2000 allows 338.
  Lower the cycles in Run Setup."

It runs before the no-samples early return: cycles are a run setting, so an
empty run with too many cycles shows red, not the grey "Add samples first".

## Setup page

The total line moves to `wizard/_cycle_total.html`.

- With a number: "Total: 322 / 338 max (300-cycle kit)", plus a red
  "Too many cycles for this kit." when over.
- Without: unchanged, "Total: 322 / 300 cycles".

Changing the instrument or flowcell can change the kit's number (and the
flowcell change can change the kit), so those two responses also swap the
total line out of band. Cycle and kit changes already re-render it.

## Clean-up

Delete `CycleCalculator.validate_cycles` and its two tests. Nothing calls it
and it compares the total with the kit label, which would flag the app's own
default.

## Not in scope

- Filling in any numbers.
- Admin-made custom instruments (no field; not checked).
- Changing the instrument does not refresh the reagent-kit list (existing).
