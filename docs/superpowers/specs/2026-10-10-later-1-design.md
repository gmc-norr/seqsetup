# Later list, slice 1: LIMS replies, kit swaps and three Sample Sheet rules — design

Date: 2026-10-10. Base: main `862d81f` (group A4 merged and pushed). Branch `fix/later-1`.
Source: the "Not in this change" and "Later list" sections of the group A1–A4 specs, and the
A1 and A2 build runs' escalations. Decisions: the user, in this brainstorm (2026-10-10).
The lab converts runs with DRAGEN 4.3 and moves to 4.4 soon (the user, 2026-10-10).

## Why

Six things on main can put a wrong row, a wrong read or a sheet DRAGEN refuses in front of
the lab. Each was measured on `862d81f` (MongoDB at `127.0.0.1:1`, mongomock for the stores).

1. **A LIMS reply with a name twice loses one of them.** `_api_get`
   (`services/sample_api.py:326`) reads the reply with `json.loads`, which keeps the last of
   a repeated name. `parse_api_samples` (`:688`) then lower-cases the names of each row, so
   two names that differ only in capitals also keep one:

   ```
   {"samples": {"S1": "WGS", "S2": "WGS", "S1": "WES"}}  -> 2 samples: S1 (test WES), S2
   [{"SampleID": "P1", "TestID": "WGS", "SampleID": "P2"}] -> one sample, P2
   [{"SampleID": "P1", "sampleid": "P2"}]                  -> one sample, P2
   ```

   A patient's row that disappears sends its reads to Undetermined. iGene's
   `/worksheets/{id}` sends a list of reports (`igene_openapi.json`); the `{sample: test}`
   form is the other format `fetch_worklist_samples` (`:557`) accepts.
2. **A test profile can turn the i5 direction back.** `I5_RULE_SETTINGS`
   (`services/sheet_text.py:67-70`) lists four settings the sync and the writer refuse in a
   BCLConvert profile's `Settings`; `IndexOrientation` is not one of them. The sync accepts a
   profile with `IndexOrientation: Forward` (also `indexorientation`), and a NextSeq 500 run,
   whose sheet writes the i5 reversed and leaves `IndexOrientation,Forward` out of
   `[Header]`, gets `IndexOrientation,Forward` in `[BCLConvert_Settings]`.
3. **One sample, two kits with different read patterns.** `_apply_kit_defaults`
   (`routes/samples.py:209-222`) gives a sample the read patterns of the last kit assigned
   from, also when only its i5 or only its i7 changes. A sample with a UMI kit's i7 and i5
   (`U8Y*`, OverrideCycles `U8Y143;I8N2;I8N2;U8Y143`) whose i5 is replaced from a plain kit
   gets `Y151;I8N2;I7N3;Y151`: the 8 UMI bases of each read go into the patient's reads.
   `tests/integration/test_group_a1.py:210-242` pins this today (6 cases, passing).
4. **LIMS values of the wrong JSON type are changed, not refused.** `parse_api_samples`
   (`:699`) writes every field it reads as `str(val).strip()[:256] if val else ""`. Only the
   sample ID, the test and the test version are checked by type (group A4):

   ```
   i7_name 1.10          -> '1.1'
   i5_name 0             -> ''
   index_pair_name true  -> 'True'
   worksheet_id ["a","b"] -> "['a', 'b']"
   sample_id ["S1","S2"] -> "['S1', 'S2']"   (Mark Ready's ID check refuses it later)
   sample_id {"a": 1}    -> "{'a': 1}"
   sample_id 0           -> refused as "sample_id is missing or empty"
   ```
5. **A mismatch number for an index the sample does not have.** Every sample stores
   `barcode_mismatches_index1 = barcode_mismatches_index2 = 1` (`models/sample.py:93-94`),
   and the writer (`services/samplesheet_v2_exporter.py:653-664`) writes it. A single-index
   sample in a dual-index run gets:

   ```
   Sample_ID,Lane,Index,Index2,OverrideCycles,BarcodeMismatchesIndex1,BarcodeMismatchesIndex2
   S2,1,ACGTACGTAC,,Y151;I10;N10;Y151,1,1
   ```

   And a BCLConvert profile with `BarcodeMismatchesIndex2: 1` in its `Settings` writes
   `BarcodeMismatchesIndex2,1` with that sample in the run, with no sheet-plan problem.
   DRAGEN 4.3 and 4.4: per-sample settings "that do not apply to a sample (e.g. 'index2' if
   i5 is masked out for that sample) must be blank or 'na' in the entry for that sample";
   `BarcodeMismatchesIndex1` in Settings "can only be specified when index 1 is present and
   used for demultiplexing for all samples" (v4.4 and v4.2 say the same for Index 2).
6. **No lane splitting with a Lane column.** A run with `no_lane_splitting` true, or a
   BCLConvert profile with `NoLaneSplitting: true` in its `Settings`, writes
   `NoLaneSplitting,true` (`NoLaneSplitting,True` from the profile) next to a `Lane` column,
   with no sheet-plan problem. DRAGEN 4.3: "DRAGEN only supports this mode when no 'Lane'
   column is specified in the sample sheet". DRAGEN 4.4: v4.4.4 the same; "DRAGEN v4.4.6 and
   above now supports no-lane-splitting mode whether or not a 'Lane' column is specified in
   the sample sheet if output is to the gzip compression format".

The measurements are in the work notes (`measure_today.py`, not committed).

## Decisions

1. The slice is these six items (the user: "2", 2026-10-10).
2. A sample keeps an index from a kit whose read patterns differ from the new kit's: the
   assignment is **refused** (the user: "1"). The read patterns do not follow the i7: a
   UMI may sit on either adapter, so that would be a guess.
3. A repeated name anywhere in a LIMS reply refuses the whole reply. Two names in one row
   that differ only in capitals refuse the whole import when SeqSetup reads that name.
4. Every field SeqSetup reads from a LIMS row is text or a whole number, or the import is
   refused. A whole number is written as its digits, `0` too.
5. `IndexOrientation` joins the BCLConvert `Settings` names SeqSetup refuses.
6. A sample with no i7 gets `na` in its `BarcodeMismatchesIndex1` cell, and one with no i5
   gets `na` in its `BarcodeMismatchesIndex2` cell. `na`, not blank: the NovaSeq X page
   names `na` for this case, and it shows the cell was left out on purpose.
7. A BCLConvert profile's `Settings` mismatch value with a sample in its section that has no
   such index stops Mark Ready.
8. `NoLaneSplitting` on with a `Lane` column stops Mark Ready, whatever the DRAGEN version.
   Loosening it for DRAGEN 4.4.6 and later goes on the later list.

## §1 LIMS replies (`services/sample_api.py`)

### A name twice in one object

`_api_get` reads the reply with an `object_pairs_hook` that raises `SampleApiError` when one
JSON object has the same name twice, at any depth. Every LIMS call goes through `_api_get`
(`check_connection`, `fetch_worklists`, `fetch_worklist_samples`), so each refuses such a
reply and shows its message as it shows its other errors today. The message:

```
The LIMS reply has the name <name> twice in one object. SeqSetup cannot tell which value is right, so the reply was not used.
```

`<name>` is `repr(shown_value(name))` (at most 40 characters, then `…`).

### Two names that differ only in capitals

In `parse_api_samples`, before a row's names are lower-cased: if two of the row's names are
equal ignoring capitals, and that name is one SeqSetup reads (one of `field_aliases`,
including an admin's field mappings), the import is refused with `ValueError`:

```
LIMS row <n> has the names <a> and <b>, which SeqSetup reads as one name. Send only one of them.
```

`<n>` is the row's 1-based position, as in the other row messages; `<a>` and `<b>` are
`repr(shown_value(...))`, in the row's order. Names SeqSetup does not read are not checked.

### Values of the wrong type

`_refuse_a_changed_value(what, value)` refuses anything that is not text or a whole number
(`bool` is refused; it is an `int` in Python). Today it refuses `bool` and `float` only. The
messages stay as they are, and a list, an object or any other type gets the `bool` message:

```
<what> that is not text or a whole number (<json>).
```

`<json>` is `shown_value(json.dumps(value))`.

`parse_api_samples` calls it for every field it reads in a row, before the value is
written, except the test and the test version, which keep their own checks and messages
(group A4). `<what>` is `LIMS row <n> has <label>`, with these labels:

| Field | Label |
|---|---|
| `sample_id` | `a sample ID` (today's call, unchanged) |
| `worksheet_id` | `a worksheet ID` |
| `index1_sequence` | `an i7 sequence` |
| `index2_sequence` | `an i5 sequence` |
| `index_pair_name` | `an index name` |
| `index1_name` | `an i7 name` |
| `index2_name` | `an i5 name` |
| an admin's own mapped field | `a value for <field>` |

A value that passes is written as `str(val).strip()[:256]`: the `if val else ""` goes, so a
whole number `0` is `"0"`. A `null` gives way to the next name, as today.

## §2 Kit swaps (`routes/samples.py`)

A kit's read patterns are the pair (`default_read1_override or None`,
`default_read2_override or None`). An assignment of only an i7 or only an i5 (slot `"i7"` or
`"i5"`) to a sample that keeps the other index — an i5 for an i7 assignment, an i7 for an i5
assignment, in the pair or on its own — and whose read patterns
(`read1_override_pattern or None`, `read2_override_pattern or None`) differ from the new
kit's is refused.

Where: `assign_index` (`POST /runs/{run_id}/samples/{sample_id}/assign-index`),
`assign_index_to_selected` (`POST /runs/{run_id}/samples/assign-index-to-selected`) and
`assign_indexes_bulk` (`POST /runs/{run_id}/samples/assign-indexes-bulk`). Each checks every
sample it would change before it changes any, and refuses the whole request with HTTP 400
and the message; nothing is saved. A pair assignment works as today. The fill
(`POST /runs/{run_id}/index-fill`) gives indexes only to samples with none (`needs_index`),
so it cannot meet this and does not change.

The message, one for the request:

```
These samples keep an index from a kit that reads Read 1 and Read 2 differently from <kit> (<kit>: Read 1 <r1>, Read 2 <r2>): <ids>. Assign both indexes from one kit, or clear these samples' indexes first.
```

`<kit>` is the new kit's name; `<r1>`/`<r2>` its patterns, `plain` for none; `<ids>` the
sample IDs as `name_list` gives them.

## §3 The Sample Sheet

### `IndexOrientation` in a BCLConvert profile (`services/sheet_text.py`)

`I5_RULE_SETTINGS` gains `IndexOrientation`. Nothing else changes: the sync
(`services/profile_validator.py:327`) refuses a BCLConvert profile that sets it in any mix
of capitals, and the writer (`services/samplesheet_v2_exporter.py:590`) refuses one already
stored, with today's messages.

### Mismatch cells for an index the sample does not have (`services/samplesheet_v2_exporter.py`)

In `_write_application_section`, the `BarcodeMismatchesIndex1` cell of a sample with no i7
(`not sample.index1_sequence`) is `na`, and the `BarcodeMismatchesIndex2` cell of a sample
with no i5 (`not sample.index2_sequence`) is `na`, whatever the sample's own number or the
profile's Data default. A sample with that index is written as today. The fallback writer
(`_write_bclconvert_data`, used only when no profile stores are given) does not change.

### Mismatch numbers in a profile's Settings (`services/sheet_plan.py`)

A new sheet-plan problem, `mismatch_setting_without_index`, in the BCLConvert part of
problem 8: a section whose profile's `Settings` has `BarcodeMismatchesIndex1` and a sample
with no i7, or `BarcodeMismatchesIndex2` and a sample with no i5. One problem per profile and
column:

```
BCLConvert profile <label> sets <column> for the whole run in its Settings, but <n> sample(s) have no <i7|i5>: <ids>. DRAGEN takes <column> in Settings only when every sample has that index. Move <column> from the profile's Settings to its DataFields, or put these samples in another run.
```

### No lane splitting with a Lane column (`services/sheet_plan.py`)

A new sheet-plan problem, `no_lane_splitting_with_lane`: a BCLConvert section whose
columns include `Lane` and where `NoLaneSplitting` is on. It is on when the profile's
`Settings` has `NoLaneSplitting` and its written cell, ignoring capitals, is not `false` or
`0`; when the profile does not set it, when the run's `no_lane_splitting` is true (the
writer's rule, `samplesheet_v2_exporter.py:581-586`). One problem per profile:

```
BCLConvert profile <label> has a Lane column, and NoLaneSplitting is true (<where>). DRAGEN 4.3 converts a run without lane splitting only when the Sample Sheet has no Lane column. Set NoLaneSplitting to false, or use a BCLConvert profile without a Lane column.
```

`<where>` is `in the profile's Settings` or `the run's setting`.

Both problems are sheet-plan problems, so the checks show them and Mark Ready refuses, as
for the other problems (group A3). `NoLaneSplitting,false` next to a Lane column stays as
today.

## §4 Tests

TDD: each rule gets a failing test first, valid and refused cases.

- LIMS: a repeated name in the `{sample: test}` form, in a report, nested deeper, and in the
  worklist list; a reply without one is read as today. Capitals: `SampleID` + `sampleid`
  refused; a name SeqSetup does not read, twice in different capitals, passes. Types: each
  label in the table with a decimal, `true`, a list and an object; whole numbers and text
  pass; `0` is `"0"`; the test and version messages are unchanged (group A4's tests stay).
- Kit swaps: on each of the three routes, a UMI kit's i7 and i5, then an i5 (and an i7) from
  a plain kit → 400, the message, nothing saved; the same swap between two kits with the
  same patterns → as today; a pair assignment → as today. `TestReplacingOneIndexKeepsTheOthersSettings`
  (`tests/integration/test_group_a1.py:210-242`) changes: its two kits get the same read
  patterns, so it keeps testing what it is for (each route passes the slot it assigned).
- Sheet: `IndexOrientation` refused at sync and by the writer, in two spellings; a
  single-index sample in a dual-index run gets `na` in `BarcodeMismatchesIndex2`, a dual one
  keeps its number; `mismatch_setting_without_index` for each column, and none when every
  sample has the index; `no_lane_splitting_with_lane` from the run and from the profile,
  none with `false`/`0` or without a Lane column; Mark Ready refuses with each.
- Break tests: each new check, removed or inverted, turns a test red.
- Today's sheets: the plan measures which of the 78 sheets change; only the mismatch cells
  of samples without that index may differ.
- The server suite, the browser suite and the docs build (`-W`) stay green.

## §5 Docs

- `docs/admin-guide/profiles.rst`, `docs/admin-guide/instruments.rst`,
  `docs/architecture/services.rst`: `IndexOrientation` in the list of refused BCLConvert
  `Settings`; the two new Mark Ready problems.
- `docs/admin-guide/sample-api.rst`: a repeated name refuses the reply; every field read is
  text or a whole number.
- `docs/user-guide/index-assignment.rst`: a swap between kits with different read patterns
  is refused.
- `docs/user-guide/export.rst`, `docs/architecture/samplesheet-format.rst`: `na` in the
  mismatch cell of a sample without that index; no lane splitting needs a sheet without a
  Lane column.
- No doc picture is expected to change; the plan checks it.

## §6 Rollout

SeqSetup has never been deployed. Runs already Ready keep their stored sheets. A Draft gets
the new cells and checks at its next Mark Ready. A stored profile with `IndexOrientation`
stops Mark Ready until the lab removes it and syncs, as for the other four names.

## Later list (from this design)

- Allow `NoLaneSplitting` with a Lane column on DRAGEN 4.4.6 and later, gzip output only.
- Two different names for one field in a LIMS row (`SampleID` and `sample_id`): the first
  alias found wins (measured: `P2`).
- A LIMS value longer than 256 characters is cut, not refused (measured: 300 → 256).
- The fallback sheet writer (`_write_bclconvert_data`) keeps writing mismatch numbers for
  an index a sample does not have; no app route uses it.
