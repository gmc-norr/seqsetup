# Group A1: every sample gets the right index — design

Date: 2026-10-03. Branch `fix/group-a1`, from `main` at `6e90006`.

## Why

A read-only project review of `main` at `6e90006` (2026-10-03) found three ways a sample
can end up with the wrong index or lose a row, and two hard rules from `CLAUDE.md` that no
test protects. Each was reproduced by running it.

1. **Dragging several indexes at once assigns them by position** (review DI-02). The page
   sends only the sample it was dropped on (`start_sample_id`); the server then fills the
   next rows of `run.samples` from there (`routes/samples.py`, `assign_indexes_bulk`). If
   another tab deleted or added a sample in between, the indexes land on other patients
   than the page showed. Measured: the page showed PAT1–PAT4, another tab deleted PAT2,
   and dragging P0, P1, P2 onto PAT1 gave PAT1←P0, **PAT3←P1, PAT4←P2**. No collision
   follows, so Mark Ready passes. ("Fill in order" is safe: it signs its plan and refuses
   a changed run with 409.)
2. **A new kit leaves the old kit's settings behind** (review DI-09 / S-3, found by two
   reviewers). `_apply_kit_defaults` copies a kit's `default_index1_cycles`,
   `default_index2_cycles`, `default_read1_override` and `default_read2_override` onto the
   sample only when the kit has them; it never empties them. `Sample.clear_index` does not
   empty them either. Measured: assign from a UMI kit (`U8Y*`, 8 index cycles), then from
   a plain 10 bp kit — the sample keeps `index1_cycles = 8` and `U8Y*`, and the Ready
   sheet says `U8Y143;I8N2;I8N2;…`: BCL Convert trims 8 real bases from every read as a UMI
   and reads only 8 of the 10 index bases. These four fields are set nowhere else: no page
   has a box for them.
3. **A LIMS worklist that lists one sample ID twice loses a row** (review DI-01). The
   import keeps the first row and drops the second, then reports it as "Skipped 1
   duplicate(s) already in run". A paste with the same rows is refused outright.
4. **The LIMS client's certificate check and 10 MB size cap have no test** (review H-4).
   Switching `ssl.create_default_context()` to an unverified context and turning the size
   check off left every unit test and every LIMS-related integration test passing. The
   LIMS tests replace `_api_get` as a whole, so its body never runs in a test.

## Decisions

Approved by the user on 2026-10-03 as presented (all four take the conservative,
already-established behaviour):

1. A multi-index drop is refused, and nothing is assigned, when the rows it would fill are
   not the rows the page showed.
2. Assigning from a kit **replaces** the sample's kit settings with that kit's own (empty
   when the kit has none); clearing an index empties them.
3. A worklist with a repeated sample ID is refused as a whole, like a paste.
4. The certificate check and the size cap get tests; their code does not change.

## 1. Multi-index drop

- `app.js` already works out the rows a drop will fill for its replace warning
  (`multiDropWarning`: the `.sample-row`s of `#sample-table` from the drop row on, one per
  dragged index). `handleIndexDrop` computes that list once, uses it for the warning, and
  sends the rows' sample ids with the request as `target_sample_ids` (a JSON array of
  strings, in page order).
- `assign_indexes_bulk` reads `target_sample_ids`. It must be a JSON array of strings;
  otherwise the request is refused with 400 and the text
  `This page is out of date. Reload the page and drag again.`
- The server works out the rows it would fill exactly as today: the samples of
  `run.samples` from the start sample on, one per index, stopping at the end of the run.
  If their ids are not exactly `target_sample_ids`, in the same order, the request is
  refused with **409** and the text
  `The sample list changed since this page was loaded. Reload the page and drag again.`
  Nothing is assigned and the run is not saved.
- Everything else is unchanged: the index checks that already run before any change, the
  start-sample-not-found 404, the "last indexes not used" behaviour when the run has fewer
  rows than indexes, the audit event and the response.
- The only page that sends this request is the run page's sample table
  (`wizard/_sample_table.html`), which lists `run.samples` in order with no sorting or
  filtering; `wizard/_new_samples_table.html` is not rendered anywhere. So a drop from an
  unchanged page always matches.
- The page shows the 409 and 400 texts the way it shows every refused request: the
  existing handler for failed HTMX requests in `app.js` puts the response text in the
  red `#error-banner` and raises an error toast; the table is left as it is.

## 2. Kit settings on assign and clear

`_apply_kit_defaults(sample, kit)` becomes `_apply_kit_defaults(sample, kit, slot)`, with
`slot` one of `"pair"`, `"i7"`, `"i5"` — what was just assigned:

| slot | `index1_cycles` | `index2_cycles` | `read1_override_pattern`, `read2_override_pattern` |
|---|---|---|---|
| `pair` | the kit's default (None if none) | the kit's default (None if none) | the kit's defaults (None if empty) |
| `i7` | the kit's default (None if none) | unchanged | the kit's defaults (None if empty) |
| `i5` | unchanged | the kit's default (None if none) | the kit's defaults (None if empty) |

- The read patterns follow the last kit assigned from, as `index_kit_name` already does.
- Every caller passes its slot: the single assign (pair, and i7/i5), assign to selected
  samples, the multi-index drop, and "Fill in order" (pair, or i7 in single mode). Each
  already recomputes OverrideCycles right after; that is unchanged.
- `Sample.clear_index()` also empties all four fields. `clear_index1()` empties
  `index1_cycles`, and the read patterns when no i5 is left; `clear_index2()` empties
  `index2_cycles`, and the read patterns when no i7 is left (the same rule they already
  use for `index_kit_name`).
- A typed OverrideCycles is handled as today.

## 3. Repeated sample IDs in a worklist

- `parse_api_samples` (`services/sample_api.py`) refuses a worklist in which one sample ID
  (after its usual clean-up) appears more than once. After its existing checks it raises
  `ValueError` with the text
  `these sample IDs appear more than once in the worklist: <ids>. Nothing was added.`
  — `<ids>` is the repeated IDs in first-seen order, the first 10 then `and N more`,
  written the way the paste message writes them.
- The import route already turns a parser `ValueError` into the error banner
  `Worklist import rejected: <text>` and adds nothing; that is unchanged.
- A worklist sample whose ID is already in the run is still skipped with
  "Skipped N duplicate(s) already in run.", as today and as paste does.

## 4. Tests for the LIMS client's two hard rules

Unit tests that run `_api_get`'s real body, with `_validate_url` replaced so it returns a
public address and the connection class replaced by a fake (no network):

- an `https` URL connects with an SSL context whose `verify_mode` is `CERT_REQUIRED` and
  whose `check_hostname` is true;
- a response one byte over 10 MB raises `SampleApiError` ("exceeds maximum size limit");
  a response of exactly 10 MB is read.

## Docs

- `docs/user-guide/index-assignment.rst`, *Selecting several indexes in order*: if the
  sample list changed since the page was loaded (another tab or person), the drop is
  refused with the message; reload and drag again.
- The same page: assigning from a kit replaces the sample's index lengths and read
  patterns with the new kit's own; clearing the index empties them.
- `docs/user-guide/samples.rst` (worklist import) and `docs/admin-guide/sample-api.rst`:
  a worklist that lists one sample ID twice is refused as a whole.
- No picture changes.

## Tests

Unit:
- `_apply_kit_defaults` for each slot, from a kit with all four defaults and from a kit
  with none; `clear_index`, `clear_index1`, `clear_index2` (with and without the other
  index left).
- `parse_api_samples`: a repeated ID is refused with the message; 12 repeated IDs show 10
  and "and 2 more"; IDs that differ only before clean-up (`" P1"` and `"P1"`) count as
  repeated; a worklist with no repeats is unchanged.
- The two LIMS client tests above.

Integration (the real routes):
- Multi-index drop after another request deleted a row in between: 409 with the message,
  no sample changed, the run not saved. The same drop with the row added instead: 409.
- Multi-index drop from an unchanged page: assigned as today; without
  `target_sample_ids`: 400. The one existing integration test class that posts this
  route directly (`TestAssignSeveralInOrder` in
  `tests/integration/test_index_assign_kit_version.py`) changes only to send
  `target_sample_ids` (the rows from `s1` on); what it checks does not change.
- Assign from a UMI kit, then from a plain kit, through each assign route (single pair,
  single i7, assign to selected, multi-index drop, Fill in order): the sample's four kit
  fields and OverrideCycles are the plain kit's; Mark Ready writes the plain OverrideCycles
  into the sheet. Assign, clear, assign plain: the same.
- Worklist import (the LIMS fetch replaced, no network) with a repeated ID: refused with
  the message, nothing added; without repeats: imported as today.

Browser: the existing multi-index drop tests (`test_multi_index_drop.py`,
`test_kit_version_assign.py`, `test_bulk_lane_panel_swap.py`) keep passing with the new
field.

Break tests (in the plan): each new check removed in turn must turn a test red.

## Rollout

SeqSetup has never been deployed. No stored data changes. A sample already holding an
old kit's settings keeps them until its index is assigned again or cleared.

## Not in this change

- If another tab assigns an index to a row this page showed as empty, a multi-index drop
  replaces it without the "replace?" warning (the patient is still the right one).
- The unreachable per-row "clear index" button on the run page (F9, group 4).
- Sample IDs already in the run are still skipped, not refused (the same as paste).
- The rest of the review's group A (A2: i5 direction; A3: the sheet's shape at Mark Ready)
  and groups B–E.
