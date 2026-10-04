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
   check off left every unit test and every LIMS-related integration test passing. No
   test runs `_api_get` past its URL check (one, in `test_audit_trail_visible.py`, stops
   there); the LIMS tests replace it as a whole.

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
  sends the rows' ids with the request as `target_sample_ids` (a JSON array of strings,
  in page order). These are the rows' internal ids (`Sample.id`, the row's
  `data-sample-id`, the same kind of id `start_sample_id` already carries), not the
  Sample ID the lab typed.
- `assign_indexes_bulk` reads `target_sample_ids`. It must be a JSON array of strings;
  otherwise the request is refused with 400 and the text
  `This page is out of date. Reload the page and drag again.`
- The server works out the rows it would fill exactly as today: the samples of
  `run.samples` from the start sample on, one per index, stopping at the end of the run.
  If their ids are not exactly `target_sample_ids`, in the same order, the request is
  refused with **409** and the text
  `The sample list changed since this page was loaded. Reload the page and drag again.`
  Nothing is assigned and the run is not saved.
- Order: the new checks run after every dragged index has been looked up and checked
  (today's checks, unchanged), at the point where today's code starts assigning, before
  the first change. So a request that today's checks refuse is still refused by them,
  with their own message.
- Rows are only ever added at the end of the run (`SequencingRun.add_sample`) and never
  reordered, so a row added since the page loaded is refused only when the drop reaches
  past the end of the page's table; a drop that ends inside the table still fills exactly
  the rows the page showed and goes ahead.
- Everything else is unchanged: the start-sample-not-found 404, the "last indexes not
  used" behaviour when the run has fewer rows than indexes, the audit event and the
  response.
- The only page that sends this request is the run page's sample table
  (`wizard/_sample_table.html`), which lists `run.samples` in order with no sorting or
  filtering; `wizard/_new_samples_table.html` is not rendered anywhere. So a drop from an
  unchanged page always matches.
- The page shows the 409 and 400 texts the way it shows every refused request: the
  existing handler for failed HTMX requests in `app.js` puts the response text in the
  red `#error-banner` and raises an error toast; the table is left as it is.

## 2. Kit settings on assign and clear

Each of the four kit settings belongs to an index: `index1_cycles` to the sample's i7,
`index2_cycles` to its i5, and the two read patterns (`read1_override_pattern`,
`read2_override_pattern`) to the sample's index as a whole. An i7 or i5 counts whether it
sits in a pair (`index_pair`) or on its own (`index1`, `index2`). Two rules:

**Rule 1 — an assign takes the kit's own values.** `_apply_kit_defaults(sample, kit)`
becomes `_apply_kit_defaults(sample, kit, slot)`, with `slot` one of `"pair"`, `"i7"`,
`"i5"` — what was just assigned. It sets the settings of what was assigned to the kit's
own values, and to None when the kit has none:

| slot | `index1_cycles` | `index2_cycles` | read patterns |
|---|---|---|---|
| `pair` | the kit's default | the kit's default | the kit's defaults |
| `i7` | the kit's default | rule 2 | the kit's defaults |
| `i5` | rule 2 | the kit's default | the kit's defaults |

**Rule 2 — no index, no setting.** After every assign and every clear, a setting whose
index is gone is emptied: `index1_cycles` when the sample has no i7, `index2_cycles` when
it has no i5, and both read patterns when it has no index at all. This lives in the
model: a private `Sample` method called at the end of `assign_index1`, `assign_index2`,
`clear_index1` and `clear_index2`; `clear_index` empties all four. The route calls
`_apply_kit_defaults` after the model's assign, as today, so rule 1 has the last word for
what was just assigned.

What this means in practice:
- An i7 from a single-index kit over a dual pair (a multi-index drop that replaces, or
  assign to selected): `assign_index1` removes the pair, so no i5 is left and
  `index2_cycles` is emptied. Measured on the spec as first written (`i7` leaving
  `index2_cycles` unchanged): the old UMI kit's 8 stayed, the sheet said
  `Y151;I10;I8N2;Y151` with an empty Index2 column, and validation found 0 errors.
- An i7 assigned next to a separate i5 (combinatorial) leaves that i5's `index2_cycles`
  alone; the i5 is still there.
- `clear_index1` on a sample that holds a pair changes none of the four settings: the
  pair, and with it the i7, is still there (as today). On a sample with only an i7 it
  empties all four.
- The read patterns follow the last kit assigned from, as `index_kit_name` already does.
- Every caller passes its slot: the single assign (pair, and i7/i5), assign to selected
  samples, the multi-index drop, and "Fill in order" (its plan's mode: pair, or i7 for a
  single-index kit). Each already recomputes OverrideCycles right after; that is
  unchanged.
- A typed OverrideCycles is handled as today.

## 3. Repeated sample IDs in a worklist

- `parse_api_samples` (`services/sample_api.py`) refuses a worklist in which one sample ID
  (after its usual clean-up) appears more than once. After its existing checks it raises
  `ValueError` with the text
  `these sample IDs appear more than once in the worklist: <ids>. Nothing was added.`
  — `<ids>` is the repeated IDs in first-seen order, the first 10 then `and N more`,
  written the way the paste message writes them. The paste message uses `_name_list` in
  `routes/samples.py`; a service must not import from a route, so `_name_list` moves
  unchanged to `services/sample_api.py` and `routes/samples.py` imports it from there
  (one format, one place).
- The import route already turns a parser `ValueError` into the message
  `Worklist import rejected: <text>` and adds nothing; that is unchanged. (On the page
  this message takes the place of the sample table, because the Import button targets
  `#sample-table`; that is unchanged too.)
- A worklist sample whose ID is already in the run is still skipped with
  "Skipped N duplicate(s) already in run.", as today and as paste does.

## 4. Tests for the LIMS client's two hard rules

Unit tests that run `_api_get`'s real body **and** the real
`_PinnedHTTPSConnection.connect()` — the certificate check happens there, in
`wrap_socket(..., server_hostname=...)` — with no network:

- `_validate_url` is replaced so it returns a public address;
- `socket.create_connection` is replaced by a fake socket that plays back a canned HTTP
  response;
- `ssl.SSLContext.wrap_socket` is wrapped by a spy that records the context and
  `server_hostname` it was called with, then hands back the fake socket.

Tests:
- an `https` URL goes through `wrap_socket`, with a context whose `verify_mode` is
  `CERT_REQUIRED` and whose `check_hostname` is true, and with `server_hostname` set to
  the URL's host;
- a response one byte over 10 MB raises `SampleApiError` ("exceeds maximum size limit");
  a response of exactly 10 MB is read;
- the body is read with a bound: with a 20 MB response, the fake records how much it was
  asked for, and it is never more than 10 MB + 1 byte.

Each of these changes, made in turn, must turn at least one of these tests red: the
context made unverified; the `wrap_socket` line removed (the api-key would go out in
clear); the size check removed; the read made unbounded (`response.read()`). Measured on
the first version of these tests (a fake connection class): the second and fourth
changes left them green.

## Docs

- `docs/user-guide/index-assignment.rst`, *Selecting several indexes in order*: if the
  sample list changed since the page was loaded (another tab or person), the drop is
  refused with the message; reload and drag again.
- The same page, *Kit defaults*: today it says the kit's defaults "are copied onto the
  sample". It will say that assigning from a kit replaces the sample's index cycles and
  read patterns with that kit's own (empty when the kit has none), and that an index
  removed by the assign (an i7 replacing a pair takes the pair's i5 with it) takes its
  index cycles with it. Nothing about clearing: this page has no clear button (the page
  says so).
- `docs/user-guide/samples.rst` (worklist import) and `docs/admin-guide/sample-api.rst`:
  a worklist that lists one sample ID twice is refused as a whole.
- No picture changes.

## Tests

Unit:
- `_apply_kit_defaults` for each slot, from a kit with all four defaults and from a kit
  with none. Every case starts from a sample that already holds another kit's values
  (all four set, and different from the new kit's), so "set to None" and "left alone"
  cannot look the same.
- Rule 2 in the model: `assign_index1` over a pair empties `index2_cycles`;
  `assign_index2` over a pair empties `index1_cycles`; `assign_index1` next to a separate
  i5 keeps `index2_cycles`; `clear_index` empties all four; `clear_index1` and
  `clear_index2` on a sample with only that index empty all four; on a sample that keeps
  the other index they keep its cycles and the read patterns; on a pair sample they
  change none of the four.
- `parse_api_samples`: a repeated ID is refused with the message; 12 repeated IDs show 10
  and "and 2 more"; IDs that differ only before clean-up (`" P1"` and `"P1"`) count as
  repeated; a worklist with no repeats is unchanged.
- The two LIMS client tests above.

Integration (the real routes):
- Multi-index drop after another request deleted a row in between: 409 with the message,
  no sample changed, the run not saved.
- A row added past the window: the page showed PAT1–PAT3, three indexes are dropped on
  PAT2 (the page sends PAT2, PAT3), PAT4 was added since → 409, nothing changed. Today the
  third index would land on PAT4, a patient the page never showed.
- A row added after the window: the page showed PAT1–PAT4, two indexes dropped on PAT1,
  PAT5 added since → assigned as today (PAT1, PAT2).
- Multi-index drop from an unchanged page: assigned as today; without
  `target_sample_ids`: 400. The one existing integration test class that posts this
  route directly (`TestAssignSeveralInOrder` in
  `tests/integration/test_index_assign_kit_version.py`) changes only to send
  `target_sample_ids`: exactly the rows its entries would fill, one per entry, from `s1`
  on. Its two refusal tests also check their own response text, so the new 409 cannot
  stand in for the refusal they test (measured: sending `["s1", "s2"]` for one entry,
  with the kit-version refusal removed and the new check run first, the test stayed
  green).
- Assign from a UMI kit, then from a plain kit, through each assign route (single pair,
  single i7, assign to selected, multi-index drop): the sample's four kit fields and
  OverrideCycles are the plain kit's; Mark Ready writes the plain OverrideCycles into the
  sheet.
- A UMI pair, then an i7 from a single-index kit (multi-index drop, and assign to
  selected): `index2_cycles` is empty and the sheet's OverrideCycles reads the i5 cycles
  as `N` (for a 151+10+10+151 run: `Y151;I10;N10;Y151`).
- Fill in order: it only fills rows with no index, and after this change clearing
  already empties the four fields, so it is tested on a stored sample that has no index
  but still holds an old kit's four values (written straight into the stored run, as a
  sample saved before this change can be): after Fill, they are the new kit's.
  (Measured: an "assign, clear, Fill" test stays green with Fill's change undone; it
  proves the clear, not the Fill.)
- Worklist import (the LIMS fetch replaced, no network) with a repeated ID: refused with
  the message, nothing added; without repeats: imported as today.

Browser:
- The existing multi-index drop tests (`test_multi_index_drop.py`,
  `test_kit_version_assign.py`, `test_bulk_lane_panel_swap.py`) keep passing with the new
  field, and so does `test_docs_screenshots.py::test_indexes_several_in_order` (it only
  runs under `pixi run docs-screenshots`; run it on purpose).
- New: a drop on a middle row assigns from that row on (every existing browser drop that
  posts starts on the first row, so none of them checks the list the page sends).
- New: a drop after the run changed behind the page shows the 409 text in
  `#error-banner` and leaves the table as it was.

Break tests (in the plan): each new check removed in turn must turn a test red.

## Rollout

SeqSetup has never been deployed. No stored data changes. A sample already holding an
old kit's settings keeps them until its index is assigned again or cleared.

## Not in this change

- If another tab assigns an index to a row this page showed as empty, a multi-index drop
  replaces it without the "replace?" warning (the patient is still the right one).
- The unreachable per-row "clear index" button on the run page (F9, group 4).
- Sample IDs already in the run are still skipped, not refused (the same as paste).
- A repeated sample ID in the other worklist format (`{"samples": {sample_id: test_id}}`)
  is lost while the JSON is read, before SeqSetup sees it (JSON keeps only the last of
  a repeated key), so the new check cannot catch it there. iGene, the lab's LIMS, sends a
  list of reports (`igene_openapi.json`), which the new check covers. Catching it would
  mean changing how every LIMS reply is read; it goes on the later list.
- The run page's **Load Worklists** button asks for `/runs//samples/worklists` (no page
  passes `run_id` to `wizard/_fetch_from_api_section.html`), which is a 404, so today the
  worklist import is reached only by posting to the route directly. Found while
  reviewing this spec; it fails safe (nothing is added), and it goes on the later list.
- The rest of the review's group A (A2: i5 direction; A3: the sheet's shape at Mark Ready)
  and groups B–E.
