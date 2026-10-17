# A change from a page that is out of date is refused, not applied

2026-10-17

## The defect

The run page's edit lock is held per user, so two browser tabs of the same
person both pass it. `get_editable_run` loads the run afresh on every request,
and `RunRepository.save`'s version check only catches a write that lands inside
one request. The client sent nothing about what it had on screen. So a bulk
Apply, or a delete, from a tab loaded before another tab's change overwrote or
removed that change with no word, and both requests look perfectly well formed:
nothing in the sample sheet, the Check panel or the index safety net can see it.

Lanes decide which lane a patient's reads land in, so a lane written from a
stale tab is a clinical defect, not a nuisance.

The single-row index routes already close this (outside review of `f490536`,
finding F8): the page sends the index each targeted row showed
(`target_indexes`, from `data-i7` / `data-i5` on the `<tr>`), the route compares
it with what is stored before writing anything, and refuses 409 naming the
samples. A request that sends no shown value is refused 400.

## What was decided (2026-10-17)

**Approach A — check only what you change.** Each action sends what the page
showed *for the field or fields it is about to change*, one entry per targeted
row, in the order the rows are sent. The route compares every entry with the
stored value before it writes anything, and when any targeted row's value has
moved it refuses with 409, writes nothing at all, and names the samples. A
request that sends no shown value is refused 400, exactly as F8 does — no real
client can send one, because `app.js` is served as `/js/app.js?v=<content hash>`,
so a browser cannot hold a pre-change script against post-change HTML.

A targeted sample the run no longer has is refused as well (409, "the sample list
changed"): four routes used to skip it without a word.

Rejected: **approach B**, a whole-row fingerprint or a run-wide version stamp. It
refuses changes that touch nothing the other tab touched, and it would have to be
threaded through F3's per-row typing queue.

`POST /runs/{run_id}/samples/{sample_id}` (`update_sample`) is left exactly as it
is: no page sends it — only tests do.

## Per route: what is sent, what is compared

Every field is JSON, a list with one entry per entry in `sample_ids`, in the same
order. Missing, unreadable, or of the wrong length → 400, nothing written.

| step | route | field sent | compared with | what the row carries |
|---|---|---|---|---|
| 1 | `POST …/samples/set-lanes` | `target_lanes`: `[[1,2], [1]]` | `sample.lanes` | `data-lanes="1,2"` |
| 2 | `POST …/samples/set-mismatches` | `target_mismatches`: `[["1","2"], ["",""]]` | `barcode_mismatches_index1/2`, **only the column the request writes** | the two boxes' `defaultValue` |
| 2 | `POST …/samples/set-override-cycles` | `target_override_cycles`: `["Y151;I8;I8;Y151", ""]` | `sample.override_cycles` ("" = None) | the box's `defaultValue` |
| 2 | `POST …/samples/set-test-id` | `target_tests`: `[["T","1"], ["",""]]` | `test_id`, `test_version` | `data-test-id`, `data-test-version` |
| 3 | `POST …/samples/bulk-delete` | `target_indexes` (F8's field) | `index1_sequence`, `index2_sequence` | `data-i7`, `data-i5` |
| 3 | `DELETE …/samples/{id}` | `target_indexes` | the same | the same |
| 4 | `POST …/samples/{id}/settings` | `target_setting`: the one box's value | the one field the box posts | the box's `defaultValue` |

Mismatch "Apply" leaves a blank box's column alone, so it compares only the
column it is about to write; "Clear" writes both, so it compares both.

`set-test-id` keeps its existing `only_if` check, which the Check page's fix
boxes use (spec 2026-10-07 group A4 §2): a fix box says what its samples lacked
when the page was loaded, and sends no `target_tests`. The bulk panel sends
`target_tests` and no `only_if`; a request with neither is refused.

A field whose row has a box of its own (the two mismatch columns and Override
Cycles) is **not** carried in a `data-*` attribute: that box saves with
`hx-swap="none"` (F3, a row save keeps typing), so the row is not redrawn and
the attribute would go stale and refuse a page where nothing had changed. The
page reads those from the box's `defaultValue`, which `app.js` sets to the
stored value on every answer. And because clicking a panel button is what blurs
a row box, the Mismatches and Override Cycles actions wait for the row's saves
to be answered before they read the boxes (`whenRowSavesAreAnswered`); F3's
queue, its `hx-swap="none"` and its waiting actions are untouched.

Step 4's box is F3's code too: its shown value is read from `defaultValue` when
the request is issued, not when it is queued.

## The message

F8's shape, because the error banner shows the first 300 characters and ten
25-character LIMS sample IDs are 268 of them: **what to do first, then the IDs.**

- 409: `<Nothing was saved.> Reload the page and try again. The <field> on these
  samples changed since this page was loaded: <IDs>.`
- 400 (no shown value): `This page is out of date. Nothing was saved. Reload the
  page and try again.`
- 409 (a targeted sample is gone): `The sample list changed since this page was
  loaded. Reload the page and try again.` — the two deletes add `Nothing was
  deleted.` before the last sentence: after a Delete Selected of five rows, the
  shared sentence alone does not say whether the other four went (first review
  of step 3, Minor 2).

The deletes compare the **index only**, not the lanes, test, Override Cycles or
mismatches: the sample's identity is its row id (a uuid4) and no page renames a
Sample ID, so the person always deletes the sample they clicked. The index is
what tells them the row is not the one they looked at.

## What proves it

Per step, integration tests that

- the stale post is refused 409, with that message, and **nothing stored
  changed** (every field of every sample read back);
- the fresh post still works, including a second action after the page's own
  earlier change — the answer re-renders the rows, so their shown values are the
  new stored ones;
- a post that sends no shown value, an unreadable one, or one of the wrong
  length is refused 400 and writes nothing;
- a targeted sample the run no longer has is refused 409;

and browser tests that drive two tabs — the stored run is changed behind the
page, as another tab's request would leave it — and check the banner's text, the
field the page actually sent, and the stored values.

Break rows (`harness/rows_<step>.py`) delete each guarantee one at a time: no
comparison at all, the wrong field compared, the page not sending the shown
value, a missing value accepted, a vanished sample skipped, the refusal writing
anyway, and the message losing the sample IDs.
