# Later list, slice 2: the LIMS import works, and its preview shows what it will add — design

Date: 2026-10-10. Base: main `0a9fa12` (later-list slice 1 merged, not pushed). Branch
`fix/later-2`. Source: the later list kept with slice 1 (its item 9, "Load Worklists" asks
`/runs//samples/worklists`; item 14, the preview has no version column) and the slice 1
build's ESCALATE-2 (a worksheet ID sent as a JSON decimal). Decisions: the user, in this
brainstorm (2026-10-10). A review of the first version (`5c6ccd2`) found one P1, three P2s
and one P3; each was reproduced on `0a9fa12` and is folded in here (marked "review of
`5c6ccd2`").

## Why

The LIMS import cannot be reached from the app today, and once it can, it would show and do
the wrong things. Each point was measured on `0a9fa12` (MongoDB at `127.0.0.1:1`, mongomock
for the stores, the LIMS calls replaced by test doubles):

1. **The button asks an address that does not exist.** The run page
   (`routes/main.py:192`) gives the template no `run_id`, and
   `templates/runs/_sample_section.html:38-41` includes the LIMS box with
   `context=''` and `existing_ids=''` only. The page has
   `hx-get="/runs//samples/worklists"`, and that address answers **404**.
2. **A worksheet ID sent as a JSON number is changed.** `fetch_worklists`
   (`services/sample_api.py:384`) reads the ID with `_get_field_value` (`:348`), which
   writes `str(value)`. The dropdown then lists, and the import then fetches, another
   ID:

   ```
   {"id": 25.10}  -> listed as 25.1      {"id": true}   -> listed as True
   {"id": ["a"]}  -> listed as ['a']     {"id": 7}      -> 7 (as today)
   {"id": "25.10"} -> 25.10 (as today)
   ```

   A worksheet called `25.10` in the LIMS and sent as a number would bring in worksheet
   `25.1`'s patients, if the LIMS has one.
3. **After an import the page shows the samples section twice.** "Import Samples"
   (`templates/wizard/_worklist_selector.html:16-17`) swaps its answer in place of
   `#sample-table` (`outerHTML`), but the route (`routes/samples.py:896`) answers with the
   whole `#sample-section` (and the banner, out of band). The section lands inside itself:
   two sample sections and two paste forms (one table, the new one). The saved run is
   right; the page is not.
4. **An import that is refused wipes the table off the page.** Every refusal of the import
   route (`_messages_only`, `routes/samples.py:106`) is a plain 200 message, swapped into
   the same `#sample-table` slot: a repeated sample ID answers 200, no `HX-Retarget`, body
   `<p class="error-message">Worklist import rejected: these sample IDs ap…`.
5. **The preview does not show what the import will add.** It shows the rows as the LIMS
   sent them (`templates/wizard/_worklist_preview.html`), by two names only (`sample_id` or
   `SampleID`, `test_id` or `TestID`), the first 20 rows, and no version:
   - a row `{"Sample": "P1", "Test": "WGS", "test_version": "1"}`, which the import reads
     as sample P1, test WGS, version 1, previews as `-`, `-`;
   - 25 rows preview as 20 and "... and 5 more samples";
   - a worksheet the import refuses (the same sample ID twice) previews as two normal rows.
6. **The import never sees the worksheet that was picked** (review of `5c6ccd2`). "Import
   Samples" posts `worklist_id` in the form body (`hx-post` with
   `hx-include="#worklist-select"`), but `import_worklist_samples` reads `worklist_id` from
   the query string. A form-body post answers 200 `No worklist selected.` and asks the LIMS
   nothing; only a query-string post (as the existing tests send) imports. The preview is a
   GET, so its `worklist_id` is in the query string and arrives.
7. **A worksheet entry with two spellings of its ID name lists one of them, with no
   warning** (review of `5c6ccd2`). `_get_field_value` lower-cases the names, and the last
   one wins: `{"Worksheet_ID": "W_A", "WORKSHEET_ID": "W_B"}` lists `W_B`; so do an admin's
   `AL` sent as `{"Al": "W_A", "al": "W_B"}`, and `{"Id": "W_A", "ID": "W_B"}`. Both values
   pass a type check. Slice 1's check of a repeated name (`_api_get`) catches only the same
   name exactly.
8. **The worksheet a row is written with can come from the pick** (review of `5c6ccd2`). A
   row whose worksheet ID is `null` (`worksheet_id` or `Worksheet_ID`) has none after
   `parse_api_samples`, and the import gives it the picked worksheet
   (`routes/samples.py:832`): `[{"sample_id": "P1", "worksheet_id": null}]` imported from
   `WS9` is stored with worksheet `WS9`.

## Decisions

1. **Scope** (the user, "1"): the import is made to work and to be safe — the button, the
   page after an import, the worksheet ID's type — and the preview shows exactly what the
   import would add, or its refusal.
2. **A worksheet whose ID is not text or a whole number is left out of the dropdown, with a
   warning that names it** (the user, "1"). The other worksheets are listed. A worksheet
   that is not in the dropdown cannot be picked, so it cannot bring in other patients, and
   one bad entry does not block the lab's other worksheets. The same holds for a worksheet
   entry with two spellings of a name its ID is read from (review of `5c6ccd2`): SeqSetup
   cannot tell which one the LIMS meant.
3. **One plan for the preview and the import.** One function reads the rows (with
   `parse_api_samples`, all its checks), builds the samples the import would add, lists
   the sample IDs already in the run (skipped, as today) and checks the run's sample
   maximum. The preview shows that plan; the import saves it. They cannot disagree about
   the same reply.
4. **The import's refusals keep their text and kind, answer 400, and are sent to the page's
   error banner** (`HX-Retarget: #error-banner`, `HX-Reswap: innerHTML`,
   `HX-Reselect: unset`, as `middleware.py`'s `_banner`). The samples section stays as it
   was. Its success answer does not change. Why 400 and not today's 200 (review of
   `5c6ccd2`): `static/js/app.js` treats an answer of 400 or more with `HX-Retarget` as an
   error — swapped into the banner, an error toast raised, the button remembered — while a
   200 from a button whose last request failed clears the banner *after* the swap, so a
   refusal right after, say, an expired sign-in would vanish.
5. **The import reads the worksheet from the form body** (review of `5c6ccd2`), as the page
   sends it; not from the query string.
6. **The preview needs the run** (to know which sample IDs are in it), so it takes
   `get_editable_run`, as the import does: a draft only. The LIMS box is shown on drafts
   only.
7. **Nothing else about the import changes**: it fetches the worksheet again (the preview is
   a look, not a lock); new samples start in lane 1 (as a paste does by default); a sample
   ID already in the run is skipped with today's warning.

## §1 The button (`templates/runs/_sample_section.html`)

The LIMS box is included with the run's ID: `{% with run_id=run.id, context='',
existing_ids='' %}`. Its buttons then ask `/runs/<run id>/samples/worklists`,
`.../preview-worklist` and `.../fetch-worklist`. The `add_step1` context of
`_worklist_selector.html` has no caller on main; it is left as it is.

## §2 The page after an import (`templates/wizard/_worklist_selector.html`, `routes/samples.py`)

- "Import Samples" swaps its answer in place of `#sample-section` (`outerHTML`), the element
  the route answers with. (The `add_step1` branch keeps `#worklist-import-result`.)
- `import_worklist_samples` reads `worklist_id` from the form body
  (`Annotated[str, Form()]`, default empty); `context` stays in the query string, as the
  page sends it.
- Every answer of `import_worklist_samples` that adds nothing because of a refusal or a
  failure — the sample API not configured or not enabled, no worksheet picked, the fetch
  failed, the rows refused, no valid samples, the run's sample maximum — is today's message,
  with today's text and kind, status 400, sent to `#error-banner` by the three headers
  above. One helper writes them (`_banner_only(request, messages)`).
- An import that adds nothing because every sample ID is already in the run answers as today
  (the section, and the warning in the banner).

## §3 Worksheet IDs (`services/sample_api.py`, `fetch_worklists`)

- The worksheet's ID is the value the list reads today: the admin's worksheet ID field (by
  the same lookup as `_get_field_value`: the mapped name, then in any capitals, then
  `worksheet_id`), and `id` when that is absent, `null` or blank.
- First, the names (review of `5c6ccd2`): the names an ID is read from are the admin's
  worksheet ID field (when mapped), `worksheet_id` and `id`. When two names of one entry are
  the same one of these once lower-cased (`Worksheet_ID` and `WORKSHEET_ID`; `Al` and `al`
  for a mapped `AL`; `Id` and `ID`), the worksheet is left out of the list with the warning
  `A worksheet in the LIMS list has the names '<a>' and '<b>', which SeqSetup reads as one
  name. Send only one of them. It is left out of the list.` (`<a>`, `<b>` in the order of
  the entry). This is checked for all three names, whichever one the ID is then read from.
- Then the value is checked by its JSON type with `_refuse_a_changed_value` (slice 1), before
  anything turns it into text. Text and whole numbers pass, written as today. A number with
  a decimal point, `true`/`false`, a list or an object: the worksheet is left out of the
  list, and a warning is kept for it.
- The warning is the helper's message for `what = "A worksheet in the LIMS list has an ID"`,
  then ` It is left out of the list.`:
  - `A worksheet in the LIMS list has an ID that is a number with a decimal point (25.1),
    which JSON may have changed (1.10 is read as 1.1). Send it as text, for example "1.10".
    It is left out of the list.`
  - `A worksheet in the LIMS list has an ID that is not text or a whole number (true). It is
    left out of the list.`
- `fetch_worklists` returns `(success, message, worksheets, left_out)`, `left_out` the
  warnings in the order of the list. When every worksheet is left out, `success` is false
  with today's message (`No valid worksheets found in API response`) and the warnings.
- `list_worklists` shows the warnings (kind `warning`) above the dropdown; when nothing is
  left to list, today's error message and then the warnings.
- The list's other fields (name, investigator, updated) are shown only, never used to fetch;
  they are read as today.

## §4 The preview is the import's plan (`routes/samples.py`, `templates/wizard/_worklist_preview.html`)

- `_plan_worklist_import(run, raw_rows, api_config, worklist_id)` returns
  `(new_samples, skipped_ids)`: the `Sample` objects the import would add, built exactly as
  the import builds them today (sample ID, test, version, worksheet, lane 1, indexes with
  their names and kit name, Override Cycles), and the sample IDs already in the run. A row
  with no worksheet ID after parsing (absent, `null` or blank, in any spelling) gets
  `worklist_id`, the worksheet that was picked, as today (review of `5c6ccd2`). It raises `ValueError` with
  today's text (without the `Worklist import rejected: ` prefix) when `parse_api_samples`
  refuses the rows, and `a run accepts a maximum of <cap> samples (run already has <n>).`
  when the run's maximum would be passed. It changes nothing.
- `import_worklist_samples` calls it and saves `new_samples` as today. Its messages are
  today's: `Worklist import rejected: <text>` (error), `No valid samples found in worklist.`
  (warning, when the plan has no rows at all), `Added …`, `Skipped …`.
- `preview_worklist` takes `get_editable_run`, fetches the worksheet, calls the same
  function, and shows:
  - when the plan is refused: `Importing this worksheet would be refused: <text>` (error),
    and no table;
  - otherwise `Worksheet <id>: <N> sample(s) to add`, a table of every sample to add (in a
    scroll box, no row limit) with Sample ID, Test, Version, i7, i5 (`-` for none), then,
    when some are skipped, `<M> already in this run, will be skipped: <IDs>` (`name_list`);
  - when the plan has no rows at all: `No valid samples found in worklist.` (warning).
- Its other answers (sample API not configured or not enabled, no worksheet picked, the fetch
  failed) are today's.

## §5 Tests

Each new test is seen failing on `0a9fa12` for the reason named, before the code exists.

- **Unit** (`fetch_worklists` with `_api_get` replaced): a decimal, `true`, `false`, a list
  and an object are left out with the exact warning; text and whole numbers are kept as
  today; the `id` fallback is checked the same way; an admin's worksheet ID field is the one
  checked; two spellings of `worksheet_id`, of a mapped name, or of `id` are left out with
  the exact warning, the others listed (through the real JSON decoder, so slice 1's
  exact-repeat check is not what catches them); every worksheet left out → not a success,
  today's message, all warnings.
- **Integration** (routes, the LIMS calls replaced): the run page's button asks
  `/runs/<id>/samples/worklists`; the selector's import swaps `#sample-section` and shows
  the left-out warnings; the import reads the worksheet from a form-body post, as the page
  sends it, and imports; each refusal of the import answers 400 with the three headers and
  leaves the stored run as it was; the preview of a refused worksheet shows the import's
  text; the preview of a good worksheet lists exactly the sample IDs the import then adds,
  with test, version and indexes, every row (25 of 25), names read by the parser's aliases
  (`Sample`, `Test`), and the IDs already in the run as skipped; a row whose worksheet ID is
  `null` (`worksheet_id`, `Worksheet_ID`) gets the picked worksheet, in the preview and the
  import; the preview of a Ready run is refused (403).
- **Browser** (the LIMS functions replaced in the test server's process): on a draft run,
  Load Worklists → pick → Preview → Import Samples, with the page's own requests: the page
  then has one `#sample-section` and one `#sample-table`, the new samples in it, and the
  banner `Added 2 samples from worklist.`; a refused import leaves the table on the page and
  shows the refusal in the banner; a refusal right after a failed import from the same
  button (the run made Ready in between, 403; then Draft again) stays in the banner.
- Existing tests keep passing unchanged unless the plan lists the change with its reason
  (tests that post the worksheet in the query string, or expect 200 for a refusal, change
  by design).

## §6 Docs

- `docs/user-guide/samples.rst` ("Importing from a worklist (LIMS)"): the preview shows the
  samples the import would add (test, version, indexes), those already in the run, or the
  refusal the import would give; a refusal shows in the banner and changes nothing.
- `docs/admin-guide/sample-api.rst` ("List Worklists", "Using it from a run", "Error
  Handling"): a worksheet ID is text or a whole number, under one name; a worksheet with
  another ID, or with two spellings of its ID's name, is left out of the list with a
  warning; send IDs as text.
- No doc picture changes (checked as in slice 1).

## §7 Rollout

SeqSetup has never been deployed. No stored data changes; nothing to migrate.

## Not in this change

- Lanes for imported samples: they start in lane 1, as a paste does by default, but the LIMS
  box has no lane boxes (a paste has).
- The `add_step1` context of the worklist selector has no caller (dead branch).
- The preview is not a lock: the import fetches the worksheet again, so a LIMS that changes
  in between gets its new rows imported (each checked as always). Importing exactly what was
  previewed would need a fingerprint of the reply.
- The kit-swap message groups clashing samples by kit name (slice 1 build, ESCALATE-1).
- Can `0` be a placeholder sample ID in the lab's LIMS? Today the number `0` and the text
  `"0"` are both sample `0` (slice 1 build, ESCALATE-3; a question for the lab).
- The worksheet list's display fields (name, investigator, updated) are written with `str()`.
