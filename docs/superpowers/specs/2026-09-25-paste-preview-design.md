# Add Samples: Preview Before Saving — Design

**Date:** 2026-09-25
**Status:** Approved design (mockup: https://claude.ai/artifact/HnaNepULtB5TzRgJaFWkZg)
**Feature area:** Run page → Samples and indexes → Add samples

## Problem

Pasting samples saves at once, and the parser makes guesses the user never
sees:

1. **No header row → positional guess.** `S1<TAB>ATTACTCG<TAB>TATAGCCT`
   becomes test `ATTACTCG`, i7 `TATAGCCT`, no i5. Check flags the odd test,
   but fixing the test leaves the swapped index in place.
2. **Unknown header columns are dropped silently** (e.g. a `lane` column).
3. **Unrecognised header names are read as a sample** (`Patient, AssayCode`
   → a sample called "Patient").
4. **Index names without sequences set no index**, silently.

Also: every pasted sample lands in lane 1 with no visible choice, a paste
without tests leaves every row without one, and duplicate IDs are skipped
with a count but never named.

## Decisions (user)

- **Default lanes:** lane 1, as today, but shown in a lane picker.
- **Repeated IDs (split rule):** the same ID twice *within the paste*
  refuses the whole paste (we can't tell which row is right). An ID *already
  in the run* is skipped, and named.

## The flow

1. **Paste.** The Add-samples box gains two pickers and its button becomes
   **Preview**. Nothing is saved.
   - *Test for rows without one:* "Leave blank" or a known test profile.
     Only fills rows whose test cell is empty.
   - *Lanes for these samples:* one checkbox per flowcell lane, lane 1
     ticked; an "All lanes" button ticks every box. At least one lane is
     required (no box ticked is an error, never "all lanes" by accident).
     Flowcells with one lane show "Lane 1" and send it hidden.
2. **Preview** (replaces the paste form inside the box):
   - recap line (lines pasted, test for blank rows, lanes) with "Edit paste";
   - counts: samples read, will be added, skipped, to look at, repeated;
   - columns used (header text → field) and columns **not used**;
   - a notice when there was no header row and columns were guessed;
   - one table row per sample: source line, sample ID, test (marked
     "picked" when it came from the picker), i7, i5, index name, lanes, note;
   - **Add N samples** and **Back to edit**.
3. **Blocked.** Red rows disable Add ("Fix the red rows first").

### Row states

| State | When | Blocks Add |
|---|---|---|
| Blocked (red) | Sample ID appears more than once in the paste | Yes |
| Skipped (grey) | Sample ID already in the run | No — row not added, named |
| Look (yellow) | Test not a known profile (+ "looks like an index sequence" hint when it is `[ACGTN]{6,}`); no test at all; index name given but no sequences | No |
| OK | none of the above | No |

"Test" checks only run when at least one test profile exists, matching the
Check panel, which only validates tests when profiles are configured.

Whole-paste errors the parser already raises (row without a sample ID, bad
DNA letters, unreadable quotes, over the sample cap) show as one red box in
the preview, with no table and no Add button — same rules as today.

## How it's built

**One reader.** The preview is rendered on the server with the same parser
that saves. The Add form carries the exact pasted text (hidden textarea),
the lanes and the default test; `/samples/bulk` re-reads it and re-applies
every blocking rule. The preview is advisory UI; `/samples/bulk` is the
authority. No parser in the browser.

### Units

- `services/sample_parser.py`
  - `ParsedSample` gains `line: int = 0` (source line number).
  - New `read_pasted_samples(text) -> PasteReadResult` returning the samples
    plus `header_found`, `columns_used: list[(header_text, field)]`,
    `columns_unused: list[str]`, `column_count`. `parse_pasted_samples`
    becomes a thin wrapper returning `.samples` (existing callers and tests
    unchanged).
- New `services/paste_preview.py` — pure, read-only:
  `build_paste_preview(read, existing_ids, test_types, default_test, lanes)
  -> PastePreview` (rows with state + notes, counts, guessed-columns text,
  `can_add`). Unit-tested without a database.
- `routes/samples.py`
  - shared `_read_paste_input(request, run, ctx)` → text, lanes, default
    test (or an error message): 10 MB caps and UTF-8 check as today; lanes
    via `_normalize_lane_selection`, at least one required; default test
    must be empty or a known `test_type`.
  - new `POST /runs/{run_id}/samples/preview` — `Depends(get_editable_run)`,
    no mutation; renders `runs/_paste_preview.html`.
  - `POST /runs/{run_id}/samples/bulk` — uses `_read_paste_input`; applies
    lanes to every added sample and the default test to blank-test rows;
    **refuses** the paste when an ID repeats within it (banner names the
    IDs); names skipped already-in-run IDs (first 10, then "and N more");
    audit event gains lanes and default test.
- Templates
  - new `runs/_paste_form.html` (textarea, file, pickers, Preview, Clear) —
    rendered inside `#paste-area` on the run page and again, pre-filled, by
    the preview so "Back to edit" keeps what was typed.
  - new `runs/_paste_preview.html` — recap, notices, table, Add form.
    "Edit paste" / "Back to edit" toggle with Alpine (`x-show`), UI state
    only; nothing domain-related lives in Alpine.
  - `runs/_sample_section.html` includes the form in `#paste-area`.
- CSS in `components.css`: preview table, row states, chips, lane picker,
  file button (`::file-selector-button`).

## Out of scope

Looking up index names in a kit; a lane column in the paste; the LIMS
worklist import (it has its own preview); page tidy-ups (red "1 error" on
an empty run, quiet Mark Ready, Export copy); the unused
`wizard/_bulk_paste_section.html`.

## Testing

- Unit: `read_pasted_samples` (line numbers, header found, used/unused
  columns, headerless guess, extra headerless columns unused);
  `build_paste_preview` (each row state, the DNA-looking-test hint, default
  test fills blanks only, counts, `can_add`, no test checks without
  profiles).
- Integration: preview renders and does not change the run; preview
  rejects missing lanes / unknown default test / non-draft run; bulk applies
  lanes and default test; bulk refuses in-paste repeats and adds nothing;
  bulk skips and names already-in-run IDs; existing bulk tests keep passing
  (updated to send `lanes`).
- Browser: paste → Preview → Add adds the rows with the chosen lanes;
  Back to edit keeps the text; a repeated ID disables Add.
