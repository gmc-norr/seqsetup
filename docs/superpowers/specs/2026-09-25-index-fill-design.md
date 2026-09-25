# Fill indexes in order, and four leftover fixes — design

Date: 2026-09-25. Base: `main` at `284e782`.

The user asked for this without a mockup ("I trust your judgement"). The
decisions below were made on that basis; they favour doing less.

## Part A — leftover fixes

A1. **Changing the instrument leaves a stale reagent kit.** `update_instrument`
(`routes/runs.py`) sets the first flowcell of the new instrument but never
checks `run.reagent_cycles` against that flowcell's kits, and only swaps
`#flowcell-select`, so `#reagent-kit-select` still lists the old kits. Apply
the rule `update_flowcell` already uses (kit not offered → first offered kit;
run cycles are NOT reset), and send the reagent-kit select back out of band so
the page shows the kit actually saved. The cycle total line (already sent out
of band) must reflect the saved kit.

A2. **`set-test-id` crashes on a non-list.** `POST /runs/{id}/samples/set-test-id`
returns 500 when `sample_ids` is JSON `null` (or an object, or a list holding a
non-string). It must be a 400 with a clear message and nothing saved. Sibling
bulk routes that parse `sample_ids` the same way get the same fix, each with a
test.

A3. **Bulk lane panel may nest the sample section.** Its forms target
`#sample-table` while the route returns the whole `#sample-section`. Prove it in
a browser first (duplicate `#sample-section`, or a section inside the table).
Fix only if real, by making target/select match what is returned.

A4. **Unused template.** `templates/wizard/_bulk_paste_section.html` looks
unused. Delete it if nothing references it.

Out of scope: the archived-run Export panel (a product decision for the user).

## Part B — Fill indexes in order

Today a user can fill several samples in order only by shift-click selecting
indexes and dragging them. For a 96-sample run that is slow and easy to get
wrong. Part B adds a button that fills every sample that has no index, from the
kit shown in the index panel, in table order, with a preview first.

### Rules

- **Targets:** samples with no index at all (`index_pair`, `index1` and
  `index2` all empty), in run order (the table order). A sample with any index,
  even a partial one, is never touched.
- **Kits:** unique dual (index pairs) and single (i7 only). Combinatorial kits
  are refused with "Fill in order works with unique dual and single-index kits.
  Assign combinatorial indexes by hand."
- **Order:** the kit's own order (as listed in the panel).
- **Start:** a "Start at" picker listing the kit's indexes. Default: the first
  index not already used in the run. From the start, go forward only; never wrap
  to the beginning.
- **Skip used:** an index is skipped when its i7 is already an i7 in the run, or
  its i5 is already an i5 in the run (any sample, any lane, any kit). Indexes
  chosen earlier in the same fill count as used, so a kit that repeats a
  sequence cannot give it twice. Skipped names are listed in the preview.
- **Not enough:** if fewer unused indexes are left from the start than samples
  need one, nothing can be assigned: "Not enough unused indexes: 20 needed, 12
  left in <kit> from <start>. Pick an earlier start or another kit." No
  partial fill.
- **Nothing to do:** "Every sample already has an index."
- **Apply = preview:** the Assign form carries the kit, the start and the plan's
  signature (`[[sample id, index id], …]`). The apply route rebuilds the plan
  from the current run and kit and refuses with 409 "The run or kit changed
  since the preview. Preview again." if the signature differs. Nothing is saved
  in that case.
- **What Assign does per row:** exactly what the existing assign routes do —
  assign the pair (or the i7), set `index_kit_name`, apply the kit's defaults,
  recompute override cycles — inside one `saving_run`. Audit event
  `sample.index_filled_in_order` with kit name and version, start name and
  count. Message: "Gave indexes to N samples from <kit>, starting at <start>."
- **Draft only** (`get_editable_run`). Check runs as usual afterwards; the fill
  never relaxes a validation rule.

### UI

- In the run page's index panel (shown while some sample has no index), under
  the kit dropdown: a small button "Fill empty samples in order…". It posts the
  selected kit (`#index-kit-dropdown`) to the preview route.
- The preview appears full width above the sample table and index panel
  (`#index-fill-area`, inside `#sample-section`): heading, "Start at" picker
  (changing it re-previews), one sentence saying what will happen, the skipped
  list, a table (Sample | Index | i7 | i5), and Assign N indexes / Cancel.
  With a problem, the problem sentence replaces the sentence and table, and
  there is no Assign.
- Assign swaps `#sample-section` like the paste preview's Add does. Cancel
  empties `#index-fill-area` (CSP-safe `data-action`, see `static/js/app.js`).

### Code

- `src/seqsetup/services/index_fill.py` — pure planning (`build_fill_plan`,
  `FillPlan`, `KitEntry`, `FillRow`); no I/O, no mutation.
- Two routes in `src/seqsetup/routes/samples.py` (they reuse its private
  helpers): `POST /runs/{run_id}/index-fill/preview` and
  `POST /runs/{run_id}/index-fill`. The paths are outside `/samples/` so the
  `POST /runs/{run_id}/samples/{sample_id}` catch-all cannot swallow them.
- `templates/runs/_index_fill_preview.html`, a button form and
  `<div id="index-fill-area">` in `templates/runs/_sample_section.html`, a
  `cancel-index-fill` click action in `static/js/app.js`, `.index-fill-*`
  styles in `static/css/components.css`.
- No model, exporter or validation change.
