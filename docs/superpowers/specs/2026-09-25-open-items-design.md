# Open items after "fill indexes in order" — design

Date: 2026-09-25. Base: `main` at `55d5d27`.

Decided by the user: archived runs get working downloads. Everything else here
follows the rule "when in doubt, do less".

## 1. Archived runs: downloads work in the Export panel

Today an archived run's Export panel shows every button disabled and the text
"Run must be marked as ready to enable exports". That text is wrong (ARCHIVED is
terminal), and it disagrees with the rest of the app: `get_exportable_run`
allows READY and ARCHIVED, the export routes serve the bytes pre-generated at
Ready (READY→ARCHIVED keeps them), and the API serves them for archived runs.

Change `templates/runs/_export_panel.html` only: a button is enabled when the
run is READY **or ARCHIVED** (Sample Sheet buttons still also need every sample
indexed, as today). The wrong sentence goes. DRAFT is unchanged ("Downloads open
when the run is Ready."). No route, model or exporter change.

## 2. The kit picker keeps the chosen kit

Every re-render of `#sample-section` (paste/add, bulk edits, index assignment,
fill, Ready→Draft) draws the kit dropdown with the first kit selected, so the
user's choice silently jumps back to kit #1 after almost any edit.

- `static/js/app.js`: on `htmx:configRequest`, when `#index-kit-dropdown`
  exists, send its value in a request header `X-Selected-Kit`,
  `encodeURIComponent`-encoded (header values must be Latin-1; kit names may
  not be). A header, never a form field: the fill's Assign form sends its own
  `selected_kit`, which must not be overwritten.
- `routes/utils.py`: `selected_kit_id(request) -> str` — the decoded header,
  capped at 512 characters, `""` when absent.
- Every server render of `runs/_sample_section.html` passes
  `chosen_kit_id=selected_kit_id(request)` (`routes/samples.py`
  `_render_sample_section`, `routes/runs.py` status change).
- `runs/_sample_section.html`: the panel and dropdown use the kit whose
  `kit_id` equals `chosen_kit_id`; if none matches (absent, deleted, bad
  value), the first kit, as today. The value is only ever compared against
  existing kit ids.
- A full page load has no header and shows the first kit, as today.

## 3. Samples with only an i5 index

A sample with an i5 and no i7 is "unindexed" for the index panel (it needs an
i7), so the panel offers "Fill empty samples in order…". The fill only touches
samples with no index at all, so for such a run the preview says "Every sample
already has an index." — which is false.

`services/index_fill.py` (no model change): `FillPlan.partial` lists the labels
of samples with an i5 but no i7 and no pair.
- No sample without any index, but some partial: problem "Fill in order only
  fills samples with no index at all. N sample(s) have only an i5 index; give
  them an i7 by hand: S1, S2." (at most 10 names, then "and N more").
- Some targets and some partial: the preview adds the note "Left alone, they
  have only an i5 index: S3."
Partial samples are never filled or changed.

## 4. Edge-case tests for the fill

Characterisation tests in `tests/unit/test_index_fill.py`: a kit whose pairs
share an id; a unique-dual pair with no i5; more samples than the whole kit
from the first index; a sample whose `sample_id` is empty. If one shows a real
defect, fix it only inside `services/index_fill.py` when the fix is obvious and
safe; otherwise escalate.

## 5. Tidy-ups

- Delete the orphaned `.bulk-paste-section` rule in `static/css/components.css`
  (its template was deleted in e73b59b).
- `set_lanes_bulk`: the message "Invalid sample_ids or lanes JSON" now only
  fires for a bad `lanes` field; say "Invalid lanes JSON".

## Not in scope

- The layout rule that would let the fill table scroll inside its panel
  (`min-width: 0` on a shared panel): a layout-wide change; the page already
  does not scroll sideways.
- The cycle-limit numbers (the lab supplies them).
- Screenshot baselines: report differences, do not update them.
