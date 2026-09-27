# Run checks (group 1b) — design

Fixes three findings from the 2026-09 documentation run
(`/home/parlar_ai/seqsetup-docs-run/FINDINGS-DOCS.md`, outside the repo):

- **F13** — a color-balance Error never stops Mark Ready, and nothing says so at the moment
  it matters.
- **F1/F2** — no reagent kit ships with a cycle limit, so the cycle total is never checked,
  while the setup page shows "Total: 322 / 300 cycles" as if it were.
- **F11** — an Override Cycles value that does not fit the run is saved, and is caught only
  later by the Check panel or Mark Ready.

The user chose the F13 behaviour ("ask before Mark Ready", not "block") and approved the
design on 2026-09-27. Branch `fix/run-checks` from `main` at `101a326`.

## Global rules

- Clinical software: when in doubt, do less; no silent behaviour change; tests first.
- Every change updates its doc page and picture in the same change.
- Messages shown in the error banner are escaped like every other banner message.

## F13 — Mark Ready asks about color-balance errors

### Why ask, not block

Color balance is counted one vote per sample, per index position. With one sample in a
lane, every position whose base is not C lights only one channel (or none, for G), so a
one-sample lane almost always has an Error. Labs run such lanes on purpose, sometimes
with an indexed PhiX control to balance the index reads (ordinary PhiX Control v3 has no
index and does not), and the app cannot see a spike-in. Blocking would stop them with no
way round. An index
collision can put one patient's reads under another's name and stays a hard error; poor
color balance costs read quality in that lane, so the operator decides, on the record.

### Behaviour

- Only color-balance **Errors** count: a position where a channel gets no signal from any
  sample in the lane. Warnings (a channel under 25 %) do not.
- Only when color balance is analysed for the instrument (`color_balance_enabled`); other
  instruments never see the question.
- New `LaneColorBalance.has_errors` (any Error position in i7 or i5) and
  `ValidationResult.color_balance_error_lanes -> list[int]` (sorted lane numbers with
  errors; empty when color balance is off).
- `POST /runs/{id}/status/ready` (`routes/runs.py` `update_status`), after the existing
  `error_count > 0` refusal and before export generation:
  - no error lanes: unchanged;
  - error lanes, and the form does not confirm them: the run stays Draft. The response is
    a question in the `#ready-message` slot (see "Where Mark Ready's messages go"),
    rendered from a new `runs/_ready_color_balance.html`. Audit event `run.status.denied`,
    `reason="color_balance_unconfirmed"`, `color_balance_lanes=[...]`;
  - error lanes, and the form confirms them: Mark Ready goes on as today, and the
    `run.status.changed` audit event carries `color_balance_accepted_lanes=[...]`.
- The question's form posts back to the same URL with two hidden fields:
  `color_balance_confirmed_at` = the run's `updated_at` (ISO text) and
  `color_balance_lanes` = the lanes shown (`"1,2"`). The confirmation counts only if both
  still match the run: an edit in between (a new `updated_at`) or a different set of error
  lanes (for example after a config sync changed the instrument's channels) asks again.
  So nobody confirms something they did not see.
- Question text (UI spelling "color", as elsewhere in the app):
  heading **Color balance errors**; body "Lane 1 has color balance errors: at some index
  position, one color channel gets no signal from any sample in the lane. Reads from that
  lane may fail to be assigned to their samples. Check the Color Balance tab of the
  validation page (link) before going on."; one button **Mark Ready anyway**.
- Check panel (`runs/_validate_panel.html`): when error lanes exist, the amber badge reads
  `Color balance: N lane(s) · Mark Ready will ask`; otherwise unchanged.

### Where Mark Ready's messages go

Today the refusal ("Cannot mark ready") goes into the app-wide `#error-banner`, which
holds one message and which `static/js/app.js` empties when the element whose request
last *failed* later gets a response under 400. The review of this design (Astra,
2026-09-27) showed three ways that loses a message:

1. After Mark Ready failed with a 409 or 500, a retry that returns the question (a 200 aimed
   at the banner) is swapped in and then cleared by that rule; the confirm button vanishes
   (reproduced in Chromium). The refusal has the same flaw today.
2. Emptying the banner when the run becomes Ready would also remove an unrelated save
   failure. With F11, a refused edit leaves the previous valid value stored, Mark Ready can
   succeed on it, and the user would lose the only sign that the edit was not saved.
3. Because the banner holds one message, a refusal or question replaces a save-failure
   message already in it.

So Mark Ready's own messages — the refusal and the color-balance question — get their own
slot, `<div id="ready-message" class="empty:hidden">`, placed right under the run status
bar in `runs/edit.html`:

- `update_status` sends both with `HX-Retarget: #ready-message` (`HX-Reswap: innerHTML`),
  as 200 responses as today.
- Every successful status change also sends an empty `#ready-message` out of band, so a
  stale refusal or question never stays on a Ready (or Archived, or Draft again) run.
- `#error-banner` and `app.js` are not changed: save failures and HTTP errors stay there,
  and nothing in this change empties them. The `app.js` rule empties `#error-banner` and
  `#form-errors` only, so it can no longer remove a readiness message (1); a Ready run
  keeps any save-failure message (2); and a readiness message never replaces one (3).
- The 409 conflict and 500 export failure of Mark Ready stay HTTP errors in
  `#error-banner`, as today.

## F1/F2 — the cycle total says when it is not checked

- `wizard/_cycle_total.html`, branch without a kit limit: "Total: 322 cycles (300-cycle
  kit)" followed by a quiet note: "Not checked: no cycle limit is set for this kit. Kits
  hold a few extra cycles, so a total a little over the kit's label is normal."
- The branch with a limit is unchanged ("Total: N / max …", red "Too many cycles for this
  kit.").
- No kit numbers are shipped (`test_shipped_config_has_no_numbers` stays): the limit must
  come from the lab's Illumina documentation.
- No new Check-panel warning: a warning on every run of a default install would teach
  users to ignore warnings.

## F11 — Override Cycles that do not fit are refused when saved

- One rule, two users: new `CycleCalculator.override_cycles_problem(value: str,
  run_cycles: RunCycles) -> Optional[str]` returns `"invalid"` (a segment that is not
  letters Y/I/U/N each followed by a count), `"mismatch"` (a `*` left in it, or segment
  sums that differ from the run's read structure, one segment per read of more than 0
  cycles), or `None`. It is the logic that `_validate_override_cycles_match_run` runs today
  on a sample's value, moved; Mark Ready calls it, and its categories and messages do not
  change. The read-override-pattern part of that check stays where it is.
- Both save routes — `update_sample_settings` (one sample) and `set_override_cycles_bulk` —
  check every **final** value before anything is saved, when the run has cycles: a typed
  value after the `*` expansion, and also the value calculated when the field is left
  empty ("Auto"). The calculated value can be wrong too: a kit whose default read override
  is `Y100` gives `Y100;I8N2;I8N2;Y151` on a 151-cycle run (measured). The bulk route works
  out every selected sample's final value first and refuses the whole request if any one
  fails — no sample is changed. A problem is an `HTTPException(400)`; the error banner
  shows the message and nothing is saved:
  - typed, invalid: "Override Cycles '<value>' is malformed: each part must be the letter
    Y, I, U or N followed by a cycle count (e.g. 'Y151;I8N2;I8N2;Y151'). Nothing was
    saved."
  - typed, mismatch: "Override Cycles '<value>' does not fit this run's cycles (Read1 151
    / Index1 10 / Index2 10 / Read2 151): each part must add up to its read's cycles, one
    part per read of more than 0 cycles. Nothing was saved. Leave the field empty to
    calculate it from the run's cycles."
  - calculated (either problem): "The Override Cycles calculated for <sample ID>
    ('<value>') do not fit this run's cycles (Read1 … / Read2 …). They come from the index
    kit's default read override, which an admin must correct. Nothing was saved." (bulk:
    the first failing sample, plus "and N more").
- A run without cycles yet: only the shape check, as today. Mark Ready keeps its check:
  the run's cycles can change after a value was saved, and assigning an index also
  recalculates the value (see Out of scope).

## Docs

- `user-guide/validation.rst`: the Check panel paragraph (badge text) and the color-balance
  `.. warning::` become a description of the question.
- `user-guide/export.rst`: the Mark Ready section describes the question, with a new
  picture `ready/mark-ready-color-balance.png`, and says the refusal and the question
  appear under the status bar; `ready/mark-ready-refused.png` is retaken there.
- `user-guide/run-setup.rst`: the cycle total paragraph and the "As shipped, no
  instrument…" warning describe the new line; picture `new-run/cycle-config.png` retaken.
- `user-guide/override-cycles.rst`: the warning about late feedback becomes "refused when
  you save".
- Pictures come from `tests/browser/test_docs_screenshots.py` (`pixi run
  docs-screenshots`); the Mark Ready picture test answers the question when it appears,
  and the refusal picture test waits on `#ready-message .ready-refused`.

## Testing

- Tests first, seen failing for the missing behaviour.
- Unit: `has_errors` / `color_balance_error_lanes` (errors vs warnings only, color balance
  off, several lanes); `override_cycles_problem` (fits, malformed, wrong count, wrong sum,
  zero-cycle read, leftover `*`); the Mark Ready check's results unchanged.
- Integration: Mark Ready with error lanes asks and stays Draft (audit event, no exports);
  confirming makes it Ready (audit carries the lanes); a stale confirmation (run edited, or
  different lanes) asks again; warnings only do not ask; a 4-color instrument does not ask;
  both save routes refuse a value that does not fit (400, value unchanged, `updated_at`
  unchanged) and accept one that fits; clearing the field refuses a calculated value
  that does not fit (a kit pattern of `Y100` on a 151-cycle run); the bulk route with
  one failing sample changes no sample; the refusal and the question carry
  `HX-Retarget: #ready-message`, and a successful status change sends an empty
  `#ready-message`; the cycle total line on a kit without a limit. Existing assertions
  that the refusal targets `#error-banner` change to `#ready-message`.
- Browser: after Mark Ready failed once (the test answers the first request with a 500
  through Playwright's request routing), the retry's question stays on screen and its
  button works; a save failure shown in `#error-banner` is still there after Mark Ready
  succeeds; a refusal does not replace it.
- Existing tests that mark a one-sample two-color run Ready will meet the question; they
  get a shared helper that confirms it. That is expected churn, not a regression.
- Break tests for each new guard; full server suite, browser suite (CSS built), docs build;
  independent review.

## Out of scope

- Weighting color balance by each sample's share of the lane, or modelling PhiX.
- Shipping kit cycle limits.
- The JSON API (read-only; it never changes a run's status).
- Assigning an index (drag, keyboard, bulk panel) and changing the run's cycles also
  recalculate Override Cycles. They are not refused here: a kit's bad default read
  override should not stop an index from being assigned, and the admin fixes the kit.
  The Check panel and Mark Ready still refuse such a value.
- Other messages in `#error-banner` (one message at a time, cleared by `app.js`'s rule):
  unchanged.
