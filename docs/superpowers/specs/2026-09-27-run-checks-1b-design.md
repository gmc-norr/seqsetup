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
one-sample lane almost always has an Error. Labs run such lanes on purpose, often with
PhiX, which the app cannot see. Blocking would stop them with no way round. An index
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
    a question in the `#error-banner` slot (same `HX-Retarget` mechanism as the refusal),
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
- The question goes away when the run becomes Ready: the Ready response also empties
  `#error-banner` out of band. Today nothing clears the banner after a later success
  (`static/js/app.js` clears it only when the element whose request *failed* succeeds, and
  the question and the refusal are 200 responses), so a stale question or refusal would
  stay on a Ready run. Emptying it on Ready is safe: the sample section is re-rendered
  read-only in the same response, so no unsaved value on screen still needs its message.
- Check panel (`runs/_validate_panel.html`): when error lanes exist, the amber badge reads
  `Color balance: N lane(s) · Mark Ready will ask`; otherwise unchanged.

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
  call it after the `*` expansion, when the run has cycles. A problem is an
  `HTTPException(400)`; the error banner shows the message and nothing is saved:
  - invalid: "Override Cycles '<value>' is malformed: each part must be the letter Y, I,
    U or N followed by a cycle count (e.g. 'Y151;I8N2;I8N2;Y151'). Nothing was saved."
  - mismatch: "Override Cycles '<value>' does not fit this run's cycles (Read1 151 /
    Index1 10 / Index2 10 / Read2 151): each part must add up to its read's cycles, one
    part per read of more than 0 cycles. Nothing was saved. Leave the field empty to
    calculate it from the run's cycles."
- A run without cycles yet: only the shape check, as today. Mark Ready keeps its check:
  the run's cycles can change after a value was saved.

## Docs

- `user-guide/validation.rst`: the Check panel paragraph (badge text) and the color-balance
  `.. warning::` become a description of the question.
- `user-guide/export.rst`: the Mark Ready section describes the question, with a new
  picture `ready/mark-ready-color-balance.png`.
- `user-guide/run-setup.rst`: the cycle total paragraph and the "As shipped, no
  instrument…" warning describe the new line; picture `new-run/cycle-config.png` retaken.
- `user-guide/override-cycles.rst`: the warning about late feedback becomes "refused when
  you save".
- Pictures come from `tests/browser/test_docs_screenshots.py` (`pixi run
  docs-screenshots`); the Mark Ready picture test answers the question when it appears.

## Testing

- Tests first, seen failing for the missing behaviour.
- Unit: `has_errors` / `color_balance_error_lanes` (errors vs warnings only, color balance
  off, several lanes); `override_cycles_problem` (fits, malformed, wrong count, wrong sum,
  zero-cycle read, leftover `*`); the Mark Ready check's results unchanged.
- Integration: Mark Ready with error lanes asks and stays Draft (audit event, no exports);
  confirming makes it Ready (audit carries the lanes); a stale confirmation (run edited, or
  different lanes) asks again; warnings only do not ask; a 4-color instrument does not ask;
  both save routes refuse a value that does not fit (400, value unchanged, `updated_at`
  unchanged) and accept one that fits; the cycle total line on a kit without a limit.
- Existing tests that mark a one-sample two-color run Ready will meet the question; they
  get a shared helper that confirms it. That is expected churn, not a regression.
- Break tests for each new guard; full server suite, browser suite (CSS built), docs build;
  independent review.

## Out of scope

- Weighting color balance by each sample's share of the lane, or modelling PhiX.
- Shipping kit cycle limits.
- The JSON API (read-only; it never changes a run's status).
