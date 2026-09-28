# Group 1c: mismatch limit, disabled instruments, kit page, sample IDs — design

Fixes four findings from the 2026-09 documentation run (findings file kept outside the
repo), plus one cosmetic finding on the same page as one of them:

- **F6** — the barcode-mismatch inputs say max 2, but the server and the models accept 3.
- **F27** — the **Enabled** toggle on Admin → Instruments does nothing.
- **F31** — the index-kit page shows blank i7/i5 sequences for every unique-dual kit.
- **F32** — the same page prints the text `&mdash;` instead of a dash.
- **F5** — the Sample ID is cut short exactly on the row that validation flags.

The user made three decisions on 2026-09-28 and approved the design the same day:
F6 = the limit is 2 and other numbers are refused; F27 = a disabled instrument is hidden,
refused, and blocks Mark Ready for drafts; F5 = the whole Sample ID is always shown.
Branch `fix/group-1c` from `main` at `caa51c7`.

## Global rules

- Clinical software: when in doubt, do less; no silent behaviour change; tests first.
- Every change updates its doc page and picture in the same change.
- Every message shown to a user is escaped like every other banner message.
- `static/js/app.js` is not changed: the refusals below use the existing error banner,
  and F5 is a template class and CSS only.

## F6 — barcode mismatches are 0, 1 or 2

### Why 2

Illumina's BCL Convert (also run as DRAGEN BCL Convert, onboard NovaSeq X) lists the
allowed values for `BarcodeMismatchesIndex1` and `BarcodeMismatchesIndex2` as
**0, 1, or 2**, default 1:

- https://support-docs.illumina.com/SW/BCL_Convert/Content/SW/BCLConvert/SampleSheets_swBCL.htm
- https://help.dragen.illumina.com/dragen-v4.4/product-guide/dragen-v4.4/bcl-conversion

Neither page says what it does with 3. The DRAGEN page says settings it does not
recognize make the analysis abort. Either way a sheet carrying 3 is outside what the
software supports, so the app must not write one. The on-screen `max="2"` was right; the
server's 3 was wrong. If a lab later shows that its BCL Convert version accepts 3, this
limit can be widened with that evidence.

### Behaviour

- A per-sample mismatch value is blank (the sample uses the run default) or 0, 1 or 2.
- The two places a user sets it refuse anything else with HTTP 400 and the message
  **"Barcode mismatches must be 0, 1 or 2 — the values BCL Convert accepts. Nothing was
  saved."** Nothing is saved:
  - the per-row inputs (`POST /runs/{run_id}/samples/{sample_id}/settings`,
    `update_sample_settings`);
  - the bulk box (`POST /runs/{run_id}/samples/set-mismatches`, `set_mismatches_bulk`).
    One bad value refuses the whole request, as the F11 bulk refusal does.
- Refused means: not an integer after trimming (`"1.5"`, `"x"`), or an integer outside
  0–2 (`"-1"`, `"3"`). Blank stays "clear the override", as today.
- The refusal happens before `saving_run`, so the run is not touched and no change is
  recorded.

### Code

- `routes/samples.py`: one parser, `_parse_mismatches(raw: str) -> Optional[int]`, used by
  both routes for both indexes. It returns `None` for blank, the int for 0–2, and raises
  `HTTPException(400, <message above>)` otherwise. It replaces the two
  `max(0, min(3, int(...)))` pairs and their `except ValueError: None/pass` branches.
  Today those branches quietly clear the override (per row) or skip it (bulk) on a
  non-number.
- Models, the backstop: `Sample.__setattr__`, `SequencingRun.__setattr__` and
  `RunTemplate.__setattr__` clamp `barcode_mismatches_*` to 0–2 (today 0–3). The app has
  never been deployed, so no stored value of 3 exists; one would load as 2.
- `routes/runs.py` `update_bclconvert` (no UI posts to it; group 4 decides its fate):
  its two `min(..., 3)` become `min(..., 2)`, so no code states 3.
- The four inputs (two per row in `_sample_row.html`, two in the bulk box in
  `_bulk_lane_panel.html`) change from `type="number" min="0" max="2"` to
  `type="text" inputmode="numeric"`, so the text a user typed reaches the server.
  - **Why (review, P1):** a number box turns text it cannot read, such as `1e`, into an
    empty value before anything is sent (HTML value sanitization). The server would read
    that as "clear the override", and would clear it on the row, or on every selected row
    in the bulk box, with no message. Reproduced in Chromium for both paths. A server
    check alone cannot tell "cleared" from "unreadable".
  - With a text box the server gets `1e` and refuses it with the message above.
    `app.js` `applyBulkMismatchesForm` copies the box's `.value`, which is now the raw
    text, so `app.js` still does not change.
  - The small up/down arrows of the number box go away. Mobile keyboards still open in
    number mode (`inputmode`).
- `CLAUDE.md`: "clamp 0–3" becomes "clamp 0–2".

### Existing tests

`tests/unit/test_model_validation.py` asserts that 10 and 99 clamp to **3** (a `Sample`
and a `SequencingRun` test). They change to **2**. This is the decision itself, not a
loosened test.

### Docs

`docs/user-guide/samples.rst`: the mismatch counts are 0, 1 or 2 (the values BCL Convert
accepts); any other number is refused and nothing is saved.

### Not in scope (follow-up)

A synced application profile can carry `BarcodeMismatchesIndex1/2` defaults, which the
exporter writes as given. Profile values are not range-checked today. This joins the
1a profile-value follow-ups in groups 2–4.

## F27 — Disabled means disabled

### Meaning

Only synced instruments have an **Enabled** switch. An instrument from
`config/instruments.yaml` alone is always enabled. For a synced instrument switched off:

1. **New Run list:** it is not offered.
2. **Server:** choosing it is refused.
3. **Check panel and Mark Ready:** a **Draft** run on it gets an Error, so Mark Ready
   refuses until another instrument is picked. **Ready and Archived runs never get this
   error**; they keep their pre-generated exports and are left alone.

This closes every way a run can reach a disabled instrument: a new run starts on NovaSeq X
(the model default), a run made from a template copies the template's instrument, and a
draft may predate the switch.

### Code

- `data/instruments.py`:
  - new `is_instrument_enabled_by_name(name: str) -> bool`. It returns False only when a
    synced definition with that name exists and has `enabled == False`; True otherwise.
  - `get_all_instruments()`: each synced entry also carries `"enabled": inst.enabled`.
  - `get_enabled_instruments()`: leaves out entries whose `"enabled"` is False. The legacy
    `InstrumentConfig.enabled_instruments` filter is kept as it is.
- `routes/admin/instruments.py`: `toggle_synced_instrument` and `_bulk_set` also call
  `clear_synced_instruments_cache()`. They already call `clear_validation_cache()`.
  Without this, the cached `InstrumentDefinition` objects keep the old flag until the next
  sync or restart, so every check above would read a stale value.
- `routes/wizard.py` `wizard_step1`: the list is `get_enabled_instruments(...)`. If the
  run's own `instrument_platform` is not in it, one entry for that instrument is added
  with a marker:
  - `disabled` when `is_instrument_enabled_by_name` is False;
  - `not available` otherwise (an instrument a sync left out). Today such a run's select
    shows the first listed instrument as if it were chosen.

  `wizard/_instrument_config.html` shows the marker after the name, e.g.
  "NovaSeq X Series (disabled)", on the selected option. The screen then always shows the
  instrument the run really uses.
- `routes/runs.py` `update_instrument`: after the known-platform check, a disabled
  instrument is refused with HTTP 400, like the unknown-platform refusal:
  **"{name} is disabled by an administrator. The run still uses {current}. Reload the page
  to see the instruments you can pick."** Nothing is saved. This is reachable only from a
  page opened before the switch.
- `services/validation.py`: new `_validate_instrument_enabled(run)`, called in
  `validate_configuration` next to `_validate_cycles_fit_kit` (a run setting, so it shows
  even when the run has no samples). For a DRAFT run whose instrument is disabled it
  returns one `ConfigurationError`:
  - severity ERROR;
  - category `instrument_disabled`;
  - message **"{name} is disabled by an administrator. Pick another instrument in Run
    Setup before marking the run ready."**

  Mark Ready already refuses when `error_count > 0`. The validation cache is already
  cleared on every toggle.
- `routes/runs.py` `update_status`, re-check before saving Ready:
  - **Why (review, P2):** Mark Ready validates first, then spends time generating the
    exports, then saves. An admin who disables the instrument during that window would
    still get a Ready run, and the audit trail would show the run marked Ready after the
    instrument was disabled.
  - The handler already re-reads the run after export generation and refuses a run
    edited meanwhile (`_export_input_fingerprint`, reason
    `concurrent_edit_during_export`). Right after that check, and before `saving_run`, it
    now reads the instrument's definition **from the database**
    (`ctx.instrument_definition_repo.get_by_name(...)`, not the in-process cache). If
    that definition exists and is disabled, the transition is refused the same way:
    - audit `run.status.denied`, reason `instrument_disabled_during_export`;
    - `ConflictError` with **"{name} was disabled by an administrator while the exports
      were being generated. The run is still a Draft. Pick another instrument in Run
      Setup."**
    - Nothing is saved; the generated exports are discarded.
  - This narrows the window to the moment between that read and the save. No
    cross-document transaction exists to close it fully, and none is added.
- The app runs as one process (`uvicorn.run` in `app.py`), which the process-local
  caches (instruments and validation) already assume. The database read above keeps the
  final gate correct even if that ever changes.

"Not available" instruments (left out of a sync) are marked in the list only. They are
not refused and do not block Mark Ready; that is F28's territory.

### Docs

- `docs/admin-guide/instruments.rst`:
  - replace the warning "the Enabled checkbox … has no effect" and the note "that
    persistence is all the flag does" with what the switch now does (the three points
    above);
  - keep the note that the flag survives a sync.
- `docs/user-guide/run-setup.rst` (Platform): disabled instruments are not offered; a run
  already on one shows it marked "(disabled)" and cannot be marked Ready until another is
  picked; "(not available)" means a sync left it out.
- `docs/user-guide/validation.rst`: add "Instrument disabled" to the list of Errors.
- No new picture. The admin picture is unchanged.

## F31 + F32 — the index-kit page

- `templates/indexes/detail.html`, unique-dual table: `pair.i7_sequence` →
  `pair.index1_sequence`, and `pair.i5_sequence` → `pair.index2_sequence or "—"`. A pair
  without an i5 shows "—", not "None".
- The seven `{{ … or "&mdash;" }}` become `{{ … or "—" }}` (a real em dash character).
  Autoescape turned the entity into visible text.
- `docs/admin-guide/index-kits.rst`: drop the sentence that says the columns are blank and
  to use Download YAML instead. Retake `admin/index-kit-detail.png`.

## F5 — the whole Sample ID

- `wizard/_sample_row.html`: both Sample ID cells (the drop-zone branch and the plain
  branch) get `class="sample-id-cell"`. They keep their `title`, which `app.js` uses to
  find the cell for the "!" badge.
- `components.css`: a rule `.sample-table td.sample-id-cell`, after the
  `td:nth-child(2..4)` truncation rule:
  - no `overflow: hidden`, no `text-overflow: ellipsis`;
  - `white-space: normal`, `overflow-wrap: anywhere`;
  - `min-width: 7rem` so short IDs do not wrap, and `max-width: 16rem` so one very long
    ID (256 characters is allowed) wraps instead of stretching the table.
- Nothing else changes. Test ID and Worksheet keep their "…", and the "!" stays in front of
  the ID.
- `docs/user-guide/samples.rst`: a long Sample ID wraps onto a second line; it is never
  cut. Retake `samples/sample-table.png` and `samples/row-edit.png`, plus any other doc
  picture of the sample table that changes because of this (listed in the change).

## Tests (each seen failing first)

- F6, unit: the model clamps high values to 2 (the edited tests).
- F6, integration:
  - per row: `"3"`, `"-1"`, `"1.5"`, `"1e"` are refused with the message and nothing
    changes; `""`, `"0"`, `"2"` save;
  - bulk: one bad value refuses the whole request and no sample changes.
- F6, browser (the review's P1 paths, real Chromium):
  - a row with an override of 2: typing `1e` in its box shows the refusal in the banner,
    and the stored value is still 2;
  - two selected rows with overrides: `1e` in the bulk box shows the refusal, and neither
    row's value changes.
- F27, unit:
  - `is_instrument_enabled_by_name` for synced-disabled, synced-enabled, and yaml-only;
  - `get_enabled_instruments` drops a disabled synced instrument.
- F27, integration:
  - the admin toggle (through its route) hides the instrument from New Run at once,
    which proves the cache is cleared;
  - a draft on a disabled instrument shows it marked "(disabled)" and selected;
  - `POST /runs/{id}/instrument` for a disabled one is refused;
  - the Check panel shows the Error and Mark Ready refuses;
  - after enabling again, Mark Ready works;
  - a Ready run on a disabled instrument has no such error;
  - the timing gap (review P2): with export generation patched to disable the instrument
    in the database while it runs, Mark Ready is refused with reason
    `instrument_disabled_during_export`, and the run stays a Draft with no stored
    exports.
- F31/F32, integration: a unique-dual kit page shows every pair's i7 and i5 sequence; a
  pair without an i5 shows "—"; the page has no `&amp;mdash;`.
- F5, browser: in a run with a 30-character Sample ID on a flagged row and on a clean row,
  both cells show the whole ID, not cut (`scrollWidth <= clientWidth` and no ellipsis);
  the flagged row still has its "!".

Final checks: the full server suite, the browser suite, the docs build with `-W`, and the
doc pictures regenerated with the whole picture file.

## Follow-ups (not in 1c)

- Profile-carried `BarcodeMismatchesIndex1/2` values are not range-checked.
- "Not available" (sync-excluded) instruments are shown but not refused (F28).
- The legacy `InstrumentConfig.enabled_instruments` filter is dead (group 4).
- Test ID and Worksheet still truncate with "…".
