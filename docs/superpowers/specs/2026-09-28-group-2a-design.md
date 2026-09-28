# Group 2a: deleted runs keep a copy and their history; template owners — design

Fixes three findings from the 2026-09 documentation run and one from the 2026-09 security
audit (both findings files are kept outside the repo):

- **F16** — deleting a run permanently deletes its change history, including when an
  administrator deletes an Archived run.
- **N-27** (= **F19** + **F20**) — any signed-in user can rename or delete any other user's
  run template.

While reading the code for F16, a worse path turned up: a Ready run can be sent back to
Draft, emptied of samples, and then deleted by **any** user. `delete_run` only checks
"Draft with no samples", and its comment ("it can never have been Ready") is wrong. The
sheet may already have gone to a sequencer, and the history went with the run.

The user decided on 2026-09-28: **admins may still delete runs, but the history stays, and
a new admin page lists deleted runs with their history** (option 2 of 2). The user approved
the design below the same day. Branch `fix/group-2a` from `main` at `62706ad`.

## Global rules

- Clinical software: when in doubt, do less; no silent behaviour change; tests first.
- Every change updates its doc page and picture in the same change.
- Every value shown on a page goes through Jinja autoescape, like every other page.
- `static/js/app.js` is not changed. Refusals use the existing error banner (the HTMX error
  handler already shows a 4xx/5xx body).
- Sample Sheets, the JSON export and the API are not changed. Nothing in this group writes
  to an export.

## F16 — a deleted run leaves a copy and its history

### Who may delete what

| Run | Who may delete | Copy kept? |
|---|---|---|
| Empty Draft, never Ready | anyone (as today) | no — a blank start, e.g. Cancel on New Run |
| Empty Draft that **was Ready once** | **admins only** (new) | **yes** (new) |
| Archived | admins only (as today) | **yes** (new) |
| Ready | nobody (as today) | — |
| Draft with samples | nobody (as today) | — |

Change history is **never** deleted from inside the app, for any run (new).

A standard user who tries to delete an empty Draft that was Ready once gets **403** with:
**"This run was Ready once, so only an admin can delete it. Nothing was deleted."**
The other refusals keep today's messages.

### "Was Ready once"

- New field `SequencingRun.was_ready: bool = False`, stored by `to_dict` / `from_dict`
  (`data.get("was_ready", False)`).
- The model keeps it, so no route can forget it (CLAUDE.md: invariants on assignment):
  - In `SequencingRun.__setattr__`, when `status` is set to READY or ARCHIVED, `was_ready`
    is also set to True.
  - When `was_ready` itself is assigned, the value becomes
    `bool(value) or <current was_ready> or <current status is READY/ARCHIVED>`. It can
    never go from True back to False. (Read the current values with `getattr(self, …,
    default)`: during dataclass `__init__`, `status` is assigned before `was_ready`.)
  - So `SequencingRun(status=READY)` and `from_dict` of a stored Ready or Archived run both
    give `was_ready=True`, and READY→DRAFT keeps it True.
- A Draft stored before this change loads as never Ready. The app has never been deployed,
  so only development data is affected. This is stated here, not hidden.
- `services/run_diff.py`: add `"was_ready"` to `RUN_DIFF_IGNORED_KEYS`. The history already
  records the status change that sets it; a second line would be noise.
- The Mark Ready fingerprint (`routes/runs.py` `_export_input_fingerprint`) is not changed:
  `was_ready` is the same in both copies it compares.
- Exports: `json_exporter` builds its own dict and the sheet exporters do not read the
  field, so no export changes. A test proves the v2 sheet and the JSON export are the same
  bytes whether `was_ready` is True or False.

### Deleting only the version that was checked

Today `BaseRepository.delete` deletes by id alone. Between the rules check and the delete,
another request can add samples to an empty Draft (or change it in any other way); the
delete then removes those samples too, and the kept copy would miss them. (Review P1.)

- New `RunRepository.delete_if_unchanged(run: SequencingRun) -> bool`:
  `delete_one({"_id": run.id, "updated_at": run._loaded_updated_at.isoformat()})`, the same
  version check `RunRepository.save` already uses. It returns True if it deleted the run,
  False if nothing matched (the run changed, or is already gone).
  - If `run._loaded_updated_at` is None (a run that was never loaded) it raises
    `ValueError` — it never falls back to an id-only delete.
- **Both** delete paths use it: `delete_run` on the dashboard and the blank-run discard in
  `new_run_from_chosen_template`. The id-only `delete` is no longer called for runs.
- Every run edit bumps `updated_at` (`saving_run` → `touch`), so "unchanged" means
  "exactly the version whose rules were checked and whose copy was taken".

### The copy store

A copy is written **before** the run is deleted, so a failed delete can never lose the run
and its copy both. Each delete attempt writes its own copy, and a copy is only ever
**added** or moved forward from `pending` — never replaced or removed. (Review P1 #2.)

- New model `models/deleted_run.py`, `DeletedRun`:
  - `copy_id: str` (a new uuid per attempt — the document `_id`), `run_id: str`;
  - `state: str` — `"pending"` → `"completed"` or `"abandoned"`; nothing else;
  - summary fields copied from the run so the list page never loads a snapshot:
    `run_name`, `status` (the status at the time), `sample_count`, `created_by`;
  - `deleted_by: str` (256-char cap, like `created_by`), `started_at: datetime`,
    `finished_at: Optional[datetime]` (set when the state leaves `pending`),
    `abandon_reason: str` (`""` unless abandoned);
  - `run: dict` — the whole `run.to_dict()` of the checked version, including the
    pre-generated sheets, JSON and validation PDF exactly as they were made.
- New repository `repositories/deleted_run_repo.py`, `DeletedRunRepository`, collection
  `deleted_runs`, indexes on `(run_id, state)` and `started_at`:
  - `start(copy: DeletedRun) -> None` — `insert_one`, state `pending`. Never replaces
    anything: a clash on `_id` raises.
  - `mark_completed(copy_id, at) -> bool` and `mark_abandoned(copy_id, at, reason) -> bool`
    — `update_one({"_id": copy_id, "state": "pending"}, {"$set": …})`. They move only a
    `pending` copy, so a `completed` copy can never be changed by a later request. True if
    the copy moved.
  - `list_for_page() -> list[dict]` — summaries only (no `run` snapshot) of every
    `completed` or `pending` copy, newest `started_at` first.
  - `get(copy_id) -> Optional[DeletedRun]` and `has_completed(run_id) -> bool`.
  - **No delete and no replace method.** Nothing in the app can remove or overwrite a copy.
- `context.py`: `deleted_run_repo: Optional[DeletedRunRepository] = None`; `startup.py`
  wires it next to `run_history_repo`.

### The delete, step by step (`routes/dashboard.py` `delete_run`)

1. The rules in the table above. Same order as today; the new once-Ready check sits in the
   empty-Draft branch.
2. If the run needs a copy (`run.was_ready`, which covers Archived):
   - `ctx.deleted_run_repo` is None → refuse, `reason="no_copy_store"` — fail closed,
     never delete without the copy;
   - `start(pending copy)` raises → refuse, `reason="copy_failed"`.
   - Either refusal: **HTTP 500** with **"Could not keep a copy of this run, so it was not
     deleted. Nothing was changed."**, and an audit event `run.delete.failed`
     (`outcome="failure"`). The run is not touched.
3. `ctx.run_repo.delete_if_unchanged(run)`.
   - **Raises** (database error): the copy stays `pending` (we cannot know whether the run
     went); audit `run.delete.failed`, `reason="delete_error"`, `copy_id`; **HTTP 500**
     "Could not delete this run. Reload the page to see whether it is still there." The
     Deleted runs page shows the truth (below).
   - **False** (the run changed, or another request deleted it first):
     `mark_abandoned(copy_id, reason="run_changed")`; audit `run.delete.failed`,
     `reason="run_changed"`; `ConflictError` → **HTTP 409** "Someone else changed or
     deleted this run at the same moment, so your delete did nothing. Reload the page to
     see where it stands." No `run.deleted` event is written.
   - **True**: continue.
4. `mark_completed(copy_id)`. If that raises, the run is already gone: log the error, audit
   `run.delete.copy_unconfirmed` (`outcome="failure"`, `copy_id`), and still answer as a
   successful delete. The page shows the copy as "Deleted — not confirmed" (below).
5. The history is **not** deleted.
6. `audit("run.deleted", …)` as today, plus `kept_copy=True/False` and `copy_id` when kept.
   Written only after step 3 returned True.

A run that needs no copy (empty, never Ready) skips steps 2 and 4: `delete_if_unchanged`
False → the same 409 and `run.delete.failed` (`reason="run_changed"`), no `run.deleted`.

`routes/run_templates.py` `new_run_from_chosen_template` deletes the New Run page's blank
run. Its condition gains `and not blank.was_ready`; it uses `delete_if_unchanged`; if that
returns False the blank run is left alone (someone is using it), the template run is still
opened, `run.delete.failed` (`reason="run_changed"`, `context="replaced_by_template"`) is
audited, and no `run.deleted` is written. It no longer deletes history.

Removed, because nothing may delete history any more:
`services/run_history.cascade_delete_history_safe` and
`RunHistoryRepository.delete_by_run`. The history repository becomes insert-and-read only,
like the audit trail's.

### Dashboard buttons (`templates/_dashboard_run_table.html`)

- Empty Draft: **Delete** shows when `not run.was_ready or user.is_admin`. For a once-Ready
  run the confirm text is: "This run was Ready once. Delete it? A copy and its change
  history are kept on Admin → Deleted runs."
- Archived, admin: the confirm text becomes: "Delete this archived run? A copy and its
  change history are kept on Admin → Deleted runs."
- Everything else is unchanged. Cancel on New Run is unchanged (a new run is never Ready).

### Admin → Deleted runs

New `routes/admin/deleted_runs.py`, router-level `require_admin_dep`, registered in
`app.py`, plus a sidebar link **Deleted runs** under **Audit trail**.

- `GET /admin/deleted-runs` — a table, newest first: run name (links to the detail page),
  status when deleted, samples, created by, deleted by, deleted at, and a **State** column.
  Empty state: "No runs have been deleted."
- What the page shows is decided when the page is read, from the copy **and** the live
  `runs` collection, so a failed delete never looks like a finished one (review P2). The
  page only reads; it never changes a copy.

  | Copy state | Also true | Shown? | State column |
  |---|---|---|---|
  | `completed` | — | yes | **Deleted** |
  | `pending` | a `completed` copy exists for the same run | no (another attempt finished) | — |
  | `pending` | the run is still in `runs` | no — nothing was deleted, or a delete is still under way | — |
  | `pending` | the run is gone, no `completed` copy, and this is the newest pending copy of that run | yes | **Deleted — not confirmed** |
  | `abandoned` | — | no (the run was not deleted; the audit trail has `run.delete.failed`) | — |

  "Deleted — not confirmed" means the app stopped (or its database write failed) after
  the run was deleted but before it marked the copy done; the copy is still the run as it
  was deleted. A note under the table says so in one sentence.
- `GET /admin/deleted-runs/{copy_id}` — read only, for a copy the list would show;
  otherwise 404 "No deleted run with that id.":
  - the State (as above), run name, description, status when deleted, instrument and
    flowcell, created by/at, last changed by/at, deleted by, deleted at (`finished_at`, or
    `started_at` for "not confirmed");
  - the Sample IDs, one per line, in the run's order;
  - the change history panel (the first 50 entries, with **Load older**).
- `GET /admin/deleted-runs/{copy_id}/history?before_ts=&before_id=` — the next history
  page, for the copy's `run_id`, same rules as `/runs/{run_id}/history` (half a cursor →
  400; 404 for a copy the list would not show).
- `templates/runs/_history_list.html` gets one variable, `history_url` (default
  `/runs/{run.id}/history`), used by its **Load older** button; the admin page passes its
  own URL. Nothing else in the template changes.
- No undo, no download of the kept sheet. Both can come later (see "Not in scope").
- `/runs/{run_id}/history` is unchanged; for a deleted run it still answers 404.

## N-27 (F19, F20) — only the maker or an admin changes a template

- `routes/run_templates.py`: one helper,
  `_require_template_owner_or_admin(request, template) -> None`, the same rule as
  `remove_index_kit`:
  - no signed-in user → 403;
  - admin → allowed;
  - `template.created_by == user.username` → allowed;
  - otherwise `HTTPException(403, "You can only change templates you made. Ask the person
    who made it, or an admin.")`.
- `update_template` (the rename route, F19) and `delete_template` (F20) load the template
  (404 if missing, as today), then call the helper, then act. The template is untouched on
  a 403.
- A template with an empty `created_by` can only be changed by an admin.
- `templates/run_templates/list.html`: the **Delete** button shows only when
  `user.is_admin or t.created_by == user.username`.
- `list_templates`' docstring ("org-wide template library") gains: "anyone may use a
  template; only its maker or an admin may rename or delete it".
- Creating a template and starting a run from one are unchanged: anyone may do both.
- The rename route keeps having no button. Removing it is a group 4 (dead code) question.

## Existing tests that change (behaviour change, on purpose)

- `tests/integration/test_run_history.py`
  - `test_deleting_archived_run_removes_its_history` → becomes "keeps its history" and
    checks the copy.
  - `test_delete_by_run` and `test_cascade_delete_survives_history_failure` are removed
    with the code they test.
  - The helper at about line 330 that calls `delete_by_run` to drop the auto "created"
    entry deletes from the collection directly instead.
- `tests/integration/test_dashboard_run_actions.py` and
  `tests/integration/test_run_templates_routes.py` keep their tests; new ones are added.

## Tests (each seen failing first)

Unit:
- `was_ready`: default False; set by status READY; set by status ARCHIVED; kept after
  READY→DRAFT; cannot be assigned back to False; `SequencingRun(status=READY)` gives True;
  `from_dict` of a Ready/Archived doc without the key gives True; a Draft doc without the
  key gives False; round-trips through `to_dict`/`from_dict`.
- The history diff of a DRAFT→READY save has a status line and no `was_ready` line.
- Exports are byte-identical with `was_ready` True vs False (v2 sheet, JSON).
- `DeletedRunRepository`: `start` then `get` returns the snapshot as `pending`; `start`
  with an existing `copy_id` raises and leaves the first copy unchanged; `mark_completed`
  and `mark_abandoned` move only a `pending` copy (a second call, or a call on a
  `completed` copy, returns False and changes nothing); `list_for_page` is newest first,
  has no `run` snapshot, and leaves out `abandoned` copies; the class has no delete or
  replace method.
- `RunRepository.delete_if_unchanged`: deletes the loaded version (True); returns False
  and deletes nothing when the stored `updated_at` differs; returns False when the run is
  gone; raises `ValueError` for a never-loaded run.

Integration:
- A standard user cannot delete an empty Draft that was Ready once (403, message, run
  still there, no copy); an admin can (copy `completed`, history kept, `run.deleted` with
  `kept_copy=True` audited).
- An admin deletes an Archived run: copy `completed` with the sheet bytes, history kept.
- An empty never-Ready Draft: anyone deletes it; no copy; its history rows stay.
- The copy fails (monkeypatched `start` raises): 500, message, run still there, history
  still there, `run.delete.failed` audited, no `run.deleted`. Same with no copy store.
- **Review case 1 — the run changes after the copy is taken.** `start` is wrapped so that,
  right after the copy is written, another request adds a sample to the run in the
  database. The delete answers 409 with the message; the run is still there **with the
  new sample**; the copy is `abandoned`; `run.delete.failed` (`run_changed`) is audited
  and `run.deleted` is not; the Deleted runs page does not list it. The same case for a
  never-Ready empty Draft (no copy): 409, the run and its new sample remain.
- **Review case 2 — two overlapping deletes.** Request A loads the run (version 1); the
  run is edited (version 2); request B loads version 2 and deletes it (copy `completed`,
  `deleted_by` B, snapshot version 2). A then runs: its own copy is written as a
  separate record, its delete matches nothing, its copy is `abandoned`, it answers 409,
  and B's `completed` copy is byte-for-byte unchanged — same snapshot, same `deleted_by`.
  The page lists exactly one entry for the run: B's. Also the same-version case: A and B
  both load version 1, B finishes first; A is refused the same way.
- **Review case 3 — the copy is saved but the delete fails.** `delete_if_unchanged`
  monkeypatched to raise: 500, "Could not delete this run…", the run is still live, the
  copy stays `pending`, `run.delete.failed` (`delete_error`) is audited, no `run.deleted`;
  the Deleted runs page does **not** list it and its detail URL is 404.
- The delete succeeds but `mark_completed` raises: the run is gone, the answer is a
  successful delete, `run.delete.copy_unconfirmed` and `run.deleted` are audited, and the
  page lists the run as "Deleted — not confirmed" with its detail page.
- A stale `pending` copy of a run that was later deleted properly is not listed; only the
  `completed` copy is.
- New Run's "Start from a template" still discards the blank run and keeps a once-Ready
  empty draft passed as `discard_run_id`; if the blank run changed first, it is kept, the
  template run still opens, and no `run.deleted` is written.
- Dashboard: Delete shows for a once-Ready empty Draft to an admin, not to a standard user.
- `/admin/deleted-runs`: 403 for a standard user; lists copies newest first; the empty
  state; the detail page shows the State, Sample IDs and the history; 404 for an unknown
  id and for an `abandoned` copy; the history page URL pages older entries and refuses
  half a cursor; a run name with HTML in it is escaped.
- Templates: user B cannot rename or delete user A's template (403, message, template
  unchanged); A can; an admin can; a template with no maker is admin-only; missing → 404;
  the list page shows Delete to A and to an admin, not to B.

Browser:
- An admin deletes an Archived run from the dashboard, opens Admin → Deleted runs, and
  sees it with its history.

## Docs

- `user-guide/change-history.rst` — the warning goes; history is never deleted, and an
  admin can read a deleted run's history on Admin → Deleted runs.
- `user-guide/dashboard.rst` — the delete rules (the table above, in words) and that a copy
  is kept; the warning goes.
- `user-guide/export.rst` (about line 214) — the sentence saying deletion discards history.
- `user-guide/templates.rst` — the maker-or-admin rule replaces "any signed-in user can
  delete one".
- New `admin-guide/deleted-runs.rst` (in the toctree after `audit-trail`) with two
  pictures: the list and the detail page.
- `admin-guide/audit-trail.rst` — `run.delete.failed` (its reasons),
  `run.delete.copy_unconfirmed`, and the `kept_copy` / `copy_id` details.
- `admin-guide/deleted-runs.rst` explains the two States, and that a delete refused with
  "Someone else changed or deleted this run…" leaves the run as it is.
- Pictures regenerated only where the page changed; regenerate twice and diff to separate
  real changes from drift (see the 1c lesson).

## Review changes (2026-09-28, before the plan)

An outside review (Astra) of `f01e6b1` found three problems. It reproduced each one with
the existing repository code and a stand-in copy store. All three were checked against
the code and accepted:

- **P1: deletion must check the saved run version.** The delete was id-only, so a sample
  added after the copy was taken would be deleted too and missing from the copy. Now it
  uses `delete_if_unchanged`, on both delete paths, and refuses with 409 if the run changed.
- **P1: an older request could overwrite a finished copy.** The copy was an upsert keyed by
  run id. Now each attempt inserts its own copy, and only a `pending` copy can move; a
  `completed` copy can never be changed. `run.deleted` is written only after the run delete
  really matched.
- **P2: a failed delete looked like a finished one.** Now copies have states, and the page
  decides what to show from the state and the live `runs` collection (table above). The
  audit events say what really happened.

The three reproductions are review cases 1–3 in the tests above.

## Not in scope (later groups)

- F17 (anyone can read any run's history), F18 (template scaffold always empty), F21 (raw
  id in the "created from" line).
- Undo a delete; download a deleted run's kept sheet.
- A never-Ready Draft with samples stays undeletable, with today's message.
- Removing the rename route (F19) — group 4.
