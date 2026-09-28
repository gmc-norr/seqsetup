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

### The copy store

- New model `models/deleted_run.py`, `DeletedRun`:
  - `run_id: str`, `run_name: str`, `status: str` (the status when deleted),
    `sample_count: int`, `created_by: str`, `deleted_by: str` (256-char cap, like
    `created_by`), `deleted_at: datetime`;
  - `run: dict` — the whole `run.to_dict()` at the moment of deletion, including the
    pre-generated sheets, JSON and validation PDF exactly as they were made.
  - The summary fields are copied from the run so the list page never loads the snapshots.
- New repository `repositories/deleted_run_repo.py`, `DeletedRunRepository`, collection
  `deleted_runs`, `_id` = the run id, index on `deleted_at`:
  - `keep(deleted: DeletedRun) -> None` — `replace_one({"_id": run_id}, doc, upsert=True)`.
    Upsert, so a retry after a half-finished delete (copy saved, run delete failed) does
    not fail; the newer copy is at least as recent.
  - `list_summaries() -> list[dict]` — every copy, newest `deleted_at` first, projection of
    the summary fields only.
  - `get(run_id) -> Optional[DeletedRun]`.
  - **No delete method.** Nothing in the app can remove a kept copy.
- `context.py`: `deleted_run_repo: Optional[DeletedRunRepository] = None`; `startup.py`
  wires it next to `run_history_repo`.

### The delete, step by step (`routes/dashboard.py` `delete_run`)

1. The rules in the table above. Same order as today; the new once-Ready check sits in the
   empty-Draft branch.
2. If the run needs a copy (`run.was_ready`, which covers Archived):
   - if `ctx.deleted_run_repo` is None, refuse — fail closed, never delete without the
     copy;
   - otherwise `keep(...)`. If that raises, refuse.
   - A refusal is **HTTP 500** with **"Could not keep a copy of this run, so it was not
     deleted. Nothing was changed."**, and an audit event `run.delete.failed`
     (`outcome="failure"`, `reason="copy_failed"` or `"no_copy_store"`). The run is not
     touched.
3. `ctx.run_repo.delete(run.id)`.
4. The history is **not** deleted.
5. `audit("run.deleted", …)` as today, plus `kept_copy=True/False`.

`routes/run_templates.py` `new_run_from_chosen_template` deletes the New Run page's blank
run. Its condition gains `and not blank.was_ready`, and it no longer deletes history.

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
  status when deleted, samples, created by, deleted by, deleted at. Empty state: "No runs
  have been deleted."
- `GET /admin/deleted-runs/{run_id}` — read only:
  - run name, description, status when deleted, instrument and flowcell, created by/at,
    last changed by/at, deleted by/at;
  - the Sample IDs, one per line, in the run's order;
  - the change history panel (the first 50 entries, with **Load older**).
  - 404 "No deleted run with that id." if there is no copy.
- `GET /admin/deleted-runs/{run_id}/history?before_ts=&before_id=` — the next history page,
  same rules as `/runs/{run_id}/history` (half a cursor → 400).
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
- `DeletedRunRepository`: `keep` then `get` returns the snapshot; `keep` twice for one run
  gives one copy; `list_summaries` is newest first and has no `run` snapshot; the class has
  no delete method.

Integration:
- A standard user cannot delete an empty Draft that was Ready once (403, message, run
  still there, no copy); an admin can (copy kept, history kept, `kept_copy=True` audited).
- An admin deletes an Archived run: copy kept with the sheet bytes, history kept.
- An empty never-Ready Draft: anyone deletes it; no copy; its history rows stay.
- The copy fails (monkeypatched `keep` raises): 500, message, run still there, history
  still there, `run.delete.failed` audited. Same with no copy store.
- New Run's "Start from a template" still discards the blank run and keeps a once-Ready
  empty draft passed as `discard_run_id`.
- Dashboard: Delete shows for a once-Ready empty Draft to an admin, not to a standard user.
- `/admin/deleted-runs`: 403 for a standard user; lists copies newest first; the empty
  state; the detail page shows Sample IDs and the history; 404 for an unknown id; the
  history page URL pages older entries and refuses half a cursor; a run name with HTML
  in it is escaped.
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
- `admin-guide/audit-trail.rst` — `run.delete.failed` and the `kept_copy` detail.
- Pictures regenerated only where the page changed; regenerate twice and diff to separate
  real changes from drift (see the 1c lesson).

## Not in scope (later groups)

- F17 (anyone can read any run's history), F18 (template scaffold always empty), F21 (raw
  id in the "created from" line).
- Undo a delete; download a deleted run's kept sheet.
- A never-Ready Draft with samples stays undeletable, with today's message.
- Removing the rename route (F19) — group 4.
