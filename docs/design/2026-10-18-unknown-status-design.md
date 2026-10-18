# A stored run whose status is unknown is refused

## The problem

`SequencingRun.from_dict` and `RunListing.from_doc` turned an unknown stored
`status` into `DRAFT` with a log line, and a missing one into `"draft"` by
default. The comment explained the choice: falling back to Draft (rather than
Archived) keeps a damaged run out of the JSON API and the export pipeline until
an administrator looks at it, and never "silently elevates a corrupted record
into a clinical snapshot".

It also silently unlocks one. A Ready run whose status was damaged -- a database
edit, or a later release renaming a status -- therefore:

- opened as an **editable Draft**: its samples, indexes and cycle counts could
  all be changed, and the edit-lock guard (`get_editable_run`, DRAFT-only)
  allowed it;
- left the API, which serves `ready` and `archived` only;
- and the **first save wrote `"draft"` over the stored value**, so the record
  that the run had ever been Ready was gone -- `was_ready` too, unless the
  stored document happened to carry it.

The last point is the serious one: a damaged status could be repaired by an
administrator while it was still in the document, and the old behaviour
destroyed it on the first mutation.

An open-items review of `e4532f2` (2026-10-18) found it.

## The decision

The same one the user made for an unknown **instrument** on 2026-10-17
(`stored_platform`, `docs/design/2026-10-17-unknown-platform-design.md`): treat
such a document as a damaged one. It cannot be opened, edited, marked Ready,
archived or served until an administrator repairs the stored value, and the
dashboard names it.

## The change

- `models.sequencing_run.stored_status(data, what)` reads the status a stored
  document names and raises `ValueError` -- naming the document and the value --
  for one this release does not know, or none. Both readers use it
  (`SequencingRun.from_dict`, `RunListing.from_doc`), next to the
  `stored_platform` call they already shared.
- The legacy `"complete"` -> `ARCHIVED` mapping stays: SeqSetup wrote that value.
- **A missing status is refused too.** Every version of `to_dict` in this
  repository's history writes `"status": self.status.value` -- all 27 of them,
  across both paths the file has had, back to the initial commit (`da2a859`) --
  and `RunStatus` never had another member. Only `RunRepository` writes the
  `runs` collection, and only through `to_dict()` (plus `mark_changed`, which
  does not touch `status`), with no upsert anywhere. So only a document changed
  outside SeqSetup lacks the field.
- The dashboard, its tabs and its search already name a run they cannot list
  (`list_readable_summaries`); opening one fails, as for any damaged run, and
  nothing is written. Measured: every collection but `web_sessions` (the auth
  middleware's `last_seen_at`) is byte-identical after a refused request, so no
  audit row either.
- `/admin/deleted-runs` fails for every administrator while such a run has a
  copy whose delete never finished, because `services/deleted_runs.py` checks
  whether the run still exists by loading it -- the same hole the unknown-
  instrument note records, and what the `fix/deleted-runs-damaged` branch of
  this batch closes. `/served-runs` does **not** fail: it lists by status, so a
  damaged status is outside both of its queries.

## What the API does

Unlike an unknown instrument, an unknown status never reaches a reader *from the
list*: `RunRepository.list_summaries` queries `{"status": "ready"}` (or
`"archived"`), and a damaged value matches neither, so the run is outside the set
the API was asked for. `/api/runs` therefore answers 200 with the other runs
rather than failing.

That is deliberate and not a regression: under the old fallback the run was read
as a Draft and equally absent. Nor is the omission new in kind -- a readable
`"complete"` run is omitted from `?status=archived` for the same reason, since
the filter matches the stored string.

What changed is everything else -- the dashboard names it, and each per-run
endpoint (`/api/runs/{id}/samplesheet-v2`, `samplesheet-v1`, `json`,
`validation-report`, `validation-pdf`) loads the run by id and now refuses it,
instead of serving a file from a run read as a Draft.

**What the caller sees is a bare 500**, with the message naming the run and the
value in the log only -- the same as for an unknown instrument
(`stored_platform`), since both raise a plain `ValueError`. That is weaker than
the precedent `CLAUDE.md` sets for a damaged stored export (`ExportDamaged`: a
500 that names the file, audited, never "try again"). Giving a damaged stored
*document* the same treatment -- its own exception, a named 500, an audit row --
would cover the instrument case too and is left for the human to decide.

Making the list itself fail would need a second query per request, for runs
outside the requested status, and would let a damaged draft-ish document block
the Ready listing. Not done.

## For a later release

Renaming or removing a `RunStatus` value now makes every stored run naming it
unreadable, and every deleted run's copy (`deleted_runs.run`) naming it
unreadable on its own page. Such a release must rewrite those records as part of
its upgrade -- the same note the unknown-instrument design carries.
