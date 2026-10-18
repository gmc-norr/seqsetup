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
  repository's history writes `"status": self.status.value` -- checked over every
  commit that ever touched `models/sequencing_run.py`, back to the first
  (`66251be`) -- so only a document changed outside SeqSetup lacks the field.
- The dashboard, its tabs and its search already name a run they cannot list
  (`list_readable_summaries`); opening one fails, as for any damaged run, and
  nothing is written.

## What the API does

Unlike an unknown instrument, an unknown status never reaches a reader *from the
list*: `RunRepository.list_summaries` queries `{"status": "ready"}` (or
`"archived"`), and a damaged value matches neither, so the run is outside the set
the API was asked for. `/api/runs` therefore answers 200 with the other runs
rather than failing.

That is deliberate and not a regression: under the old fallback the run was read
as a Draft and equally absent. What changed is everything else -- the dashboard
names it, and each per-run endpoint (`/api/runs/{id}/samplesheet-v2`,
`samplesheet-v1`, `json`, `validation-report`, `validation-pdf`) loads the run by
id and now refuses it with the message naming the value, instead of serving a
file from a run read as a Draft.

Making the list itself fail would need a second query per request, for runs
outside the requested status, and would let a damaged draft-ish document block
the Ready listing. Not done.

## For a later release

Renaming or removing a `RunStatus` value now makes every stored run naming it
unreadable, and every deleted run's copy (`deleted_runs.run`) naming it
unreadable on its own page. Such a release must rewrite those records as part of
its upgrade -- the same note the unknown-instrument design carries.
