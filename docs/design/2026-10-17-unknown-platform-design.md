# A stored run or template naming an unknown instrument is refused

## The problem

Every reader of a stored run, listing row or template fell back to NovaSeq X
when the stored `instrument_platform` was one the release does not know, or
missing, with only a log line (`SequencingRun.from_dict`,
`RunListing.from_doc`, `RunTemplate.from_dict`). So a run made for another
instrument -- after a database edit, or a later release renaming an
instrument -- opened as a NovaSeq X run:

- it could be marked Ready with NovaSeq X's i5 direction and settings;
- any save wrote "NovaSeq X Series" over the stored value, archiving a Ready
  run included, so the record itself changed with no word;
- a template started NovaSeq X runs.

The fallback was there so that an archived run never becomes unreadable. An
open-items review of 258ad89 (2026-10-17) found it.

## The decision

The user chose (2026-10-17) to treat such a document as a damaged one, over
opening it locked: it cannot be opened, edited, marked Ready or served until
an administrator repairs the stored value, and the dashboard and the
template lists name it.

## The change

- `models.sequencing_run.stored_platform(data, what)` reads the instrument a
  stored document names and raises `ValueError` -- naming the document and
  the value -- for one the release does not know, or none. The three readers
  use it. Every run SeqSetup has written stores the field, so only a record
  changed outside SeqSetup lacks it.
- The dashboard, its tabs and search already name a run they cannot list
  (`list_readable_summaries`); opening one fails, as for any damaged run, and
  nothing is written. `/api/runs` fails rather than answer without it, the
  rule already pinned for any run the API cannot read.
- `RunTemplateRepository.list_all_readable()` does for templates what the
  run repository does for runs: the Run Templates page and the New Run page
  list the templates that read and name the ones that do not
  (`run_templates/_unreadable.html`). It names any template that does not
  read, as `list_readable_summaries` does for runs, not only this case.
  Starting a run from such a template fails before anything is made or
  deleted, and so do renaming and deleting it.
- Two pages still fail for everyone while such a run is stored, as they
  already did for any run SeqSetup cannot read, and are left as they are:
  `/served-runs` (API Exports), which lists what the API serves and fails
  with it (`docs/design/2026-10-17-listing-summaries-design.md`), and
  `/admin/deleted-runs`, only for a run with a copy whose delete never
  finished, whose existence `services/deleted_runs.py` checks by loading it.
  *(Half closed on 2026-10-18: the deleted-runs **list** asks
  `RunRepository.exists` instead of loading the run, so it opens. Following a
  row to `/admin/deleted-runs/{copy_id}` still fails when that copy's own
  embedded run cannot be read.)*
- An unknown run *status* still falls back to Draft, as before; it keeps a
  run out of the API and the exports.

## For a later release

Renaming or removing an `InstrumentPlatform` value now makes every stored run
and template naming it unreadable, and every deleted run's copy
(`deleted_runs.run`) naming it unreadable on its own page. Such a release
must rewrite those records as part of its upgrade.
