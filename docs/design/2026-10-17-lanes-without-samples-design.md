# Mark Ready asks about a lane no sample is on

## The problem

A lane of the flow cell that no sample is on gets no row in the Sample
Sheet, so no read from it can be assigned to a sample. Nothing said so:

- A paste starts in lane 1, so samples pasted on a NovaSeq X `10B` leave
  lanes 2-8 empty unless someone ticks **All lanes**.
- Changing the flow cell keeps every sample's lanes (`update_flowcell`), so
  samples put in both lanes of a `1.5B` are on lanes 1 and 2 only of a
  `10B`.

The checks caught only the other way round: a sample on a lane the flow cell
does not have (`lane_out_of_range`, an error). An open-items review of
258ad89 (2026-10-17) found it.

## The decision

The user chose (2026-10-17) to **ask at Mark Ready**, as for a color balance
error, over refusing: a lane may be left empty on purpose, but never
unnoticed.

## The change

- `ValidationService.lanes_without_samples(run, total_lanes)`: the lanes of
  the flow cell no sample is on. A sample with no lane is on every lane (the
  sheet then has no `Lane` column for it, or the plan refuses it as
  `lanes_not_picked`); a lane outside the flow cell fills none. The checks
  give one warning, `lanes_without_samples`, naming the lanes, and
  `ValidationResult.lanes_without_samples` carries them.
- The Check panel shows **Lanes without samples: 3, 4, ... · Mark Ready will
  ask**; the validation page lists the warning.
- Mark Ready asks (`runs/_ready_lanes_without_samples.html`) after the color
  balance question, and accepts the answer only for the run version and the
  lanes it was shown, as the color balance question does. The denial is
  audited `lanes_without_samples_unconfirmed`, and the accepted lanes go into
  the `run.status.changed` row as `lanes_without_samples_accepted`. The
  question's form carries the color balance answer too, so a run asked both
  is not asked the first again.
- The Check panel says "Mark Ready will ask" only on a Draft, for this
  badge and the color balance one: a Ready run's panel, whose checks run
  live, still names the lanes.
- The Sample Sheet does not change. The validation report written at Mark
  Ready (JSON and PDF) carries the new warning, so its warning count is one
  higher for such a run.

## Tests

Test runs that stood for "a run Mark Ready accepts without a question" put
their samples on lane 1 of an 8-lane flow cell; they now put them on every
lane (`_clean_run`, `_wgs_draft`, and a few runs of their own). The helper
`conftest.mark_ready` answers both questions. The color balance tests keep
lane 1 and answer the lanes question where they go on to Ready.
