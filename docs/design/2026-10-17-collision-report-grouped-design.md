# The index-collision report is grouped, not one finding per pair

Decision: 2026-10-17. Replaces nothing; it changes the *shape of the report*
produced by the collision check described in
`2026-10-12-collision-rule-design.md`. **The rule that decides whether two
samples collide is unchanged by this note.**

## The defect

`IndexCollisionValidator.validate_index_collisions` compares every pair of
samples in every lane and appends one `IndexCollision` per colliding pair per
lane. Every surface then multiplies that list:

- `services/validation_summary.error_messages` — one sentence per pair;
  `errors_by_sample` — the same sentence on **both** samples.
- `templates/runs/_validate_panel.html` serialises the per-sample errors into
  a `data-sample-errors` attribute, and the panel is refetched after **every**
  change to the run.
- `templates/runs/_ready_refused.html` lists every message.
- `templates/validation/_issues_tab.html` built its list with a quadratic
  `ns.errors = ns.errors + [...]` inside a Jinja loop.
- the validation cache keeps 64 whole results.

One ordinary click — "Give this same index to all N samples" — makes every
sample in the lane collide with every other. Measured on main `7c95e76`:

| samples x lanes | findings | check | Mark Ready refusal | Check panel attribute | Issues tab |
|---|---|---|---|---|---|
| 300 x 1 | 44,850 | 0.4 s | 7.3 MiB | 13.0 MiB | 32.1 MiB (5.0 s) |
| 1,000 x 8 | 3,996,000 | 42.9 s | 651.7 MiB | 1,152.5 MiB | did not finish in 10 min |

Peak RSS of one 1,000 x 8 request: 6.6 GiB. The application is one process, so
an out-of-memory kill takes it down **for everyone**.

**No wrong sheet.** Any collision blocks Mark Ready, so this is availability
and usability, not a wrong Sample Sheet.

## The decision: group the report, keep the scan

The comparison stays exactly as it is — `_check_sample_pair_collision` is not
rewritten and is still the only code that decides a collision. What changes is
what the scan *collects*.

Per lane, samples are grouped by the **whole of what the comparison reads**:

    key = (effective i7 sequence, effective i5 sequence,
           effective mismatch number for index 1,
           effective mismatch number for index 2 — None when there is no i5)

`_check_sample_pair_collision` reads nothing else about a sample except its id
and display name, which it only puts in the report. So **two samples with the
same key are interchangeable for the comparison**, and one call on a
representative decides the verdict for every pair across two groups.

Two kinds of finding come out, both `IndexCollisionGroup`:

- **One group, one index.** Every sample in a group has the *same* sequences,
  so the Hamming distance within a group is 0 for both indexes and 0 is within
  every tolerance (>= 0): every pair inside a group collides. One finding, with
  the exact count, the sequences, and every member's id and name.
- **Two groups within the tolerance.** For each unordered pair of distinct
  groups, one call on the two representatives. If it collides, one finding
  naming both groups, their counts, sequences and members.

Groups are **never merged by chaining**: collisions within a tolerance are not
transitive (A may be within tolerance of B and of C while B and C are not), so
each pair of groups is reported on its own.

Every colliding `(sample, sample, lane)` triple is still derivable from the
report: a one-group finding means every pair inside `sample1_ids`; a two-group
finding means every `sample1_ids x sample2_ids` pair. `tests/unit/
test_collision_groups_oracle.py` expands the report that way and compares the
resulting set with an independent per-pair oracle kept in the test file.

A group whose effective i7 is empty is skipped entirely — exactly as the old
scan returned `None` for every pair involving one.

## What each surface says now

- `ValidationResult.index_collision_groups` replaces `index_collisions`. The
  field is **renamed**, not re-typed, so every reader had to be revisited: a
  silent type change under the old name would have let tests pass with
  different meaning.
- `error_count` and `has_errors` count **findings (groups), not pairs**. A
  refusal therefore says "3 errors to fix first" where it once said "44,850".
  No message states a pair count it has not computed; a finding that stands for
  more than two samples says how many samples share the index.
- Sample names inside a message are capped at `MAX_LISTED_SAMPLE_NAMES` (5) and
  the text then says "and N more" with the exact remainder. A finding standing
  for exactly two samples keeps today's wording ("A (SEQ) vs B (SEQ) - rule"),
  so the ordinary small case reads as it always did.
- `errors_by_sample` marks every sample a finding names — the whole membership,
  not just the examples — and caps the messages on one sample at
  `MAX_SAMPLE_ERROR_MESSAGES` (20), adding one line with the exact number of
  further collision findings for that sample.
- The Issues tab's list is built in Python (`validation_summary.issue_rows`)
  and passed in; the template only renders it.
- `_collision_detail.html` lists at most `MAX_LISTED_SAMPLE_NAMES` names per
  side and says how many are not shown.
- The validation report JSON keeps its `errors.index_collisions` key; each row
  now carries `sample1_names` / `sample2_names` (capped) and
  `sample1_count` / `sample2_count` instead of two single names. A **Ready run
  has no collision**, so every stored validation report is unchanged except its
  timestamp.
- `IndexCollisionValidator.validate_index_collisions` (the per-pair form) is
  **kept** as the low-level API the collision-rule unit tests drive. Nothing in
  `src/` calls it; `validate_index_collision_groups` is the production path.

## What is not fixed

The scan is still O(n^2) per lane: a valid 5,000-sample 8-lane run still
compares every pair. That is option B in the F5 plan and is deliberately out of
scope — rewriting the comparison is the one change that could silently stop
finding a collision.

The number of findings is still O(groups^2) when nearly every index collides
with nearly every other (short indexes with a tolerance of 2, say). That is no
worse than today and the measured, ordinary case — one shared index — collapses
to one finding per lane.

## What proves it

- `tests/unit/test_collision_groups_oracle.py` — a generative property test
  over fixed-seed random runs: the set of colliding (sample id, sample id, lane)
  triples expanded from the grouped report equals an independent per-pair
  oracle's set, exactly, and `error_count > 0` agrees.
- `tests/unit/test_collision_groups.py` — the planted corpus (a pair that
  collides only because of the tolerance, and one only after the i5 direction
  is applied, per index mode and tolerance), the grouping keys, the caps, and
  the "no chaining" rule.
- `tests/integration/test_collision_report_size.py` — the asserted ceilings at
  300 x 1 and 1,000 x 8.
- `tests/unit/test_validation.py` and `tests/unit/test_collision_rule.py` still
  drive the unchanged per-pair comparison.
