# Index collisions: when two dual-index samples in one lane clash — design

Date: 2026-10-12. Base: main `d91b652`. Branch `fix/identity-checks` (night run, batch 1,
item 1c). Decision: the user. Source: open item S-6 / question Q1.

**Status: DECIDED and BUILT (2026-10-13).** The night run wrote this as a spec only and
asked (its Q1). The user revisited the decision with the evidence below and chose the AND
rule ("both close") for every run, not only for DRAGEN-converted ones: the guide
(`docs/user-guide/validation.rst`) and the v2 sheet's target box on API Exports say that the
collision check follows DRAGEN's built-in BCL conversion and that standalone bcl-convert
3.10.5+ is stricter. The user also confirmed that combinatorial plates must stay allowed
(the AND rule gives 0 alarms on the measured plate). Built as in "What would change in the
app" items 1, 2, 3, 5, 6 and 7: an `IndexCollision` carries both distances and both limits,
and the report's older `hamming_distance` / `mismatch_threshold` keep their summed meaning.
Item 4 (the heatmaps) only gained a sentence in the guide; the combined view stays.

The original status, kept for the record: SPEC ONLY. No code was written for this item, and
none should be written from this spec without the decision in "NOT BUILT IN THIS RUN — AND
WHY" being revisited.

## The rule as decided

Today `services/index_collision_validator.py: _check_sample_pair_collision` flags a pair of
dual-index samples that share a lane when the **sum** of the two distances is inside the
summed budget:

```
d_i7 + d_i5 <= 2 * (m_i7 + m_i5)        # today, "SUM"
```

The decision replaces that, for a pair where **both** samples carry an i7 **and** an i5,
with an AND of two per-index tests:

```
d_i7 <= 2 * m_i7   AND   d_i5 <= 2 * m_i5        # decided, "AND"
```

- `d_i7` / `d_i5` are the Hamming distances over the cycles actually **read** at
  demultiplexing (`effective_index_sequence`), not the full stored sequences — unchanged.
- `m_i7` / `m_i5` are the mismatch numbers the Sample Sheet gives BCL Convert for the pair:
  the larger of the two samples' numbers, from the sheet plan where it has one, else the
  per-sample value, else the run default (`_effective_mismatches`) — unchanged.
- A pair where either sample is single-index keeps today's rule (`d_i7 <= 2 * m_i7`) —
  unchanged.
- The run-level and per-sample mismatch numbers stay 0, 1 or 2 (the values BCL Convert
  accepts; default 1).

Nothing about the Sample Sheet bytes changes. What changes is only which runs SeqSetup
refuses at **Mark Ready**, and what the validation page and the PDF report list.

## The evidence

No network access was used for this spec; every quotation below is taken from the night
run's brief, which recorded Illumina's public documentation for this item.

### DRAGEN integrated BCL conversion — the AND rule is the documented default

The lab runs DRAGEN 4.3 (moving to 4.4 soon).

- https://help.dragen.illumina.com/dragen-v4.3/product-guide/dragen-v4.3/bcl-conversion
- https://help.dragen.illumina.com/dragen-v4.5/product-guides/dragen-v4.5/bcl-conversion

> "When disabled (default), a barcode collision among samples in the corresponding lane(s)
> will be identified if both indices (index and index2) have a collision."

> "When enabled for any given lane, a barcode collision among samples in the corresponding
> lane(s) will be identified if at least one index (index or index2) have a collision."

`IndependentIndexCollisionCheck` is documented as a "Semi-colon-separated list of lanes
which will use stricter validation"; its default is empty, i.e. disabled.

> "BarcodeMismatchesIndex1" / "BarcodeMismatchesIndex2": "The number of allowed mismatches
> between the first/second Index Read and index sequence" — values 0, 1 or 2, default 1.

**SeqSetup never writes `IndependentIndexCollisionCheck`.** Measured on this worktree at
`d91b652`:

```
$ grep -rn "IndependentIndexCollisionCheck" . --exclude-dir=.git --exclude-dir=graft --exclude-dir=.pixi
(no output; exit status 1)
```

So a run SeqSetup writes is converted by DRAGEN under the default — the AND rule.

### Standalone BCL Convert v3.10.5 and later — the OR rule is the documented default

- https://support-docs.illumina.com/SW/BCL_Convert_v4.0/Content/SW/BCLConvert/BCLConvert.htm

> "BCL Convert v3.10.5 and later uses strict barcode collision logic to support increased
> high-throughput and complex sample pooling."

> "Each index in a dual setup must individually meet the hamming distance requirements set
> by the BarcodeMismatchesIndex# value."

> "If either i7 or i5 does not meet the hamming distance requirements the program will
> error."

> "Barcodes must differ by at least 3 bases." (for the default mismatch values)

> "If any two samples in i7 differ by fewer than 3 bases, an error is produced and the run
> will not proceed, regardless of the samples i5 values."

> "If any two samples in i5 differ by fewer than 3 bases, an error is produced and the run
> will not proceed, regardless of the samples i7 values."

That is the OR rule: either index too close is an error, whatever the other index does.

## The measurement

Run on this worktree's code at `d91b652` with the shipped
`config/indexes/nextera_xt_combinatorial.yaml` — the script is the night run's
`scratch/measure_1c.py`; it changes no code. 12 i7 × 8 i5 = 96 samples, every i7 × i5
combination once, all in lane 1 of a NovaSeq X 10B, run cycles 151/151/8/8, barcode
mismatches 1/1 (so every threshold is `2 * 1 = 2`, and the summed threshold is 4):

```
kit Nextera XT Index Kit v2 1.0.0: 12 i7 x 8 i5 = 96 samples, default_index1_cycles=8, default_index2_cycles=8
run: 96 samples in lane 1, mismatches 1/1
total sample pairs in the lane: 4560
today's rule (d_i7 + d_i5 <= 2*(m_i7+m_i5) = 4), as the validator reports it: 92
today's rule, recomputed here:                                  92
AND rule   (d_i7 <= 2 and d_i5 <= 2):                           0
OR rule    (d_i7 <= 2 or  d_i5 <= 2):                           864
pairs sharing an identical i7 sequence:                         336
pairs sharing an identical i5 sequence:                         528
distinct i7 sequences: 12; distinct i5 sequences: 8
a pair the OR rule refuses and today's SUM rule accepts: ('S001', 'S002', 'ATTACTCG', 'ATTACTCG', 'TATAGCCT', 'ATAGAGGC', 0, 8)
a pair today's SUM rule refuses and the AND rule accepts: ('S001', 'S003', 'ATTACTCG', 'ATTACTCG', 'TATAGCCT', 'CCTATCCT', 0, 3)
minimum distance between two i7 sequences: 4; between two i5 sequences: 3
distinct i7 sequence pairs within 2: 0 of 66
distinct i5 sequence pairs within 2: 0 of 28
```

Reading those numbers:

- Today's SUM rule reports **92** collisions on an ordinary, correctly built combinatorial
  plate. Every one is a false alarm in the sense that no two samples share both indexes;
  92 red lines per plate is alarm fatigue, which is itself a clinical hazard.
- The AND rule reports **0** on this plate: no pair has both indexes within 2.
- The OR rule reports **864** — every pair that reuses an i7 (336) plus every pair that
  reuses an i5 (528). On a combinatorial plate that is by design: the whole point of 12 i7
  × 8 i5 is that each i7 appears 8 times and each i5 appears 12 times.
- The two sets do not nest. `S001` vs `S002` (identical i7 `ATTACTCG`, i5 distance 8) is a
  pair the **OR** rule refuses and today's SUM rule **accepts** (0 + 8 = 8 > 4). `S001` vs
  `S003` (identical i7, i5 distance 3) is a pair today's SUM rule **refuses** and the AND
  rule **accepts** (3 > 2). So today's rule is neither uniformly stricter nor uniformly
  looser than either candidate: it can pass a pair the strict converter refuses, and refuse
  a pair the lab's converter would convert happily.

## What would change in the app, if it were built

1. `services/index_collision_validator.py: _check_sample_pair_collision`, the
   `both_have_i5` branch only: the test becomes the AND of the two per-index tests. An
   `IndexCollision` would then need to carry both distances and both thresholds, or the
   report text has to change, because `hamming_distance` / `mismatch_threshold` are today
   the combined distance and the summed threshold.
2. `models/validation.py: IndexCollision.collision_description` — "distance
   {hamming_distance} <= threshold {mismatch_threshold}" states the rule and would have to
   state the new one (e.g. "i7 distance 1 <= 2 and i5 distance 0 <= 2").
3. `templates/validation/_collision_detail.html` — "(distance: N)" is the combined
   distance; it would show the two distances.
4. `templates/validation/_heatmaps_tab.html` — the "i7+i5" (combined) heatmap and the
   legend ("Lower values (red) indicate potential collision risk", red at 0/1/2) describe
   the summed distance. Under the AND rule the combined heatmap no longer corresponds to
   the rule, and the per-i7 and per-i5 heatmaps do.
5. `services/validation_report.py` — the PDF/JSON report's "Index Collisions" count and
   its per-collision rows carry `hamming_distance` / `mismatch_threshold`.
6. `docs/user-guide/validation.rst` — "Two samples in the same lane with the same (or too
   similar) an index are reported here as a collision" and the warning under it would have
   to say "the same (or too similar) **pair** of indexes", and say which converter the rule
   follows.
7. Tests: the Nextera XT plate gives 0 collisions; a real collision (both indexes close) is
   still flagged; a single-index pair is unchanged; the heatmap / report texts that state
   the rule say the new rule.

## NOT BUILT IN THIS RUN — AND WHY

The decision was conditional: build the AND rule **only if** Illumina's documentation does
not show BCL Convert refusing pairs the AND rule would accept, because the rule must never
be looser than BCL Convert's. It does show that, so nothing was built.

1. **Illumina's standalone BCL Convert documentation refuses pairs the AND rule accepts.**
   "If any two samples in i7 differ by fewer than 3 bases, an error is produced and the run
   will not proceed, regardless of the samples i5 values." Under the AND rule SeqSetup
   would pass the measured plate (0 collisions) while every one of its 336 identical-i7
   pairs is, by that sentence, an error for standalone BCL Convert v3.10.5+.
2. **The two documentation sets disagree.** DRAGEN's integrated BCL conversion (v4.3, the
   version the lab runs, and v4.5) documents the AND rule as the default and the OR rule as
   an opt-in per lane (`IndependentIndexCollisionCheck`, default empty — and SeqSetup never
   writes it). Standalone BCL Convert v3.10.5 and later documents the OR rule as the
   behaviour, with no setting to relax it. Which rule is "BCL Convert's" therefore depends
   on which converter the lab's pipeline actually invokes, and SeqSetup does not record
   that per run.
3. **The documentation does not clearly state whether the strict check compares sample
   pairs or distinct index sequences.** This is not a detail: on the measured plate the OR
   rule reports **864** collisions read as sample pairs, and **0** read as distinct index
   sequences (`distinct i7 sequence pairs within 2: 0 of 66`; `distinct i5 sequence pairs
   within 2: 0 of 28` — the closest two i7 sequences are 4 apart and the closest two i5
   sequences 3 apart). The sentences quoted above say "any two samples", which reads as
   sample pairs and would refuse every ordinary combinatorial plate; that reading is hard
   to believe of a converter Illumina ships for "complex sample pooling", which suggests
   the sequence reading — but Illumina does not say so.
4. **What the failure would look like.** Under the AND rule, a run SeqSetup marks Ready
   could be refused by a standalone BCL Convert v3.10.5+ at conversion time. That failure
   is loud: the conversion stops with an error and nothing is reported. It is not a wrong
   patient result and not a silent misassignment of reads. That is why the AND rule is a
   defensible choice for this lab — but it is a choice between "SeqSetup warns about
   nothing real 92 times per plate" and "a run may fail at the converter", and only the
   human can make it.
5. **Today's SUM rule is not uniformly stricter than either candidate** (measured above):
   it accepts `S001`/`S002`, two samples with an **identical i7**, which the strict rule
   refuses; and it refuses `S001`/`S003`, which the AND rule accepts. So "leave it as it
   is" is not the safe default either — it is a third rule that matches neither converter.

The question for the human, with the options, is in the night run's `QUESTIONS.md` (Q1).
