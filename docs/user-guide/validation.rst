Validation
==========

Every Draft run has a **Check** panel above its Export panel, on the run's
own page. It re-runs automatically after every change -- add a sample,
assign an index, edit an override -- so it always reflects what is
currently saved, not what the page looked like when it was first loaded.

The Check panel
----------------

.. figure:: /_static/screenshots/check/panel.png
   :alt: The Check panel showing Samples, Indexes and Errors status badges, an error list, and an "Open the validation page" link.

   The Check panel, outlined.

The panel shows a badge for the sample count, a badge for how many samples
have an index assigned, and -- only when there is at least one -- a badge
for the number of errors. When any lane has a color balance warning or
error, an amber **Color balance: N lane(s)** badge appears too -- with
"· Mark Ready will ask" when a lane has a color balance *error* -- see
`Color balance`_ below for what that counts. Up to ten error messages are
listed directly underneath; beyond ten, the panel says how many more there
are and points to the full validation page. Errors it finds are the same
fixes needed to pass **Mark Ready** -- see :doc:`export`.

Select **Open the validation page** for the full picture: every error and
warning in detail, an index distance heatmap per lane, and a color
balance table per lane.

Errors and warnings
--------------------

The validation page's **Issues** tab lists every error first, then every
warning. Two samples in the same lane with the same (or too similar) an
index are reported here as a collision; a sample with no test assigned is
reported as a missing-test error; and so on.

.. figure:: /_static/screenshots/check/validation-issues.png
   :alt: The validation page's Issues tab, listing index collision and other errors in red.

   The Issues tab, outlined.

.. warning::
   Two samples that share a lane must not share an index -- with nothing
   to tell their reads apart, demultiplexing cannot say which sample a
   read actually came from. SeqSetup does not refuse to *save* this in a
   Draft run; the Check panel and the Issues tab mark it as an error, but
   the run is only actually blocked at **Mark Ready** (see :doc:`export`).
   Do not assume a run is safe because it saved without complaint -- check
   the Issues tab, or the Check panel's error count, before relying on it.

What else can block Mark Ready
----------------------------------

An index collision and a missing test are only two of the checks that can
put an error on the Issues tab. If **Mark Ready** refuses a run, the reason
is one of these:

- **No run name.** *"Run has no name; give it a name in Run Setup before
  marking it ready."*
- **No samples.** *"Run has no samples; add samples before marking the run
  as ready."*
- **Sample(s) with no index assigned.**
- **Too many cycles for the reagent kit.** The run's total cycles (Read 1 +
  Index 1 + Index 2 + Read 2) exceed what the kit and instrument allow.
- **Instrument disabled.** An administrator has switched the run's
  instrument off. Pick another in Run Setup. Only Draft runs get this
  error.
- **Sample ID has invalid characters.** Only letters, digits, ``-`` and
  ``_`` are allowed.
- **A sample assigned to a lane the flowcell doesn't have.**
- **Duplicate Sample ID.** The same Sample ID used more than once in the
  run.
- **Inconsistent index length in a lane.** Not every sample sharing a lane
  reads the same number of i7 (or i5) cycles.
- **Mixed single- and dual-indexed samples in a lane.**
- **An index longer than the run's index cycles for that read.**
- **An index whose length differs from the cycles its Override Cycles
  reads** (see :doc:`override-cycles`).
- **A line break in a sample's name, project or description.** *"Sample
  'ID' has a line break in its description. A line break would split the
  sample's row in the Sample Sheet. Remove it before marking the run
  ready."* (The message names each field that has one.)
- **A hidden character in a sample's name, project or description, or in
  the run's name or description** -- a tab, a NUL or another invisible
  control character, or an invisible formatting character such as a
  zero-width space, a byte-order mark or a direction mark, often carried in
  by pasted text. *"Sample 'ID' has a hidden character in its project:
  U+200B. Hidden characters can break the Sample Sheet. Remove it before
  marking the run ready. If you cannot see it, delete the text and type it
  again."* The message names each field and each character by its code.
- **A malformed Override Cycles value**, on the sample or from a kit's
  default read-override pattern.
- **Override Cycles that don't match the run's declared cycles** -- each
  segment must sum to its Read/Index cycle count.
- **An index part of Override Cycles that does not start with the index,
  or holds two runs of index cycles** (see :doc:`override-cycles`).
- **A duplicate index pair in a lane** -- two samples sharing the exact
  same i7 (and i5) sequence. *"Demultiplexing cannot distinguish these
  samples."*
- **An application profile problem**: the sample's test isn't found, the
  application profile it points to isn't found, the application isn't
  available on the run's instrument, the required software version isn't
  available on it, or two samples in the run need different versions of
  the same application.
- **A Sample Sheet that would not carry the run**: a test without a
  BCL Convert profile, or with two profiles for one application; two
  profiles for one application whose Settings or columns differ; a
  profile column written twice, a setting in two places, or a name
  SeqSetup uses spelled otherwise; a BCL Convert profile without a column a
  sample needs, a sample with no lanes picked where the sheet has a Lane
  column, or an empty mismatch cell. See :doc:`/admin-guide/profiles`.

Two warnings point at the Sample Sheets without stopping **Mark Ready**:
*"No v1 sheet will be made for this run: ..."* on MiSeq and NovaSeq 6000
(see :doc:`export`), and a sample whose barcode mismatch number the sheet
cannot carry, because the BCL Convert profile has no column for it -- the
checks use the number the sheet gives.

Every one of these blocks **Mark Ready** exactly the way an index
collision does (see the warning above) -- read the Issues tab for which
one, and which samples, before assuming a run is otherwise ready.

Index distance heatmaps
-------------------------

The **Heatmaps** tab shows, for each lane, the pairwise Hamming distance
between every pair of samples' indexes -- lower numbers (closer to red)
mean a higher risk that a sequencing error could make one sample's index
misread as another's. Separate views are available for i7 only, i5 only,
and the two combined.

.. figure:: /_static/screenshots/check/heatmaps.png
   :alt: The Heatmaps tab, with the i7/i5/combined selector and the colour legend around a 5-sample lane table, outlined, whose cells run from dark red for the closest pair to near-white for the farthest; each sample's row against itself is a plain dash, not colour-coded.

   A lane's i7 index-distance table, outlined -- redder cells mark closer,
   riskier pairs.

This tab is only available once a lane has more than one indexed sample --
there is nothing to compare a single index against.

Color balance
--------------

Illumina two-color chemistry instruments (NovaSeq X, NextSeq, MiSeq i100,
and others) need signal in both of the two fluorescence channels at
every sequencing cycle to keep base-calling and cluster-finding on track.
The **Color Balance** tab checks this at every position of every index
read, across all the indexed samples in a lane at once:

.. figure:: /_static/screenshots/check/color-balance.png
   :alt: The Color Balance tab's per-position table for one lane, with per-channel percentages and a status column.

   A lane's color balance table, outlined.

Each row is one cycle position. The table counts, across every sample in
the lane, how many indexes carry a base that lights up each channel at
that position, and gives it a status:

- **OK** -- both channels have signal.
- **Warning** -- one channel is below 25% of samples.
- **Error** -- one channel has *no* signal at all from any sample in the
  lane.

Which bases feed which channel is instrument-specific -- the tab's legend
names the channels and bases for the run's own instrument.

.. note::
   An **Error** here -- no signal in a channel from any sample in the
   lane -- does not block **Mark Ready** on its own, because a lane with
   one or two samples almost always has one. Instead, Mark Ready stops
   and asks: it names the lanes and offers **Mark Ready anyway** (see
   :doc:`export`). Your answer is kept in the audit trail. If the run
   changes before you answer, it asks again. Read this tab before you
   answer; a **Warning** does not make it ask.

.. note::
   A dedicated check also flags any single sample whose index starts with
   two consecutive dark bases (no signal in either channel) -- this can
   keep the instrument from finding that sample's read at all in the
   first two index cycles. That check's errors are listed on the **Issues**
   tab alongside collisions, not on the Color Balance tab, because it is
   about one sample's own index, not the mix of indexes sharing a lane.
   The **Dark Cycles** tab is where that detail lives: every indexed
   sample's own i7 and i5 index, with each dark base highlighted and a
   per-index status, whether or not it triggered an error.
