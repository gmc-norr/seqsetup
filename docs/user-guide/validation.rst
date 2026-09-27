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
error, an amber **Color balance: N lane(s)** badge appears too -- see
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

Index distance heatmaps
-------------------------

The **Heatmaps** tab shows, for each lane, the pairwise Hamming distance
between every pair of samples' indexes -- lower numbers (closer to red)
mean a higher risk that a sequencing error could make one sample's index
misread as another's. Separate views are available for i7 only, i5 only,
and the two combined.

.. figure:: /_static/screenshots/check/heatmaps.png
   :alt: The Heatmaps tab's per-lane distance table, with the diagonal and any close pairs colour-coded.

   A lane's index distance heatmap, outlined.

This tab is only available once a lane has more than one indexed sample --
there is nothing to compare a single index against.

Color balance
--------------

Illumina two-color chemistry instruments (NovaSeq X, NextSeq, MiSeq i100,
and others) need signal in at least one of two fluorescence channels at
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

.. warning::
   An **Error** here -- 0% signal in a channel -- is reported on this tab
   and on the Check panel's amber **Color balance: N lane(s)** badge, but
   it does not block **Mark Ready** (see :doc:`export`): color balance is
   not one of the checks that transition refuses on. Read this tab
   yourself before promoting a run on a two-color instrument -- do not
   assume Mark Ready caught a color balance problem the way it catches an
   index collision.

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
