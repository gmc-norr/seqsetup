Lane Assignment
================

A flowcell has one or more lanes. A sample's lane assignment decides which
lane(s) its reads are sorted into during demultiplexing. A new sample is
never left without a lane: pasted samples start in lane 1 (change this
before previewing, in the **Lanes for these samples** box), a single
sample added by hand is assigned lane 1, and samples brought in from a LIMS
worklist are also assigned lane 1. The only way to put a sample into
*every* lane of the flowcell is to tick it and select **Clear** in the
bulk-action panel (see :ref:`Clearing a lane assignment
<clearing-a-lane-assignment>` below).

The Lanes column
------------------

The sample table's **Lanes** column shows each sample's current assignment:
a sorted, comma-separated list of lane numbers (for example ``2,3``), or
``All`` when no specific lane is set.

This column is display only -- there is no field in the row itself to type
a lane number into. Changing a sample's lanes, even one sample, is a
separate select-and-apply action described below (see also
:doc:`samples`).

How many lanes a flowcell offers depends on the flowcell type -- for
example, a NovaSeq X ``10B`` flowcell, the one this guide's screenshots
use, has 8.

Setting lanes for one or more samples
----------------------------------------

1. Tick the checkbox of each sample you want to change -- one is enough
   for a single sample.
2. In the **Lanes** row of the bulk-action panel above the table, tick
   each lane number you want those samples assigned to.
3. Select **Apply**.

.. figure:: /_static/screenshots/lanes/bulk-panel.png
   :alt: The bulk-action panel's Lanes row, with lanes 2 and 3 ticked and two samples selected, outlined.

   The Lanes row of the bulk-action panel, outlined -- the ticked lane
   numbers, and the Apply / Clear / Toggle buttons that act on every
   ticked sample.

Applying replaces the lanes on every ticked sample with exactly the lanes
you ticked -- it does not add to whatever lanes were already there. The
table updates immediately:

.. figure:: /_static/screenshots/lanes/row-lanes.png
   :alt: A sample's Lanes cell reading "2,3" in the sample table, outlined; the table header and neighbouring rows are visible for context.

   A sample's Lanes cell after applying lanes 2 and 3, outlined.

**Toggle** inverts which lane checkboxes are ticked, which is a quick way
to pick "every lane except this one." Selecting **Apply** or **Clear**
(below) without ticking any sample does nothing but remind you to tick one
first.

.. _clearing-a-lane-assignment:

Clearing a lane assignment
------------------------------

Tick the sample(s) and select **Clear** instead of **Apply**. This applies
an empty lane list, which returns those samples to the default "all lanes"
behavior -- the same as a sample that has never had lanes set.

.. warning::
   Two samples that share a lane must not share an index -- with nothing
   to tell their reads apart, demultiplexing cannot say which sample a
   read actually came from. SeqSetup does not refuse this while a run is
   still a Draft: as soon as it happens, the **Check** panel above the
   table marks it as an error, and the full report on :doc:`validation`
   names the samples and the lane. A Draft with two same-lane, same-index
   samples saves and stays saved -- it is only actually *refused* at
   **Mark Ready**: if this error (or any other) is still present,
   transitioning to Ready is refused and the problem is listed in the
   banner at the top of the page. Do not assume a run is safe just
   because lanes are assigned -- check the **Check** panel (or
   :doc:`validation`) before relying on it.

Lanes in the exported Sample Sheet
--------------------------------------

Whether the exported Sample Sheet has a ``Lane`` column at all is decided
by the application profile a sample's Test ID resolves to (see
:doc:`export`), not by whether any sample in the run has an explicit
lane. In the shipped BCLConvert profile, ``Lane`` is always a column: a
sample still left on "All" gets a blank cell there rather than a lane
number, and a sample assigned to more than one lane produces one row per
lane in the exported data section -- a sample in lanes 2 and 3 becomes two
rows. A different application profile is free to define its own data
columns and can leave ``Lane`` out entirely.
