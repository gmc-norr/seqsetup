Index Assignment
================

Every sample needs an index (barcode) before its run can go **Ready** --
it is what lets the sequencer sort each read back to the right sample.
Indexes come from an index kit and live in a panel next to the sample
table; the panel only appears while at least one sample in the run has no
index at all.

Index Kits
----------

Indexes are organized into kits, uploaded by an admin. A kit's mode
decides how its indexes are assigned:

**Unique Dual Indexing (UDI)**
   Pre-defined pairs of i7 and i5 indexes. Each pair is assigned as a
   unit -- dragging a pair sets both a sample's i7 and i5 together.

**Combinatorial**
   i7 and i5 indexes are listed separately and assigned independently, so
   any i7 can be paired with any i5 from the kit.

**Single Index**
   Only i7 indexes are used; there is no i5 to assign.

Picking a kit
^^^^^^^^^^^^^^

.. figure:: /_static/screenshots/indexes/kit-picker.png
   :alt: The index kit dropdown in the "Available Indexes" panel, showing "Demo UDI Set A v1.0 (24 indexes)", outlined.

   The index kit selector, outlined. Each option names the kit, its
   version and how many indexes it holds.

If your organization has more than one kit, choose the one you are using
for this run from this dropdown -- the panel below it lists that kit's
indexes.

Assigning one index by drag and drop
--------------------------------------

Each sample row that has no i7 (or i5) yet shows a dashed **Drop i7** or
**Drop i5** target instead of an index. Drag an index chip from the panel
onto that target to assign it:

.. figure:: /_static/screenshots/indexes/drag-drop.png
   :alt: SAMPLE-A05's row after a UDI0005 pair chip was dragged onto its i7 drop target; both the i7 and i5 index cells now show the assigned index, with the i7 cell outlined.

   The index just dropped, outlined -- assigning a unique-dual pair fills
   both the i7 and i5 cells at once, whichever of the two you drop it on.

A unique-dual **pair** chip can be dropped on either the i7 or the i5
target of a sample; either way it fills both. A single **i7** or **i5**
chip (combinatorial or single-index kits) only fills the matching target
and refuses the other one. Dropping a new index on a sample that already
has one replaces it -- there is no separate button on this page to clear
just the index; drag a different one on to replace it, or remove the
whole sample to start over.

You can do the same thing from the keyboard: press **Enter** or
**Space** on an index chip to select it, then **Tab** to the sample's
drop target and press **Enter** or **Space** there to assign it.
**Escape** clears the current selection.

Selecting several indexes in order
--------------------------------------

To hand out a block of indexes in one move, select more than one: click
the first index chip, then shift-click the last one you want -- everything
between them (in the order the panel lists them) is selected together.
Ctrl-click (Cmd-click on a Mac) adds or removes one chip at a time instead
of a range.

.. figure:: /_static/screenshots/indexes/several-in-order.png
   :alt: UDI0006, UDI0007 and UDI0008 highlighted as selected in the index panel after clicking UDI0006 and shift-clicking UDI0008, outlined.

   Three indexes selected by click, then shift-click, outlined.

Drag the selection onto a sample the same way as a single index. The
first selected index goes to the sample you drop on, the next one to the
row below it, and so on down the table -- filling that many rows starting
from the drop target, in table order. If any of those rows already has an
index it will be replaced, and if the table runs out of rows before the
selection does, the extra indexes are left unused; either way SeqSetup
asks you to confirm before going ahead.

.. note::
   Ticking sample checkboxes (below) has no effect on a multi-index drag
   -- it always fills consecutive rows starting at the row you drop on,
   whichever rows are ticked.

Assigning one index to several ticked samples
-------------------------------------------------

Each row has a checkbox. Ticking one or more highlights those rows and
enables the bulk-action tools above the table (lanes, mismatches,
override cycles, test ID -- see :doc:`lane-assignment`); it also changes
what a *single*-index drop does:

.. figure:: /_static/screenshots/indexes/ticked-rows.png
   :alt: Two ticked sample rows (checkboxes checked) in the sample table, the second one outlined.

   Ticked rows, outlined -- dropping one index anywhere among ticked rows
   gives every ticked sample that same index.

Drop (or keyboard-assign) a single index chip onto a ticked row and
SeqSetup gives that same index to every ticked sample, plus the one you
dropped on -- not just the row under the drop target. Because two samples
sharing an index in the same lane is exactly the kind of mistake this
tool exists to prevent, it always asks first:

.. warning::
   Before making the assignment, SeqSetup shows a confirmation dialog
   reading exactly:

   .. code-block:: text

      Give this same index to all N samples (the ticked ones and the one you dropped on)?

      Samples in the same lane must not share an index.

   (``N`` is however many samples are ticked, including the drop target
   if it was not already ticked.) Selecting Cancel leaves every sample
   unchanged. Only tick rows you actually mean to give the same index to
   -- and check the run afterward, since two samples in the same lane
   with the same index is a real error, not just a warning here.

Filling empty samples in order
----------------------------------

For a run where nobody has an index yet, assigning them one at a time is
slow. **Fill empty samples in order…**, above the index panel, hands out
the next unused index from the chosen kit to every sample that has none,
in table order:

.. figure:: /_static/screenshots/indexes/fill-preview.png
   :alt: The fill-in-order preview: "Start at" set to UDI0001 (A01), and a table of the six samples that would receive UDI0001 through UDI0006.

   The fill preview, outlined -- nothing is saved yet.

Nothing is written until you confirm. The preview names how many samples
would be filled and from where, and lists exactly which index each one
would get. **Start at** lets you begin further into the kit instead of
its first index. An index already used elsewhere in this run is skipped
automatically; a sample that already has *some* index (for example, only
an i5) is left alone and called out separately, since fill-in-order only
ever touches samples with no index at all.

Select **Assign N indexes** to apply the plan exactly as previewed:

.. figure:: /_static/screenshots/indexes/fill-assigned.png
   :alt: The sample table after filling in order: six samples now have UDI0001 through UDI0006 assigned; the first row is still flagged with a validation error.

   The samples after filling in order, outlined.

.. warning::
   Filling in order only avoids indexes already used *in this run* -- it
   does not check index quality. The picture above shows exactly that: the
   first sample was handed the kit's first index and still ends up flagged
   by validation for an unrelated reason. Always check the **Check**
   panel (or the full :doc:`validation` page) after filling, the same way
   you would after assigning indexes by hand.

Fill-in-order only works for unique-dual and single-index kits -- a
combinatorial kit is refused, since there is no single ordering of
independent i7 and i5 indexes to hand out. If the run or the kit changes
between previewing and confirming (someone else edited it, or an admin
replaced the kit), Assign refuses and asks you to preview again rather
than silently applying a stale plan.

Kit defaults
---------------

When an index is assigned -- by any of the methods above -- and its kit
declares defaults, they are copied onto the sample automatically:

- **Index cycles** -- the number of cycles the kit expects for its i7 and/or i5
- **Read override patterns** -- pre-defined patterns the kit specifies for its
  data reads (for example ``N2Y*``)

SeqSetup computes the index override pattern (for example ``I8N2``) from the
index cycles above and the run's cycle configuration, then recalculates
Override Cycles from both. Any of it can still be changed by hand afterward
on the sample table -- see :doc:`override-cycles`.
