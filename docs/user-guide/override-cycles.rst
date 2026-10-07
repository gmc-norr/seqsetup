Override Cycles
=================

Override Cycles is the instruction SeqSetup writes into the Sample Sheet
telling BCL Convert exactly what to do with every cycle the run performs:
read it as data, read it as part of an index, treat it as a UMI, or skip
it. An index read one cycle short or long throws off demultiplexing for
everyone in that lane, not just the one sample.

The format
-----------

An Override Cycles value is up to four segments separated by ``;``, one
for each read the run actually performs, in order: Read 1, Index 1,
Index 2, Read 2. (A run with no Index 2, or no Read 2, simply has one
fewer segment -- there is a segment only for a read the run's cycle
configuration actually includes.) Each segment is one or more tokens: a
letter followed by a cycle count.

.. list-table::
   :header-rows: 1
   :widths: 10 60

   * - Letter
     - Meaning
   * - ``Y``
     - Sequencing (data) cycles
   * - ``I``
     - Index-read cycles
   * - ``N``
     - Masked / skipped cycles
   * - ``U``
     - UMI cycles

For example, ``Y151;I8;I8;Y151`` reads a 151-cycle Read 1, an 8-cycle
Index 1 and Index 2, and a 151-cycle Read 2. ``I8N2`` reads an 8-cycle
index, then masks 2 more cycles the run performs but the index does not
use.

The Override Cycles cell
--------------------------

Every sample's **Override Cycles** cell is in the sample table, between
**Lanes** and the mismatch columns (see :doc:`samples` for how the cell
itself is edited). An empty cell shows the placeholder **Auto** --
nothing is stored for that sample yet.

.. figure:: /_static/screenshots/override-cycles/cell.png
   :alt: SAMPLE-A02's Override Cycles cell, empty and showing the "Auto" placeholder, outlined; the table header and neighbouring rows are visible for context.

   An Override Cycles cell showing the "Auto" placeholder, outlined --
   this sample already has an index assigned, but no Override Cycles
   value has been stored for it yet.

**Auto** does not mean SeqSetup does not know what to write -- it means
nothing is *stored*. The value actually used (at export, or when you
select **Auto** in the bulk panel below) is calculated fresh from the
run's cycle configuration and the sample's assigned index length: an
index that exactly fills its configured cycles gets a plain ``I``
segment (``I8``); a shorter index gets the rest masked (``I8N2``); no
index at all masks every cycle of that read (``N8``). Once a value is
stored, the cell looks the same whether SeqSetup calculated it or you
typed it by hand -- only an empty cell means nothing is stored.

.. warning::
   Assigning an index (by drag, keyboard, or the bulk panel) recalculates
   a sample's Override Cycles and *overwrites* whatever was stored before
   -- including a value you typed by hand (see :doc:`index-assignment`).
   Re-dropping an index on a sample that already has one has the same
   effect, even if it is the same index as before.

   Clearing an index does **not** reliably do the same. Clearing i5 alone
   leaves the stored Override Cycles completely untouched, so a segment
   sized for an index that is now gone can be left behind silently.
   Clearing i7 alone does the same unless the sample's i5 was already
   empty too. If you have set a manual Override Cycles value, or an index
   change leaves you unsure what is stored, check the cell (or select
   **Auto** in the bulk panel) rather than assuming a clear reset it.

Setting a value by hand
-------------------------

Type directly into a sample's own **Override Cycles** cell, or change
several ticked samples at once from the **Override Cycles** row of the
bulk-action panel above the table:

1. Tick the checkbox of each sample you want to change.
2. Type the value into the **Override Cycles** row of the bulk-action
   panel.
3. Select **Apply**.

.. figure:: /_static/screenshots/override-cycles/bulk.png
   :alt: The bulk-action panel's Override Cycles row, with "Y151;I8;I8;Y151" typed in and one sample selected, outlined.

   The Override Cycles row of the bulk-action panel, outlined.

Select **Auto** instead of **Apply** to drop whatever is stored for the
ticked samples and go back to the calculated value described above.

The ``*`` wildcard
--------------------

You may type ``*`` in place of a cycle count to mean "however many
cycles are left in this read" -- for example ``Y*`` for a Read segment,
or ``N2Y*`` to skip the first 2 cycles and sequence the rest. SeqSetup
expands every ``*`` to a concrete number, against the run's configured
cycles, before saving -- the exported Sample Sheet needs an explicit
count, never a wildcard. Expanding a ``*`` needs the run's cycles to be
configured and the value to have exactly as many segments as the run has
reads, with at most one ``*`` per segment; if any of that is not true,
nothing is saved and the reason is named in the error banner at the top
of the page.

What is checked, and when
----------------------------

An Override Cycles value may only contain the letters ``Y``, ``I``,
``U``, ``N``, digits, and the segment separators ``;`` or ``,``, and
each segment must be a letter followed by digits. Typing anything
else -- a stray character, a segment missing its letter, a ``*`` that
could not be expanded -- is refused immediately: nothing is saved, and
the error banner names the problem. This applies the same way whether
you typed it into the row's own cell or the bulk panel.

The same save also checks that the value fits this run: one segment per
read of more than 0 cycles, each adding up to that read's cycles. A value
that does not fit is refused the same way, and so is a value calculated
when you leave the field empty -- that one comes from the index kit's
default read override, which an admin must correct. The **Check** panel
and Mark Ready check again, because the run's cycles can change after a
value was saved.

Reading order
-----------------

Type Override Cycles in reading order, the same way on every instrument:
each index part as the index read is read, the index first and then any
masked cycles -- ``I8N2`` for an 8-base index on a 10-cycle read.
SeqSetup writes the Index 2 part the way the instrument's reader needs:
on NovaSeq X (the instrument this guide's screenshots use), NextSeq
1000/2000 and MiSeq i100 read-first runs it is written reversed
(``N2I8``), because BCL Convert reverses it back there; elsewhere it is
written as you typed it. See :doc:`export` and
:doc:`/admin-guide/instruments`, or check the exported Sample Sheet.

An Index 2 part with cycles before the index -- such as ``N2I8``, the
form Illumina's NovaSeq X entry page uses, or ``Y2I8`` -- is refused, at the input
and at **Mark Ready**: *"Index 2 in OverrideCycles is written in reading
order in SeqSetup: the index first, then the masked cycles (for example
I8N2). SeqSetup writes it the way the instrument needs."* A part with no
index, such as ``N10`` for a sample without an i5, is fine. The Override
Cycles fields say the same when you point at them.

The Index 1 part follows the same rule: the index first, then any masked
or UMI cycles (``I8N2``, ``I8U9``). An Index 1 part with cycles before
the index (``N2I8``, ``Y2I8``) is refused at the input and at **Mark Ready**:
*"Index 1 in OverrideCycles starts with the index in SeqSetup: the index
first, then any masked or UMI cycles (for example I8N2 or I8U9).
SeqSetup's checks compare the index from the first cycle of its read."*
So is an index part with two runs of index cycles, in either index part
(``I4N2I4``): *"An index part of OverrideCycles holds one run of index
cycles in SeqSetup (for example I8N2, not I4N2I4). SeqSetup's checks
compare the index as one run of cycles."*

An index must have exactly as many bases as the index cycles its Override
Cycles reads for it -- Illumina's rule for the Sample Sheet's index columns
("Length of string must match number of first index cycles in RunInfo.xml
or number specified in OverrideCycles"). **Mark Ready** refuses, naming the
sample and both numbers, when they differ: a 10-base index read for 8
cycles (``I8``, typed or from a kit's index cycles), a typed ``I6N4`` on a
10-base i7, a typed ``I10`` on an 8-base i7, or index cycles for an index
the sample does not have. On every instrument. Use an index of that length,
or change the Override Cycles or the kit's index cycles.

The collision, duplicate and index-length checks count the index bases
read from the Override Cycles -- the typed value when there is one, else
the calculated one -- from the first cycle of the read.

Global vs. per-sample in the exported sheet
-----------------------------------------------

The exported Sample Sheet writes each sample's Override Cycles on its own
row, in the application's ``_Data`` section (see :doc:`export`) -- always
per sample, never as a single run-wide value, even when every sample in
the run ends up with the same effective Override Cycles. The value
written is the one described above: what is stored on the sample if
anything is, otherwise the calculated one.
