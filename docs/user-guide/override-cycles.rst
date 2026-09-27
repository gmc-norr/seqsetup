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

.. warning::
   That immediate check does **not** confirm the value actually matches
   this run. A value with the right characters but the wrong number of
   segments, or one whose cycle counts do not sum to the run's declared
   Read/Index cycles, is accepted and saved without complaint -- for
   example, typing a four-read value's worth of cycles into only two
   segments. The mistake is only caught the next time the run is
   checked: the **Check** panel above the table, or Mark Ready, compares
   every sample's Override Cycles against the run's configured cycles
   and flags anything that does not add up. Do not treat a value as
   correct just because it was accepted when you typed it -- check the
   run (see :doc:`validation`) before relying on it.

Forward orientation
-----------------------

Type and read Override Cycles the same way regardless of instrument:
index lengths and directions exactly as you see them. What ends up in
the *exported* Sample Sheet for the Index 2 segment can differ from what
you typed, though, because BCL Convert expects the i5 index written in
whatever orientation that specific instrument's Sample Sheet format
calls for -- which is not always the direction the instrument physically
reads it in. On a NovaSeq X, the instrument this guide's screenshots
use, that expected orientation happens to match the forward orientation
you typed, so the Index 2 segment is exported unchanged. Five of the
other ten shipped instruments do have their Index 2 segment reversed for
export, and five stay forward like NovaSeq X -- see :doc:`export` for
which is which, or check the exported Sample Sheet itself rather than
assuming.

Global vs. per-sample in the exported sheet
-----------------------------------------------

When every sample in the run ends up with the same effective Override
Cycles, SeqSetup writes it once, for the whole run. As soon as samples
differ from each other, each sample's own value is written per-row in
the exported data instead. Either way, the value used is the one
described above: what is stored on the sample if anything is, otherwise
the calculated one.
