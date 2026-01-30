Override Cycles
===============

Override cycles control how the sequencer interprets each cycle of a run. They are
essential when index lengths differ from the configured run cycles, or when special
read patterns (such as UMI reads) are needed.

Override Cycles Format
----------------------

Override cycles use Illumina's notation with four semicolon-separated segments::

   Y151;I8N2;I8N2;Y151

The segments correspond to:

1. **Read 1** -- Sequencing read
2. **Index 1** (i7) -- First index read
3. **Index 2** (i5) -- Second index read
4. **Read 2** -- Sequencing read

Cycle Tokens
^^^^^^^^^^^^

Each segment is composed of one or more tokens:

.. list-table::
   :header-rows: 1
   :widths: 10 40 20

   * - Token
     - Meaning
     - Example
   * - ``Y``
     - Sequencing (base call) cycles
     - ``Y151`` = 151 sequencing cycles
   * - ``I``
     - Index read cycles
     - ``I8`` = 8 index cycles
   * - ``N``
     - Masked/skipped cycles
     - ``N2`` = skip 2 cycles
   * - ``U``
     - UMI (Unique Molecular Identifier) cycles
     - ``U8`` = 8 UMI cycles

The wildcard ``*`` means "remaining cycles". For example, ``Y*`` means "use all
remaining cycles for sequencing".

Common Patterns
^^^^^^^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 20 40

   * - Pattern
     - Description
   * - ``I10``
     - Full 10-cycle index read
   * - ``I8N2``
     - 8 index cycles + 2 masked (index shorter than allocated)
   * - ``N10``
     - All cycles masked (no index)
   * - ``N2I8``
     - 2 masked + 8 index cycles (reversed for RC instruments)
   * - ``U8Y*``
     - 8 UMI cycles then sequencing for remaining
   * - ``N2Y*``
     - Skip 2 cycles then sequence remaining

Automatic Calculation
---------------------

SeqSetup automatically calculates override cycles based on:

- The configured run cycles (Read 1, Read 2, Index 1, Index 2)
- The actual index sequence lengths
- Kit-provided effective index cycle counts
- Kit-provided read override patterns

When an index is assigned to a sample, the override cycles are computed
automatically. If the index length matches the run cycles, the segment is a simple
``I`` token (e.g., ``I10``). If shorter, the remaining cycles are masked with ``N``
(e.g., ``I8N2``).

Global vs Per-Sample
--------------------

**Global override cycles**: When all samples in a run have the same override cycles
string, it is written once in the ``[BCLConvert_Settings]`` section of the sample
sheet.

**Per-sample override cycles**: When samples have different index lengths or patterns,
override cycles are written per-row in the ``[BCLConvert_Data]`` section.

Forward Orientation
-------------------

Override cycles are always entered and displayed in forward orientation. For
instruments that read the i5 index in reverse-complement (e.g., NovaSeq X,
NovaSeq 6000), the Index 2 segment is automatically reversed during sample sheet
export.

For example, if you enter ``I8N2`` for the Index 2 pattern, the exported sample sheet
for a NovaSeq X will contain ``N2I8`` in the Index 2 position.

Manual Override
---------------

Per-sample override cycles can be edited manually in the sample table. Enter the
full four-segment override cycles string (e.g., ``Y151;I8N2;I8N2;Y151``) to override
the automatic calculation.
