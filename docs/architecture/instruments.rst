Supported Instruments
=====================

SeqSetup supports Illumina sequencing instruments across three SBS chemistry
generations. Instrument definitions, flowcell types, and reagent kit configurations
are maintained in ``config/instruments.yaml``.

Two-Color SBS -- XLEAP (Blue+Green)
------------------------------------

The latest chemistry generation using blue and green dye channels.

- **Base colors:** A = Blue, C = Blue+Green, T = Green, G = Dark
- **Dark base:** G
- Color balance validation is enabled for these instruments.

.. list-table::
   :header-rows: 1
   :widths: 25 20 15 40

   * - Instrument
     - i5 read (standard workflow)
     - Flowcells
     - Reagent Kits (cycles)
   * - **NovaSeq X Series**
     - Reverse-complement
     - 1.5B (2 lanes), 10B (8 lanes), 25B (8 lanes)
     - 100, 200, 300
   * - **MiSeq i100 Series**
     - Forward (index-first)
     - 5M, 25M, 50M, 100M (1 lane each)
     - 100, 300, 600, 1000 (varies by flowcell)
   * - **NextSeq 1000/2000**
     - Reverse-complement
     - P1, P2 (1 lane each), P3 (1 lane)
     - 50, 100, 200, 300, 600 (varies by flowcell)

Two-Color SBS (Red+Green)
--------------------------

Previous two-color chemistry generation using red and green dye channels.

- **Base colors:** A = Red+Green, C = Red, T = Green, G = Dark
- **Dark base:** G
- Color balance validation is enabled for these instruments.

.. list-table::
   :header-rows: 1
   :widths: 25 20 15 40

   * - Instrument
     - i5 read (standard workflow)
     - Flowcells
     - Reagent Kits (cycles)
   * - **NovaSeq 6000**
     - Reverse-complement (v1.5 reagents)
     - SP (2 lanes), S1 (2 lanes), S2 (2 lanes), S4 (4 lanes)
     - 100, 200, 300, 500 (varies by flowcell)
   * - **NextSeq 500/550**
     - Reverse-complement
     - High Output (4 lanes), Mid Output (4 lanes)
     - 75, 150, 300
   * - **MiniSeq**
     - Reverse-complement (standard kits)
     - High Output (1 lane), Mid Output (1 lane)
     - 75, 150, 300

Four-Color SBS
--------------

Classic four-color chemistry using blue, green, yellow, and red dye channels.

- **Base colors:** A = Green, C = Blue, T = Yellow, G = Red
- **No dark base.** Highly tolerant of low-diversity libraries.
- Color balance validation is not applicable.

.. list-table::
   :header-rows: 1
   :widths: 25 20 15 40

   * - Instrument
     - i5 read (standard workflow)
     - Flowcells
     - Reagent Kits (cycles)
   * - **MiSeq**
     - Forward
     - v2 Standard (1 lane), v3 (1 lane), v2 Nano (1 lane), v2 Micro (1 lane)
     - 50, 150, 300, 500, 600 (varies by flowcell)
   * - **HiSeq 2000/2500**
     - Forward
     - High Output v4 (8 lanes), Rapid Run v2 (2 lanes)
     - 50, 100, 125, 150, 200, 250
   * - **HiSeq 4000**
     - Reverse-complement
     - Standard (8 lanes)
     - 50, 75, 150, 300
   * - **HiSeq X**
     - Reverse-complement
     - Standard (8 lanes)
     - 300
   * - **GAIIx**
     - Forward
     - Standard (8 lanes)
     - 36, 50, 76, 100, 150

i5 Index Read Orientation
-------------------------

Each instrument lists its i5 workflows -- how it reads the i5 in each way
it runs, the standard one first -- and whether its ``RunInfo.xml`` marks a
reversed i5 read (``runinfo_marks_i5_reversed``). A run picks a workflow
(``SequencingRun.i5_workflow``; empty means the standard one).
``data/instruments.py`` turns the two facts into an ``I5Direction``
(``run_i5_direction``):

- ``read_orientation`` -- how the instrument reads the i5: the dark-start
  and colour-balance checks and the v1 Sample Sheet use it;
- ``index2_column_reversed`` -- read reversed and not marked: the v2
  Index2 column is the i5's reverse complement, and the header has no
  ``IndexOrientation,Forward`` line;
- ``index2_mask_reversed`` -- read reversed and marked: the Index 2 part
  of OverrideCycles, stored in reading order (``I8N2``), is written
  reversed (``N2I8``), because BCL Convert reverses it back.

An instrument with no settings, or a workflow it does not list, gives no
direction (``NoI5Direction``): validation reports it and the writers
refuse the run. See :doc:`/admin-guide/instruments` for the shipped
values and their sources.

Read reversed in the standard workflow: NovaSeq X Series, NextSeq
1000/2000, NextSeq 500/550, MiniSeq (standard kits), NovaSeq 6000 (v1.5
reagents), HiSeq 4000, HiSeq X. Read forward: MiSeq i100 Series
(index-first), MiSeq, HiSeq 2000/2500, GAIIx. ``RunInfo.xml`` marks the
reversed read on NovaSeq X Series, NextSeq 1000/2000 and MiSeq i100
Series.

SampleSheet v2 Export Support
-----------------------------

SeqSetup generates SampleSheet v2 files for all instrument platforms listed
above. The legacy SampleSheet v1 (IEM) format is also available, but only for
**MiSeq** and **NovaSeq 6000**.
