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
     - i5 Orientation
     - Flowcells
     - Reagent Kits (cycles)
   * - **NovaSeq X Series**
     - Reverse-complement
     - 1.5B (2 lanes), 10B (8 lanes), 25B (8 lanes)
     - 100, 200, 300
   * - **MiSeq i100 Series**
     - Forward
     - 5M, 25M, 50M, 100M (1 lane each)
     - 100, 300, 600, 1000 (varies by flowcell)
   * - **NextSeq 1000/2000**
     - Forward
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
     - i5 Orientation
     - Flowcells
     - Reagent Kits (cycles)
   * - **NovaSeq 6000**
     - Reverse-complement
     - SP (2 lanes), S1 (2 lanes), S2 (2 lanes), S4 (4 lanes)
     - 100, 200, 300, 500 (varies by flowcell)
   * - **NextSeq 500/550**
     - Forward
     - High Output (4 lanes), Mid Output (4 lanes)
     - 75, 150, 300
   * - **MiniSeq**
     - Forward
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
     - i5 Orientation
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

The i5 (Index 2) read orientation varies by instrument. SeqSetup handles this
automatically during SampleSheet export.

**Forward** (i5 read as written in the sample sheet):
   MiSeq, MiSeq i100 Series, HiSeq 2000/2500 (Rapid Run), NextSeq 500/550,
   NextSeq 1000/2000, MiniSeq, GAIIx

**Reverse-complement** (i5 read as reverse complement):
   NovaSeq X Series, NovaSeq 6000, HiSeq 4000, HiSeq X

SampleSheet v2 Export Support
-----------------------------

SeqSetup currently generates SampleSheet v2 files for:

- **NovaSeq X Series**
- **MiSeq i100 Series**

Other instruments are available for run configuration and JSON metadata export,
but SampleSheet v2 export is limited to the instruments listed above.
