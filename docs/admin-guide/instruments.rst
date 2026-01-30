Instrument Configuration
========================

Supported sequencing instruments and their configurations are defined in
``config/instruments.yaml``.

Configuration Structure
-----------------------

Each instrument entry defines:

- **Name** -- Display name (e.g., "NovaSeq X Series")
- **Platform** -- Illumina platform identifier
- **i5 read orientation** -- ``forward`` or ``reverse-complement``
- **SBS chemistry** -- Chemistry type (``2-color`` or ``4-color``) and dye channel
  configuration
- **Flowcell types** -- List of supported flowcell types, each with:

  - Name and identifier
  - Number of lanes
  - Available reagent kits (with maximum cycle counts)

Supported Instruments
---------------------

SeqSetup includes configurations for the following instruments:

**Reverse-complement i5 instruments:**

- NovaSeq X Series
- NovaSeq 6000
- HiSeq 4000
- HiSeq X

**Forward i5 instruments:**

- MiSeq i100 Series
- MiSeq (classic)
- MiniSeq
- NextSeq 1000/2000
- NextSeq 500/550

i5 Read Orientation
-------------------

The i5 read orientation determines how the Index 2 sequence is processed:

**Forward instruments** read the i5 index in the same orientation as entered.
The i5 sequence in the sample sheet matches the stored sequence.

**Reverse-complement instruments** read the i5 index in the opposite direction.
SeqSetup handles this automatically:

- Index sequences are always stored in forward orientation
- At export time, the Index 2 override cycles segment is reversed for
  reverse-complement instruments (e.g., ``I8N2`` becomes ``N2I8``)
- BCLConvert handles the actual sequence reverse-complementing

SBS Chemistry
-------------

The SBS chemistry type affects color balance validation:

**Two-color SBS** (XLEAP, Red/Green):
   Used by most modern instruments. Two fluorescence channels detect bases, with one
   base (G) being dark (no signal). Good color balance requires both channels to have
   signal at every index position.

**Four-color SBS:**
   Each base has a distinct fluorescence signal. Color balance is not a concern.

Customizing Instruments
-----------------------

To add or modify instruments, edit ``config/instruments.yaml``. The application reads
this file on startup. Changes require a restart.

The instrument configuration path can be overridden with the ``INSTRUMENTS_CONFIG``
environment variable.
