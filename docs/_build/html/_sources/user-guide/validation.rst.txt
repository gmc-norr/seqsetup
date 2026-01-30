Validation
==========

SeqSetup validates the run configuration to detect potential issues before export.

Index Collision Detection
-------------------------

Indexes within the same lane are checked for collisions. Two indexes collide when
their Hamming distance is less than or equal to the configured barcode mismatch
threshold.

For example, with a mismatch threshold of 1, indexes ``ATTACTCG`` and ``ATTACTCA``
(Hamming distance 1) would collide because BCLConvert cannot reliably distinguish
them.

Collision detection considers:

- Per-lane grouping (only samples in the same lane are compared)
- Both i7 and i5 indexes independently
- The configured barcode mismatch threshold (global and per-sample)

Index Distance Matrix
---------------------

A distance matrix shows the pairwise Hamming distances between all indexes in each
lane. This helps identify which sample pairs are closest and might cause
demultiplexing issues.

The matrix includes:

- i7 distances
- i5 distances
- Combined (i7 + i5) distances

Color Balance Analysis
----------------------

For two-color SBS chemistry instruments (NovaSeq X, MiSeq i100, NextSeq, etc.),
SeqSetup analyzes the color balance of index sequences at each position.

Good color balance requires signal in both fluorescence channels at every cycle.
The analysis reports:

- **Per-position balance** -- Percentage of bases contributing to each channel
- **Warnings** -- Positions where a channel is below 25%
- **Errors** -- Positions where a channel has no signal

Channel assignments are instrument-specific:

**XLEAP chemistry** (NovaSeq X, MiSeq i100):

- Channel 1 (Blue): A, C
- Channel 2 (Green): C, T
- Dark: G

**Red/Green chemistry** (NextSeq 500/550, NovaSeq 6000):

- Channel 1 (Red): A, C
- Channel 2 (Green): A, T
- Dark: G

Dark Cycle Detection
--------------------

A warning is raised when a sample's index sequence starts with two consecutive
dark bases (G for two-color instruments). This can cause imaging issues during the
first cycles of the index read.

Duplicate Sample IDs
--------------------

The system checks for duplicate sample identifiers within the same run. Each
sample must have a unique sample ID.
