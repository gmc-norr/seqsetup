Data Models
===========

SeqSetup uses Python dataclasses for all data models. Models support serialization
to and from dictionaries for MongoDB storage.

SequencingRun
-------------

The central model representing a sequencing run configuration.

**Key fields:**

- ``id`` -- UUID for the run
- ``run_name`` -- User-friendly name
- ``run_description`` -- Optional notes
- ``status`` -- ``DRAFT``, ``READY``, or ``ARCHIVED``
- ``instrument_platform`` -- InstrumentPlatform enum value
- ``flowcell_type`` -- Flowcell identifier (e.g., "10B")
- ``reagent_cycles`` -- Total cycles available from the reagent kit
- ``run_cycles`` -- RunCycles object with per-segment cycle counts
- ``barcode_mismatches_index1``, ``barcode_mismatches_index2`` -- Default mismatch
  tolerances (default: 1)
- ``samples`` -- List of Sample objects
- ``analyses`` -- List of Analysis objects
- ``created_by``, ``updated_by`` -- Audit trail usernames
- ``created_at``, ``updated_at`` -- Timestamps

RunCycles
---------

Cycle configuration for a sequencing run.

- ``read1_cycles`` -- First sequencing read
- ``read2_cycles`` -- Second sequencing read
- ``index1_cycles`` -- i7 index read
- ``index2_cycles`` -- i5 index read
- ``total_cycles`` -- Sum of all four (computed property)

InstrumentPlatform
------------------

Enum of supported instruments:

.. list-table::
   :header-rows: 1
   :widths: 30 30

   * - Value
     - Display Name
   * - ``NOVASEQ_X``
     - NovaSeq X Series
   * - ``NOVASEQ_6000``
     - NovaSeq 6000
   * - ``MISEQ_I100``
     - MiSeq i100 Series
   * - ``MISEQ``
     - MiSeq
   * - ``NEXTSEQ_1000_2000``
     - NextSeq 1000/2000
   * - ``NEXTSEQ_500_550``
     - NextSeq 500/550
   * - ``MINISEQ``
     - MiniSeq
   * - ``HISEQ_4000``
     - HiSeq 4000
   * - ``HISEQ_X``
     - HiSeq X
   * - ``HISEQ_2000_2500``
     - HiSeq 2000/2500
   * - ``GAIIX``
     - GAIIx

Sample
------

A sequencing sample with assigned indexes.

**Key fields:**

- ``id`` -- Internal UUID
- ``sample_id`` -- User-provided sample identifier
- ``sample_name`` -- Optional display name
- ``project`` -- Project assignment
- ``test_id`` -- Associated test identifier
- ``lanes`` -- Lane assignments (empty list = all lanes)
- ``index_pair`` -- Assigned IndexPair (for unique dual mode)
- ``index1``, ``index2`` -- Individual indexes (for combinatorial/single mode)
- ``index_kit_name`` -- Name of the kit the indexes came from
- ``override_cycles`` -- Computed or manual override cycles string
- ``barcode_mismatches_index1``, ``barcode_mismatches_index2`` -- Per-sample overrides
- ``index1_cycles``, ``index2_cycles`` -- Effective index cycle counts
- ``index1_override_pattern``, ``index2_override_pattern`` -- Resolved index patterns
- ``read1_override_pattern``, ``read2_override_pattern`` -- Read patterns (e.g., UMI)
- ``analyses`` -- List of analysis IDs assigned to this sample

Index Models
------------

**Index**
   A single sequencing index with name, sequence, and type (``I7`` or ``I5``).

**IndexPair**
   A paired i7 + i5 index combination. The i5 index is optional (for single indexing).

**IndexKit**
   A collection of indexes organized as pairs (unique dual), separate i7/i5 lists
   (combinatorial), or i7-only (single). Kits can define:

   - Default effective index cycle counts
   - Default index override patterns
   - Default read override patterns (e.g., for UMI kits)
   - Adapter sequences for trimming
   - Fixed layout flag (for plate-based kits)

**IndexType** enum: ``I7``, ``I5``

**IndexMode** enum: ``UNIQUE_DUAL``, ``COMBINATORIAL``, ``SINGLE``

Analysis
--------

Configuration for a DRAGEN or downstream analysis pipeline.

- ``analysis_type`` -- ``DRAGEN_ONBOARD`` or ``DOWNSTREAM``
- ``dragen_pipeline`` -- ``GERMLINE``, ``SOMATIC``, ``RNA``, or ``ENRICHMENT``
- ``reference_genome`` -- Reference genome path (e.g., "hg38")
- ``pipeline_name`` -- Pipeline identifier for downstream analyses
- ``pipeline_version`` -- Version string
- ``sample_ids`` -- Samples assigned to this analysis

User and Authentication Models
------------------------------

**User**
   Session user with username, display_name, role (``ADMIN`` or ``STANDARD``), and
   optional email.

**LocalUser**
   MongoDB-stored user with bcrypt password hash, timestamps, and conversion to User.

**ApiToken**
   Bearer token for programmatic API access. Only the bcrypt hash is stored; the
   plaintext is shown once at creation time.

Validation Models
-----------------

**ValidationResult**
   Complete validation output including duplicate sample IDs, index collisions,
   distance matrices, dark cycle errors, and color balance analysis.

**IndexCollision**
   A collision between two indexes in the same lane, with Hamming distance and
   mismatch threshold.

**IndexDistanceMatrix**
   Pairwise Hamming distances between all indexes in a lane (i7, i5, and combined).

**LaneColorBalance** / **IndexColorBalance** / **PositionColorBalance**
   Hierarchical color balance analysis for two-color SBS instruments, tracking
   signal in both fluorescence channels at each index position.

**DarkCycleError**
   Warning when an index starts with two consecutive dark bases.
