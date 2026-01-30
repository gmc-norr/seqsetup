Services
========

SeqSetup's business logic is organized into service classes.

CycleCalculator
---------------

Handles all override cycle computation.

**Key methods:**

``calculate_run_cycles(reagent_kit_cycles, ...)``
   Computes default cycle distribution for a reagent kit, with optional overrides
   for individual segments.

``calculate_override_cycles(sample, run_cycles)``
   Generates the full override cycles string for a sample based on its index
   lengths and the run's cycle configuration. Returns a string like
   ``Y151;I8N2;I8N2;Y151``.

``infer_global_override_cycles(run)``
   Checks if all samples in a run have the same override cycles. Returns the
   common string if uniform, or ``None`` if per-sample overrides are needed.

``populate_index_override_patterns(sample, run_cycles)``
   Computes resolved index patterns (e.g., ``I8N2``) from the effective index
   length and run index cycles. Sets ``index1_override_pattern`` and
   ``index2_override_pattern`` on the sample.

``update_all_sample_override_cycles(run)``
   Recalculates override cycles and patterns for all samples in a run. Called
   after run cycle changes.

``reverse_override_segment(segment)``
   Reverses the token order within an override cycles segment. Used for
   reverse-complement i5 instruments (e.g., ``I8N2`` becomes ``N2I8``).

``validate_cycles(cycles, reagent_kit_cycles)``
   Validates that total cycles do not exceed the reagent kit capacity.

SampleSheetV2Exporter
---------------------

Generates Illumina SampleSheet v2 CSV output.

**Key methods:**

``export(run, test_profile_repo=None, app_profile_repo=None)``
   Main entry point. Writes all sections and returns the complete sample sheet as
   a string.

**Sections written:**

1. ``[Header]`` -- File format version, run name, instrument platform
2. ``[Reads]`` -- Cycle counts for all four segments
3. ``[BCLConvert_Settings]`` -- Barcode mismatches, global override cycles, adapter
   settings
4. ``[BCLConvert_Data]`` -- Per-sample rows with index sequences, projects, and
   optionally per-sample override cycles and lane assignments
5. DRAGEN sections -- Generated from application profiles (if available) or
   legacy analysis objects

**Instrument adjustments:**

For reverse-complement i5 instruments (NovaSeq X, NovaSeq 6000, etc.), the
Index 2 override cycles segment is automatically reversed at export time.

JSONExporter
------------

Exports complete run metadata as JSON, including information not supported by the
SampleSheet v2 format (test IDs, detailed metadata, kit information).

AuthService
-----------

Handles user authentication with a priority chain:

1. LDAP/AD authentication (if configured)
2. Local MongoDB users
3. File-based users (``config/users.yaml``)

Supports bcrypt password verification and optional LDAP fallback to local
authentication.

LDAPService
-----------

Manages LDAP/AD integration:

- Connection management with TLS support
- User search and DN resolution
- Group-based role assignment (admin group membership)
- LDAP injection prevention (RFC 4515 escaping)

ValidationService
-----------------

Performs comprehensive run validation:

- **Duplicate sample IDs** -- Detects non-unique identifiers
- **Index collisions** -- Per-lane Hamming distance checking against mismatch
  thresholds
- **Dark cycle detection** -- Identifies indexes starting with two dark bases
  (two-color SBS instruments)
- **Color balance analysis** -- Per-position signal distribution across fluorescence
  channels
- **Distance matrices** -- All-vs-all Hamming distance computation for visualization

IndexValidator
--------------

Validates index kit definitions:

- Mode-specific structural checks (pairs for UDI, separate lists for combinatorial)
- Sequence validation (valid DNA characters: A, C, G, T, N)
- Duplicate detection within kits
- Version format validation (PEP 440)

IndexParser
-----------

Parses index kit definitions from CSV files, supporting multiple column layouts
and index modes.

ProfileValidator
----------------

Validates test and application profile definitions against the expected schema.

GitHubSyncService
-----------------

Synchronizes application and test profiles from a GitHub repository, keeping
local definitions up to date with a remote source.

SampleAPIService
----------------

Imports sample and test identifiers from an external API, supporting bulk
sample creation during run setup.
