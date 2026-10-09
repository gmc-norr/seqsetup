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
   Checks if all samples in a run have the same override cycles (a sample's
   stored value, typed by hand or not, else the calculated one). Returns the
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
   the Index 2 part when the run's instrument reads the i5 reversed and
   its ``RunInfo.xml`` marks it (e.g., ``I8N2`` becomes ``N2I8``).

SampleSheetV2Exporter
---------------------

Generates Illumina SampleSheet v2 CSV output.

**Key methods:**

``export(run, test_profile_repo=None, app_profile_repo=None, instrument_config=None, plan_fingerprint=None)``
   Main entry point. Writes all sections and returns the complete sample sheet as
   a string. With both repositories it writes the application sections from
   the sheet plan (below); given ``plan_fingerprint`` (Mark Ready passes the
   one its checks used), a plan with another fingerprint raises
   ``SheetPlanChanged``, and any plan problem raises ``SheetPlanProblem``,
   before anything is written.

**Sections written:**

1. ``[Header]`` -- File format version, run name, instrument platform
2. ``[Reads]`` -- Cycle counts for all four segments
3. ``[BCLConvert_Settings]`` -- Software version, lane-splitting and adapter
   settings, global override cycles
4. ``[BCLConvert_Data]`` -- Per-sample rows with index sequences, and
   optionally per-sample override cycles, barcode mismatch overrides, and
   lane assignments
5. DRAGEN sections -- Generated from application profiles (if available) or
   legacy analysis objects

**Instrument adjustments:**

The run's ``I5Direction`` (see :doc:`instruments`) decides the i5 and the
Index 2 part of OverrideCycles. Where the run's workflow reads the i5
reversed and ``RunInfo.xml`` marks it (NovaSeq X Series, NextSeq
1000/2000, MiSeq i100 read-first), the Index 2 part is written reversed
(``N2I8``) and the i5 forward. Where it reads the i5 reversed without the
mark (NextSeq 500/550, MiniSeq standard kits, NovaSeq 6000 v1.5, HiSeq
4000, HiSeq X), the i5 is written as its reverse complement, the Index 2
part as stored (``I8N2``), and the header without
``IndexOrientation,Forward``. A ``BCLConvert`` profile whose ``Settings``
set ``OverrideCycles``, ``OverrideReads``,
``RunInfoIndex2ReverseComplement`` or ``Index2ColumnReverseComplement`` is
refused.

Sheet plan
----------

``services/sheet_plan.py`` works out a run's v2 application sections from
the run and the two profile repositories: ``plan_sheet(run,
test_profile_repo, app_profile_repo, lanes)`` returns a ``SheetPlan`` with
one ``PlannedSection`` per ``ApplicationName`` (its distinct resolved
profiles and its rows, each sample with its own profile), the
``problems`` that stop the writer (those with a category are Mark Ready
errors), a warning for a mismatch number the sheet cannot carry, the
mismatch number the sheet gives BCL Convert for each sample, and a
``fingerprint`` of the profiles' content and the lane count. Mark Ready's
checks (``ValidationService.validate_run``, which puts the fingerprint in
its result) and the v2 writer both use it, so they cannot disagree about
which samples go where.

Samples are grouped by test and version text, and each group's test
profile comes from ``resolve_test`` (below); the plan records the exact
version each group found (``test_versions``), which Mark Ready saves on the
Ready run. A newer matching version synced between the checks and the
writing changes the fingerprint, so Mark Ready refuses rather than write
from another version than it checked.

Test versions
-------------

``services/versioned_tests.py`` holds the rule for a test profile's
``Version`` (three whole numbers) and ``resolve_test(test_profile_repo,
test, asked)``: the newest stored version of the test whose numbers start
with those the sample asks for (``1``, ``1.2`` or ``1.2.3``), compared as
numbers. It returns the profile, or the reason there is none -- no profile
of that test, no matching version, or the newest match stored twice -- with
the text the checks show. The sheet plan and the application-profile checks
both use it; the repository only lists every stored version of a test
(``list_by_test_type``). ``offered_tests`` gives the pages' test lists: each
test once, with its synced versions.

JSONExporter
------------

Exports complete run metadata as JSON, including information not supported by the
SampleSheet v2 format (test IDs, detailed metadata, kit information).

AuthService
-----------

Checks a sign-in:

1. LDAP/AD, if directory sign-in is set up (see LDAPService)
2. Local MongoDB users -- when no directory is used, or the directory
   refused and local fallback is on

Names longer than 64 characters are refused first. Every refusal carries a
reason for the audit trail; the sign-in page shows one message for all.

LDAPService
-----------

Directory sign-in without a service account:

- Binds as the person signing in (a user principal name on Active Directory,
  a DN on LDAP), over TLS unless cleartext is explicitly allowed
- Reads that person's own entry over the same connection
- Asks the server about Users and Admins group membership (on Active
  Directory with the in-chain rule, so nested groups count)
- LDAP injection prevention (RFC 4515 filter escaping, RFC 4514 DN escaping)

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

Profile Validation
-------------------

``validate_test_profile_yaml()`` and ``validate_application_profile_yaml()``
(in ``services/profile_validator.py``) validate test and application profile
definitions against the expected schema.

GitHubSyncService
-----------------

Synchronizes application and test profiles from a GitHub repository, keeping
local definitions up to date with a remote source.

Sample API (LIMS Import)
-------------------------

``services/sample_api.py`` imports sample and test identifiers from an
external API, supporting bulk sample creation during run setup.
