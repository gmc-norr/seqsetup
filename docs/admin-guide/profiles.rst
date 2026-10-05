Profiles
========

SeqSetup uses a profile system to define reusable configurations for test
types and analysis pipelines. Every user can browse profiles from
**Settings > Profiles**; only an administrator can bring new ones in
(below).

Overview
--------

The profile system consists of two types:

**Test Profiles**
   Define a sequencing test type (e.g., "WGS", "Exome", "RNA-Seq") and link
   it to one or more application profiles. When a sample has a test ID,
   SeqSetup resolves the test profile and includes the associated
   application pipelines in the sample sheet.

**Application Profiles**
   Define analysis pipeline configurations -- for on-instrument DRAGEN
   pipelines, cloud pipelines, or external tools. All of them generate
   sample sheet sections the same way; none of them appear in the JSON
   metadata export.

Test Profiles
-------------

A test profile defines a sequencing test type and its associated analysis
pipelines.

Required Fields
~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 25 15 60

   * - Field
     - Type
     - Description
   * - ``TestType``
     - string
     - Unique identifier matching the test ID assigned to samples
   * - ``TestName``
     - string
     - Human-readable display name
   * - ``Description``
     - string
     - Description of the test
   * - ``Version``
     - string
     - Profile version (PEP 440 format, e.g., ``1.0.0``)
   * - ``ApplicationProfiles``
     - list
     - List of application profile references (see below)

Application Profile References
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Each entry in ``ApplicationProfiles`` must contain:

- ``ApplicationProfileName`` -- Name of the application profile
- ``ApplicationProfileVersion`` -- Version constraint (PEP 440 format)

Version constraints support:

- Exact versions: ``1.0.0``
- Compatible releases: ``~=1.0.0`` (matches 1.0.x)
- Range specifiers: ``>=1.0,<2.0``

Example Test Profile
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: yaml

   ---
   TestType: WGS
   TestName: Whole Genome Sequencing
   Description: Germline whole genome sequencing with variant calling
   Version: 1.0.0

   ApplicationProfiles:
     - ApplicationProfileName: BCLConvertNextera
       ApplicationProfileVersion: "~=1.0.0"

     - ApplicationProfileName: DragenGermlineIdtWgs
       ApplicationProfileVersion: "~=1.0.0"

Application Profiles
---------------------

Application profiles define analysis pipeline configurations. SeqSetup
does not treat the ``ApplicationType`` field specially when writing the
Sample Sheet: **every** application profile referenced by a sample's test
profile writes an ``[AppName_Settings]`` / ``[AppName_Data]`` pair into
the instrument-facing Sample Sheet, named after whatever
``ApplicationName`` the profile declares -- whether ``ApplicationType`` is
``Dragen`` (BCLConvert, DragenGermline, DragenSomatic, etc.), ``Cloud``,
``External``, or anything else. ``ApplicationType`` is free-form,
informational text; it does not control what gets exported.

Application and test profile data is never included in the JSON metadata
export, regardless of ``ApplicationType``.

Required Fields (All Profiles)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

These fields are required for all application profiles regardless of type:

.. list-table::
   :header-rows: 1
   :widths: 30 15 55

   * - Field
     - Type
     - Description
   * - ``ApplicationProfileName``
     - string
     - Unique profile identifier
   * - ``ApplicationProfileVersion``
     - string
     - Version (PEP 440 format, e.g., ``1.0.0``)
   * - ``ApplicationName``
     - string
     - Application identifier (e.g., ``DragenGermline``, ``CustomPipeline``)
   * - ``ApplicationType``
     - string
     - Free-form label describing how the pipeline runs (e.g. ``Dragen``,
       ``Cloud``, ``External``) -- does not change what gets exported

DRAGEN Profile Fields
~~~~~~~~~~~~~~~~~~~~~~

When ``ApplicationType`` is ``Dragen``, these additional fields are required:

.. list-table::
   :header-rows: 1
   :widths: 20 15 65

   * - Field
     - Type
     - Description
   * - ``Settings``
     - dict
     - Key-value pairs for the ``[AppName_Settings]`` sample sheet section.
       Common keys: ``SoftwareVersion``, ``AppVersion``, ``MapAlignOutFormat``
   * - ``Data``
     - dict
     - Default values for the ``[AppName_Data]`` section columns
   * - ``DataFields``
     - list
     - Column names to include in the ``[AppName_Data]`` section

Optional DRAGEN field:

.. list-table::
   :header-rows: 1
   :widths: 20 15 65

   * - Field
     - Type
     - Description
   * - ``Translate``
     - dict
     - Field name mappings. Maps profile field names to sample sheet column
       names (e.g., ``IndexI7: Index`` maps the i7 index to the ``Index`` column)

Example DRAGEN Profile
~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: yaml

   ---
   ApplicationProfileName: DragenGermlineIdtWgs
   ApplicationProfileVersion: 1.0.0
   ApplicationType: Dragen
   ApplicationName: DragenGermline

   Settings:
     SoftwareVersion: 4.1.23
     AppVersion: 1.2.1
     MapAlignOutFormat: bam
     KeepFastq: true

   Data:
     ReferenceGenomeDir: hg38-alt_masked.cnv.graph.hla.rna-8-1667497097-2
     VariantCallingMode: AllVariantCallers
     QcCoverage1BedFile: na
     QcCoverage2BedFile: na
     QcCoverage3BedFile: na

   DataFields:
     - ReferenceGenomeDir
     - VariantCallingMode
     - QcCoverage1BedFile
     - QcCoverage2BedFile
     - QcCoverage3BedFile
     - Sample_ID

This generates sample sheet sections like:

.. code-block:: text

   [DragenGermline_Settings]
   SoftwareVersion,4.1.23
   AppVersion,1.2.1
   MapAlignOutFormat,bam
   KeepFastq,true

   [DragenGermline_Data]
   ReferenceGenomeDir,VariantCallingMode,...,Sample_ID
   hg38-alt_masked...,AllVariantCallers,...,Sample_001

External Profile Fields
~~~~~~~~~~~~~~~~~~~~~~~~

External profiles (``ApplicationType`` is anything other than ``Dragen``)
only require the four core fields. Additional fields are optional and can be
used to store pipeline-specific configuration:

.. list-table::
   :header-rows: 1
   :widths: 20 15 65

   * - Field
     - Type
     - Description
   * - ``Settings``
     - dict
     - Optional. Pipeline configuration (URLs, parameters, etc.)
   * - ``Data``
     - dict
     - Optional. Default values for sample-level fields
   * - ``DataFields``
     - list
     - Optional. Field names to include as columns in this profile's
       ``[AppName_Data]`` Sample Sheet section

Example External Profiles
~~~~~~~~~~~~~~~~~~~~~~~~~~

**Minimal external profile:**

.. code-block:: yaml

   ---
   ApplicationProfileName: ExternalVariantCalling
   ApplicationProfileVersion: 1.0.0
   ApplicationName: CustomVariantPipeline
   ApplicationType: External

   DataFields:
     - Sample_ID

**External profile with configuration:**

.. code-block:: yaml

   ---
   ApplicationProfileName: CloudAnalysisPipeline
   ApplicationProfileVersion: 2.1.0
   ApplicationName: CloudGenomics
   ApplicationType: Cloud

   Settings:
     PipelineUrl: "https://pipeline.example.com/api/v2"
     OutputBucket: "s3://results-bucket"
     NotifyEmail: "lab@example.com"
     QueuePriority: "high"

   Data:
     AnalysisMode: "germline"
     ReferenceGenome: "GRCh38"

   DataFields:
     - Sample_ID
     - AnalysisMode
     - ReferenceGenome

External profiles generate sample sheet sections exactly like DRAGEN
profiles do -- an ``[AppName_Settings]`` / ``[AppName_Data]`` pair, named
after the profile's ``ApplicationName`` -- and are not included in the
JSON metadata export. Use them to track which external pipelines should
process which samples, and to carry the settings and per-sample data those
pipelines need directly into the Sample Sheet for a downstream tool to
read.

Validation
----------

Test Profile Validation
~~~~~~~~~~~~~~~~~~~~~~~~

- All required fields must be present and non-empty; a field with nothing
  after it (``Version:``) is empty
- ``Version`` must be a valid PEP 440 version
- ``ApplicationProfiles`` must be a non-empty list
- Each application profile reference must have a name and a version
  constraint, and the constraint must itself be valid PEP 440
- A version written as a number with a decimal point -- ``Version: 1.10``,
  or ``ApplicationProfileVersion: 1.10`` in a reference -- is refused: YAML
  reads it as the number 1.1. Put it in quotes: ``"1.10"``

Application Profile Validation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- All four required fields must be present and non-empty; a field with
  nothing after it is empty
- ``ApplicationProfileVersion`` must be a valid PEP 440 version, in quotes
  when it has a decimal point (``"1.10"``; unquoted, YAML reads it as 1.1,
  and two versions could become one)
- ``ApplicationName`` may only contain letters, digits, ``_`` and ``-`` --
  it becomes a section name in the Sample Sheet (``[<name>_Settings]``),
  written exactly as given
- ``Settings``, ``Data``, ``DataFields`` and ``Translate`` may not hold a
  hidden character anywhere -- no line break, tab or other invisible
  control character, in a key or a value. They are written into the Sample
  Sheet as cells, and a line break there would start a new line in it.
  A YAML block value (``|`` or ``>``) ends in a line break, so it is
  refused; write the value on one line, or use ``>-`` with no blank line
  inside
- Every name -- a ``Settings`` or ``Data`` key, a ``DataFields`` entry, and
  both sides of ``Translate`` -- must be text made only of letters, digits,
  ``_`` and ``-``. Names start a line or name a column in the Sample Sheet,
  and a name such as ``[BCLConvert_Data]`` would start a section of its
  own. Quote a name that YAML would read as a number or as true/false
  (``"1"``, ``"yes"``, ``"on"``); the same goes for ``ApplicationName``
- No ``Settings`` or ``Data`` value may start with ``[``, even after
  spaces -- written first on a line, it would start a new section. A value
  written as a YAML list is written as ``['a', 'b']``, so it is refused too
- Every ``Settings`` and ``Data`` value must be text, a whole number or
  ``true``/``false``. These are refused, because the Sample Sheet would not
  get what the file says:

  - a number with a decimal point, such as ``SoftwareVersion: 4.10`` --
    YAML reads it as 4.1. Put it in quotes: ``"4.10"``
  - an empty value (a key with nothing after it). Write ``''`` for an empty
    cell
  - a mapping or a list, which would be written as Python text
  - a date such as ``2024-01-01`` (or a date and time), which YAML reads as
    a date, and any other value YAML does not read as text, a number or
    ``true``/``false`` (``!!binary``, ``!!set``). Put a date in quotes:
    ``"2024-01-01"``

- ``BarcodeMismatchesIndex1`` and ``BarcodeMismatchesIndex2`` (BCL Convert
  allows at most 2 mismatches): as a ``Settings`` entry, 0, 1 or 2. As a
  ``Data`` default for a sample's column -- also a column that
  ``Translate`` renames to one of them -- 0, 1, 2, blank (``''``) or ``na``,
  which Illumina uses for a setting that does not apply to a sample.
  ``true`` and ``false`` are refused
- In the profile whose ``ApplicationName`` is ``BCLConvert``, ``Settings``
  may not set ``OverrideCycles``, ``OverrideReads``,
  ``RunInfoIndex2ReverseComplement`` or ``Index2ColumnReverseComplement``
  (in any mix of capitals). They change how BCL Convert reads the i5 or
  the OverrideCycles that SeqSetup writes for the run's instrument (see
  :doc:`instruments`). ``OverrideCycles`` as a data column is fine. A
  profile already stored with one of them stops **Mark Ready** with
  *"Failed to generate exports"*
- The data section must have a ``Sample_ID`` column, or no row would name
  its sample: ``Sample_ID`` must be in ``DataFields`` (or, when
  ``DataFields`` is missing or empty, be a key of ``Data``), as it is or
  renamed to it by ``Translate``
- ``Settings``, ``Data`` and ``Translate`` must be mappings and
  ``DataFields`` a list, when given. A section left empty (``Settings:``
  with nothing under it) means "none"
- If ``ApplicationType`` is ``Dragen``: ``Settings`` and ``Data`` must be
  present and be dicts, and ``DataFields`` must be present and be a list.
  For a DRAGEN profile an empty section is refused

.. note::
   These checks run when a profile file is pulled in by :ref:`Config Sync
   <config-sync>`. A file that fails them is **not** imported, and does not
   count towards the "N profiles synced" total on the Config Sync page --
   but no per-file error is shown there either. The reason is only visible
   on :doc:`Admin > Logs <logs>`, as a warning naming the file.

   The sync then replaces the stored profiles with the ones that passed, so
   a run that needs a refused profile is stopped at **Mark Ready** with
   *"Application profile '<name>' version '<version>' not found"*. If
   **every** application profile (or every test profile) is refused, the
   sync stops instead and changes nothing: the profiles stored before stay
   in use.

Runtime Validation
~~~~~~~~~~~~~~~~~~~

When validating a sequencing run (see :doc:`/user-guide/validation`),
SeqSetup checks:

1. Test profiles exist for all samples with test IDs
2. Referenced application profiles exist with compatible versions
3. DRAGEN applications are available on the selected instrument
4. Software versions match instrument capabilities
5. No version conflicts across samples in the same run

.. _config-sync:

Bringing profiles in: Config Sync
-------------------------------------

Application profiles and test profiles reach SeqSetup in exactly one way:
synced in from a GitHub repository, from **Admin > Config Sync**. There is
no form to create or edit a profile directly in the app -- write the YAML
(the local files under ``config/profiles/`` in this repository are examples
of the format to use), push it to your own repository, and sync.

.. figure:: /_static/screenshots/admin/config-sync.png
   :alt: The GitHub Config Sync form, with a repository URL and branch filled in and the Save Configuration button outlined.

   The **Config Sync** form, with **Save Configuration** outlined.

What one sync does
~~~~~~~~~~~~~~~~~~~~~

A sync (manual or scheduled) always does all of the following:

- **Application profiles** and **test profiles** are fetched recursively
  from their configured repository paths and **completely replace** what is
  already stored -- every application and test profile not present in this
  sync is gone afterwards, whether or not **Enable scheduled sync** is
  checked.
- **Instruments** and **index kits** are each synced only if their own
  checkbox (**Also sync instruments** / **Also sync index kits**) is on.
  Instruments are also replaced wholesale, but an instrument's **Enabled**
  state (see :doc:`instruments`) is carried forward across the replace by
  matching on its samplesheet name -- disabling one is not undone by the
  next sync. If any instrument file or folder is refused -- it cannot be
  downloaded or read, a subfolder cannot be listed, it breaks a rule, or
  two files give the same instrument -- **no** instrument settings are
  stored and the stored ones, with their switches, stay; the sync reports
  that it failed and names each refused file, and still syncs the
  profiles and index kits (see :doc:`instruments`). Index kits keep any
  kit uploaded directly through the UI; only previously *synced* kits are
  replaced.
- As a safety net, a sync that would replace an existing, non-empty
  collection with **zero** fetched items is refused rather than applied --
  a misconfigured path or a network blip cannot wipe out reference data
  that was already there. (When an instrument file was refused, no
  instruments are stored anyway.)

.. warning::
   Syncing instruments changes what a **new** run can be set up on -- see
   the warning on :doc:`instruments`. Syncing profiles or index kits does
   not touch any existing run's own stored data, but it can change how that
   run validates the *next* time it is checked (a profile version bump or
   removal can turn a passing run into a failing one, or the reverse). A
   run's already pre-generated exports (Ready or Archived) are not
   regenerated by a sync -- only re-opening its validation, or moving it
   through Ready again, sees the new definitions.

Manual vs. scheduled
~~~~~~~~~~~~~~~~~~~~~~~

**Run Manual Sync** runs a sync immediately, regardless of the **Enable
scheduled sync** checkbox -- that checkbox only controls the background
scheduler described next.

SeqSetup also syncs on a schedule, in a background thread that starts with
the application and checks once a minute whether a sync is due. A scheduled
sync runs only when **all** of these are true: **Enable scheduled sync** is
checked, a **Repository URL** is configured, and at least **Sync Interval
(minutes)** (1-1440, default 60) has passed since the last sync. With no
repository configured -- the default -- nothing ever runs on its own.

Both the interactive and the scheduled sync record an entry on the
:doc:`audit-trail` page.

Who can do this
-------------------

Viewing profiles, from **Settings > Profiles**, needs no special role.
Configuring or triggering Config Sync, from **Admin > Config Sync**,
requires the **Admin** role.
