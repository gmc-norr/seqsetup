Profiles
========

SeqSetup uses a profile system to define reusable configurations for test types
and analysis pipelines. Profiles enable consistent sample sheet generation and
support both on-instrument DRAGEN pipelines and external analysis workflows.

Overview
--------

The profile system consists of two types:

**Test Profiles**
   Define a sequencing test type (e.g., "WGS", "Exome", "RNA-Seq") and link it
   to one or more application profiles. When a sample has a test ID, SeqSetup
   resolves the test profile and includes the associated application pipelines
   in the sample sheet.

**Application Profiles**
   Define analysis pipeline configurations. These can be DRAGEN on-instrument
   pipelines (generating sample sheet sections) or external pipelines (metadata
   only, processed outside the sequencer).

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
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Each entry in ``ApplicationProfiles`` must contain:

- ``ApplicationProfileName`` -- Name of the application profile
- ``ApplicationProfileVersion`` -- Version constraint (PEP 440 format)

Version constraints support:

- Exact versions: ``1.0.0``
- Compatible releases: ``~=1.0.0`` (matches 1.0.x)
- Range specifiers: ``>=1.0,<2.0``

Example Test Profile
~~~~~~~~~~~~~~~~~~~~

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
--------------------

Application profiles define analysis pipeline configurations. SeqSetup supports
two types:

1. **DRAGEN profiles** -- Generate sample sheet sections for on-instrument
   analysis (BCLConvert, DragenGermline, DragenSomatic, etc.)

2. **External profiles** -- Define metadata for pipelines run outside the
   sequencer (bioinformatics workflows, cloud pipelines, custom tools)

Required Fields (All Profiles)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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
     - Profile type: ``Dragen`` for on-instrument, any other value for external

DRAGEN Profile Fields
~~~~~~~~~~~~~~~~~~~~~

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
~~~~~~~~~~~~~~~~~~~~~~

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
~~~~~~~~~~~~~~~~~~~~~~~

External profiles (``ApplicationType`` is anything other than ``Dragen``) only
require the four core fields. Additional fields are optional and can be used
to store pipeline-specific configuration:

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
     - Optional. Field names to include in JSON export

Example External Profiles
~~~~~~~~~~~~~~~~~~~~~~~~~

**Minimal external profile:**

.. code-block:: yaml

   ---
   ApplicationProfileName: ExternalVariantCalling
   ApplicationProfileVersion: 1.0.0
   ApplicationName: CustomVariantPipeline
   ApplicationType: External

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

**LIMS integration profile:**

.. code-block:: yaml

   ---
   ApplicationProfileName: LimsExport
   ApplicationProfileVersion: 1.0.0
   ApplicationName: LimsIntegration
   ApplicationType: Integration

   Settings:
     LimsEndpoint: "https://lims.example.com/api"
     AutoSubmit: true
     IncludeQcMetrics: true

External profiles are included in the JSON metadata export but do not generate
sample sheet sections. Use them to:

- Track which external pipelines should process the samples
- Store pipeline configuration for downstream automation
- Pass metadata to LIMS or workflow management systems

Validation
----------

Profiles are validated when loaded from YAML files or synced from GitHub.

Test Profile Validation
~~~~~~~~~~~~~~~~~~~~~~~

- All required fields must be present and non-empty
- ``Version`` must be a valid PEP 440 version
- ``ApplicationProfiles`` must be a non-empty list
- Each application profile reference must have name and version

Application Profile Validation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- All four required fields must be present and non-empty
- ``ApplicationProfileVersion`` must be a valid PEP 440 version
- If ``ApplicationType`` is ``Dragen``:

  - ``Settings`` must be present and be a dict
  - ``Data`` must be present and be a dict
  - ``DataFields`` must be present and be a list

Runtime Validation
~~~~~~~~~~~~~~~~~~

When validating a sequencing run, SeqSetup checks:

1. Test profiles exist for all samples with test IDs
2. Referenced application profiles exist with compatible versions
3. DRAGEN applications are available on the selected instrument
4. Software versions match instrument capabilities
5. No version conflicts across samples in the same run

Profile Storage
---------------

Profiles can be stored in two locations:

**MongoDB**
   Primary storage. Profiles synced from GitHub or created through the admin
   interface are stored in the ``application_profiles`` and ``test_profiles``
   collections.

**YAML Files**
   Local files in ``config/profiles/`` are loaded at startup:

   - ``config/profiles/application_profiles/`` -- Application profile YAML files
   - ``config/profiles/test_profiles/`` -- Test profile YAML files

   Subdirectories are supported for organization (e.g.,
   ``application_profiles/dragen/``, ``application_profiles/external/``).

GitHub Sync
-----------

Profiles can be automatically synced from a GitHub repository. Configure sync
settings through the admin interface:

1. Navigate to **Settings > Profile Sync**
2. Enter the GitHub repository URL and optional access token
3. Specify the branch and paths to sync
4. Enable automatic sync or trigger manually

The sync service pulls YAML files from the repository and updates MongoDB.
Profiles are validated during sync; invalid profiles are rejected with error
messages.

Directory Structure
-------------------

Recommended organization for profile YAML files:

.. code-block:: text

   config/profiles/
   ├── application_profiles/
   │   ├── dragen/
   │   │   ├── BCLConvertNextera.yaml
   │   │   ├── DragenGermlineIdtWgs.yaml
   │   │   ├── DragenSomaticIdt.yaml
   │   │   └── DragenRnaIdt.yaml
   │   └── external/
   │       ├── CloudAnalysisPipeline.yaml
   │       └── LimsExport.yaml
   └── test_profiles/
       ├── Wgs.yaml
       ├── Exome.yaml
       └── RnaSeq.yaml
