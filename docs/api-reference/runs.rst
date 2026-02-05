Runs
====

Access Restrictions
-------------------

The API only provides access to runs that have been finalized. Draft runs are
not accessible via the API to prevent exposure of incomplete or unapproved
configurations.

**Allowed statuses:** ``ready``, ``archived``

Attempting to access a draft run or specifying ``draft`` as a status filter
returns HTTP 403 Forbidden.

List Runs
---------

.. http:get:: /api/runs

   List sequencing runs filtered by status.

   :query status: Filter by run status. One of ``ready`` or ``archived``.
      Defaults to ``ready``. The ``draft`` status is not allowed via API.
   :status 200: Returns a JSON array of run objects.
   :status 400: Invalid status (e.g., ``draft`` was requested).
   :status 401: Authentication required.

   **Example request**::

      GET /api/runs?status=ready HTTP/1.1
      Authorization: Bearer <token>

   **Example response**:

   .. code-block:: json

      [
        {
          "id": "a1b2c3d4-...",
          "run_name": "Run_2025_001",
          "run_description": "Exome capture batch 12",
          "status": "ready",
          "validation_approved": true,
          "created_by": "jdoe",
          "updated_by": "jdoe",
          "created_at": "2025-06-15T10:30:00",
          "updated_at": "2025-06-15T14:22:00",
          "instrument_platform": "NovaSeq X Series",
          "flowcell_type": "10B",
          "reagent_cycles": 300,
          "run_cycles": {
            "read1_cycles": 151,
            "read2_cycles": 151,
            "index1_cycles": 10,
            "index2_cycles": 10,
            "total_cycles": 322
          },
          "barcode_mismatches_index1": 1,
          "barcode_mismatches_index2": 1,
          "adapter_behavior": "trim",
          "create_fastq_for_index_reads": false,
          "no_lane_splitting": false,
          "samples": ["..."],
          "analyses": ["..."]
        }
      ]

   Each run object contains the full run configuration including all samples
   and analysis definitions. See :doc:`export` for endpoints that return
   instrument-ready SampleSheet v2 or structured JSON metadata.

Run Object Fields
-----------------

.. list-table::
   :header-rows: 1
   :widths: 25 15 60

   * - Field
     - Type
     - Description
   * - ``id``
     - string
     - Unique run identifier (UUID)
   * - ``run_name``
     - string
     - User-assigned run name
   * - ``run_description``
     - string
     - Optional run description or comments
   * - ``status``
     - string
     - Run status: ``draft``, ``ready``, or ``archived``
   * - ``validation_approved``
     - boolean
     - Whether the run has passed validation
   * - ``created_by``
     - string
     - Username of the user who created the run
   * - ``updated_by``
     - string
     - Username of the user who last modified the run
   * - ``created_at``
     - string
     - ISO 8601 timestamp of creation
   * - ``updated_at``
     - string
     - ISO 8601 timestamp of last update
   * - ``instrument_platform``
     - string
     - Instrument platform (e.g., ``NovaSeq X Series``, ``MiSeq i100 Series``)
   * - ``flowcell_type``
     - string
     - Flowcell type (e.g., ``10B``, ``25B``, ``50M``)
   * - ``reagent_cycles``
     - integer
     - Maximum cycles supported by the reagent kit
   * - ``run_cycles``
     - object
     - Cycle configuration with ``read1_cycles``, ``read2_cycles``,
       ``index1_cycles``, ``index2_cycles``, and computed ``total_cycles``
   * - ``barcode_mismatches_index1``
     - integer
     - Default allowed mismatches for i7 index
   * - ``barcode_mismatches_index2``
     - integer
     - Default allowed mismatches for i5 index
   * - ``adapter_behavior``
     - string
     - Adapter handling mode (e.g., ``trim``)
   * - ``create_fastq_for_index_reads``
     - boolean
     - Whether to generate FASTQ files for index reads
   * - ``no_lane_splitting``
     - boolean
     - Whether to disable lane splitting in output
   * - ``samples``
     - array
     - List of sample objects (see below)
   * - ``analyses``
     - array
     - List of analysis configuration objects

Sample Object Fields
--------------------

Each sample in the ``samples`` array contains:

.. list-table::
   :header-rows: 1
   :widths: 25 15 60

   * - Field
     - Type
     - Description
   * - ``id``
     - string
     - Unique sample identifier (UUID)
   * - ``sample_id``
     - string
     - User-assigned sample ID
   * - ``sample_name``
     - string
     - Sample display name
   * - ``project``
     - string
     - Project assignment
   * - ``test_id``
     - string
     - Associated test identifier
   * - ``worksheet_id``
     - string
     - Source worksheet ID (from LIMS import)
   * - ``lanes``
     - array
     - Flowcell lane assignments (empty array = all lanes)
   * - ``index_pair``
     - object
     - Assigned index pair (unique dual mode) with ``index1`` and ``index2``
       sub-objects containing ``name``, ``sequence``, and ``length``
   * - ``index1``
     - object
     - i7 index (combinatorial/single mode) with ``name``, ``sequence``, ``length``
   * - ``index2``
     - object
     - i5 index (combinatorial mode) with ``name``, ``sequence``, ``length``
   * - ``index_kit_name``
     - string
     - Name of the index kit the assigned indexes came from
   * - ``override_cycles``
     - string
     - Override cycles string (e.g., ``Y151;I8N2;I8N2;Y151``) or null
   * - ``barcode_mismatches_index1``
     - integer
     - Per-sample allowed mismatches for i7 index (default: 1)
   * - ``barcode_mismatches_index2``
     - integer
     - Per-sample allowed mismatches for i5 index (default: 1)
   * - ``analyses``
     - array
     - List of analysis IDs assigned to this sample
   * - ``description``
     - string
     - Optional sample description
   * - ``metadata``
     - object
     - Additional sample metadata

Get SampleSheet v2
------------------

.. http:get:: /api/runs/{run_id}/samplesheet-v2

   Get the pre-generated SampleSheet v2 CSV for a ready or archived run.

   :param run_id: Run UUID
   :status 200: Returns the SampleSheet v2 CSV.
   :status 403: Run is a draft (not accessible via API).
   :status 404: Run not found or SampleSheet not yet generated.

   **Example request**::

      GET /api/runs/a1b2c3d4-.../samplesheet-v2 HTTP/1.1
      Authorization: Bearer <token>

   **Response headers**::

      Content-Type: text/csv

Get SampleSheet v1
------------------

.. http:get:: /api/runs/{run_id}/samplesheet-v1

   Get the pre-generated SampleSheet v1 CSV for instruments that support it
   (e.g., MiSeq).

   :param run_id: Run UUID
   :status 200: Returns the SampleSheet v1 CSV.
   :status 403: Run is a draft (not accessible via API).
   :status 404: Run not found or SampleSheet v1 not available for this run.

   **Example request**::

      GET /api/runs/a1b2c3d4-.../samplesheet-v1 HTTP/1.1
      Authorization: Bearer <token>

   **Response headers**::

      Content-Type: text/csv

Get JSON Metadata
-----------------

.. http:get:: /api/runs/{run_id}/json

   Get the pre-generated JSON metadata for a ready or archived run.

   :param run_id: Run UUID
   :status 200: Returns the JSON metadata.
   :status 403: Run is a draft (not accessible via API).
   :status 404: Run not found or JSON not yet generated.

   **Example request**::

      GET /api/runs/a1b2c3d4-.../json HTTP/1.1
      Authorization: Bearer <token>

   **Response headers**::

      Content-Type: application/json

Get Validation Report (JSON)
----------------------------

.. http:get:: /api/runs/{run_id}/validation-report

   Get the pre-generated validation report in JSON format.

   :param run_id: Run UUID
   :status 200: Returns the validation report JSON.
   :status 403: Run is a draft (not accessible via API).
   :status 404: Run not found or validation report not yet generated.

   **Example request**::

      GET /api/runs/a1b2c3d4-.../validation-report HTTP/1.1
      Authorization: Bearer <token>

   **Response headers**::

      Content-Type: application/json

Get Validation Report (PDF)
---------------------------

.. http:get:: /api/runs/{run_id}/validation-pdf

   Get the pre-generated validation report as a PDF document.

   :param run_id: Run UUID
   :status 200: Returns the validation report PDF.
   :status 403: Run is a draft (not accessible via API).
   :status 404: Run not found or validation PDF not yet generated.

   **Example request**::

      GET /api/runs/a1b2c3d4-.../validation-pdf HTTP/1.1
      Authorization: Bearer <token>

   **Response headers**::

      Content-Type: application/pdf
