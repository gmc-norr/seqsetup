Runs
====

List Runs
---------

.. http:get:: /api/runs

   List sequencing runs filtered by status.

   :query status: Filter by run status. One of ``draft``, ``ready``, or
      ``archived``. Defaults to ``ready``.
   :status 200: Returns a JSON array of run objects.
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
   * - ``lane``
     - integer
     - Flowcell lane assignment
   * - ``index_pair``
     - object
     - Assigned index pair with ``index1`` and ``index2`` sub-objects
       containing ``name``, ``sequence``, and ``length``
   * - ``override_cycles``
     - string
     - Override cycles string (e.g., ``Y151;I8N2;I8N2;Y151``) or null
   * - ``description``
     - string
     - Optional sample description
   * - ``metadata``
     - object
     - Additional sample metadata
