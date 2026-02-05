Export
======

Export endpoints provide instrument-ready SampleSheet files and structured
metadata for individual runs. These endpoints are accessed through the web
interface using session authentication.

.. note::

   For programmatic access with Bearer token authentication, see the
   :doc:`runs` API endpoints (``/api/runs/{run_id}/samplesheet-v2``, etc.).

Export SampleSheet v2
---------------------

.. http:get:: /runs/{run_id}/export/samplesheet-v2

   Download an Illumina SampleSheet v2 CSV file for the specified run.

   :param run_id: Run UUID
   :status 200: Returns the SampleSheet CSV as a file download.
   :status 404: Run not found.
   :status 500: Error generating the SampleSheet.

   **Response headers**::

      Content-Type: text/csv
      Content-Disposition: attachment; filename="Run_2025_001.csv"

   The generated SampleSheet v2 contains the following sections:

   - ``[Header]`` -- Run metadata and instrument platform
   - ``[Reads]`` -- Cycle counts for all read and index segments
   - ``[BCLConvert_Settings]`` -- Demultiplexing configuration
   - ``[BCLConvert_Data]`` -- Per-sample index and lane assignments
   - DRAGEN pipeline sections (if configured)

   For details on the SampleSheet format, see
   :doc:`/architecture/samplesheet-format`.

Export SampleSheet v1
---------------------

.. http:get:: /runs/{run_id}/export/samplesheet-v1

   Download a SampleSheet v1 CSV file for instruments that support it
   (e.g., MiSeq i100 Series).

   :param run_id: Run UUID
   :status 200: Returns the SampleSheet CSV as a file download.
   :status 400: SampleSheet v1 not supported for this instrument.
   :status 404: Run not found.
   :status 500: Error generating the SampleSheet.

Export JSON Metadata
--------------------

.. http:get:: /runs/{run_id}/export/json

   Download full run metadata in JSON format for the specified run.

   :param run_id: Run UUID
   :status 200: Returns the JSON metadata as a file download.
   :status 404: Run not found.
   :status 500: Error generating the JSON export.

   **Response headers**::

      Content-Type: application/json
      Content-Disposition: attachment; filename="Run_2025_001.json"

   **Example response**:

   .. code-block:: json

      {
        "id": "a1b2c3d4-...",
        "run_name": "Run_2025_001",
        "run_description": "Exome capture batch 12",
        "instrument": {
          "platform": "NovaSeq X Series",
          "flowcell_type": "10B",
          "reagent_cycles": 300
        },
        "cycles": {
          "read1_cycles": 151,
          "read2_cycles": 151,
          "index1_cycles": 10,
          "index2_cycles": 10,
          "total_cycles": 322
        },
        "bclconvert_settings": {
          "barcode_mismatches_index1": 1,
          "barcode_mismatches_index2": 1,
          "adapter_behavior": "trim",
          "global_override_cycles": "Y151;I8N2;I8N2;Y151",
          "create_fastq_for_index_reads": false,
          "no_lane_splitting": false
        },
        "samples": [
          {
            "id": "e5f6a7b8-...",
            "sample_id": "Sample_01",
            "sample_name": "Sample_01",
            "project": "ProjectA",
            "lanes": [1],
            "index1": {
              "name": "UDP0001",
              "sequence": "AACGTTCC",
              "length": 8
            },
            "index2": {
              "name": "UDP0001",
              "sequence": "GGAACTTG",
              "length": 8
            },
            "override_cycles": "Y151;I8N2;I8N2;Y151",
            "analyses": [],
            "description": "",
            "metadata": {}
          }
        ],
        "index_kits": [
          {
            "name": "IDT for Illumina DNA/RNA UD Indexes",
            "version": "1.0.0",
            "description": "96 unique dual index pairs",
            "index_count": 96,
            "is_fixed_layout": true,
            "index_pairs": ["..."]
          }
        ],
        "analyses": []
      }

   The JSON export includes all metadata for the run, including information
   not representable in the SampleSheet v2 format (e.g., test identifiers,
   index kit details, detailed sample metadata).

Export Validation Report (JSON)
-------------------------------

.. http:get:: /runs/{run_id}/export/validation-report

   Download the validation report in JSON format.

   :param run_id: Run UUID
   :status 200: Returns the validation report JSON as a file download.
   :status 404: Run not found.
   :status 500: Error generating the validation report.

Export Validation Report (PDF)
------------------------------

.. http:get:: /runs/{run_id}/export/validation-pdf

   Download the validation report as a PDF document.

   :param run_id: Run UUID
   :status 200: Returns the validation report PDF as a file download.
   :status 404: Run not found.
   :status 500: Error generating the validation PDF.

Differences Between Formats
---------------------------

.. list-table::
   :header-rows: 1
   :widths: 40 15 15

   * - Data
     - SampleSheet v2
     - JSON
   * - Sample indexes and sequences
     - Yes
     - Yes
   * - Override cycles
     - Yes
     - Yes
   * - Lane assignments
     - Yes
     - Yes
   * - Barcode mismatch settings
     - Yes
     - Yes
   * - DRAGEN pipeline configuration
     - Yes
     - Yes
   * - Index kit metadata
     - No
     - Yes
   * - Sample metadata and descriptions
     - No
     - Yes
   * - Timestamps and user tracking
     - No
     - Yes
   * - Run UUID for traceability
     - Yes (in header)
     - Yes
