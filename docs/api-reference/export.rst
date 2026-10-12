Export
======

Export endpoints provide instrument-ready SampleSheet files and structured
metadata for individual runs. These endpoints are accessed through the web
interface using session authentication.

.. note::

   For programmatic access with Bearer token authentication, see the
   :doc:`runs` API endpoints (``/api/runs/{run_id}/samplesheet-v2``, etc.).

The downloaded file's name
--------------------------

Every download names its file after the run, in a
``Content-Disposition: attachment`` header. The ``filename`` parameter is
always plain ASCII: accents are removed (``Příliš`` becomes ``Prilis``),
any other character outside ASCII is dropped, and if that leaves nothing
the endpoint's own default is used (``SampleSheet_v2``, ``SampleSheet``,
``run_metadata``, ``validation_report``). When the run's name is not ASCII,
a second parameter carries the name's own letters -- so a Polish, Czech,
Turkish, Cyrillic or CJK name is not lost -- UTF-8 percent-encoded, after
the same scrub every download name gets (spaces become ``_``, and
punctuation other than ``-`` and ``.`` is dropped)::

   Content-Disposition: attachment; filename="Prilis_zlutoucky.csv"; filename*=UTF-8''P%C5%99%C3%ADli%C5%A1_%C5%BElu%C5%A5ou%C4%8Dk%C3%BD.csv

Browsers prefer ``filename*`` and so save the file under that name; the
ASCII ``filename`` is the fallback for clients that do not understand it
(RFC 6266 / RFC 5987). A run whose name is already ASCII gets the single
``filename`` parameter, unchanged.

Export SampleSheet v2
---------------------

``GET /runs/{run_id}/export/samplesheet-v2``

Download an Illumina SampleSheet v2 CSV file for the specified run.

:``run_id``: Run UUID

====== ============================================================
Status Meaning
====== ============================================================
200    Returns the SampleSheet CSV as a file download.
403    Run is a draft (exports are only available for ready or
       archived runs).
404    Run not found.
500    Error generating the SampleSheet.
503    The synced instrument settings cannot be used; the
       message names the config sync to run.
====== ============================================================

**Response headers**::

   Content-Type: text/csv
   Content-Disposition: attachment; filename="Run_2025_001.csv"

The generated SampleSheet v2 contains the following sections:

- ``[Header]`` -- Run metadata and instrument platform
- ``[Reads]`` -- Cycle counts for all read and index segments
- One ``[AppName_Settings]`` / ``[AppName_Data]`` pair per application
  profile a sample's Test ID and test version resolve to (e.g.
  ``[BCLConvert_Settings]`` /
  ``[BCLConvert_Data]``, ``[DragenGermline_Settings]`` /
  ``[DragenGermline_Data]``) -- absent entirely if no sample's test
  resolves to one
- ``[Cloud_Settings]`` / ``[Cloud_Data]`` -- always written

For details on the SampleSheet format, see
:doc:`/architecture/samplesheet-format`.

Export SampleSheet v1
---------------------

``GET /runs/{run_id}/export/samplesheet-v1``

Download a SampleSheet v1 CSV file for instruments that support it
(e.g., MiSeq, NovaSeq 6000).

:``run_id``: Run UUID

====== ============================================================
Status Meaning
====== ============================================================
200    Returns the SampleSheet CSV as a file download.
400    SampleSheet v1 not supported for this instrument.
403    Run is a draft (exports are only available for ready or
       archived runs).
404    Run not found.
500    Error generating the SampleSheet.
503    The synced instrument settings cannot be used; the
       message names the config sync to run.
====== ============================================================

Export JSON Metadata
--------------------

``GET /runs/{run_id}/export/json``

Download full run metadata in JSON format for the specified run.

:``run_id``: Run UUID

====== ============================================================
Status Meaning
====== ============================================================
200    Returns the JSON metadata as a file download.
403    Run is a draft (exports are only available for ready or
       archived runs).
404    Run not found.
500    Error generating the JSON export.
503    The synced instrument settings cannot be used; the
       message names the config sync to run.
====== ============================================================

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
         "samplesheet_index2": "GGAACTTG",
         "override_cycles": "Y151;I8N2;I8N2;Y151",
         "samplesheet_override_cycles": "Y151;I8N2;N2I8;Y151",
         "analyses": [],
         "description": "",
         "metadata": {}
       }
     ],
     "analyses": []
   }

``global_override_cycles`` is the Override Cycles every sample has -- its
own stored value (typed by hand or not), otherwise the calculated one -- or
``null`` when the samples' values differ. Each sample's own
``override_cycles`` is always given.

As typed, and as in the sheet
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Two of a sample's values are given twice, because the Sample Sheet does not
always write them the way they were typed. Which instrument the run is on,
and which of its i5 workflows, decides that (see :doc:`/admin-guide/instruments`).

**As typed** -- the index as the kit lists it, and the Override Cycles in
reading order (the index first):

- ``index1.sequence`` and ``index2.sequence``
- ``override_cycles``, and the run-level ``global_override_cycles``

**As in the Sample Sheet v2** -- exactly the characters that run's sheet
puts in the cell, taken from the same code that writes the sheet:

- ``samplesheet_index2`` -- the sheet's ``Index2`` cell. It is the reverse
  complement of ``index2.sequence`` for a run whose workflow reads the i5
  reversed and whose RunInfo.xml does not mark that; the same sequence
  otherwise.
- ``samplesheet_override_cycles`` -- the sheet's ``OverrideCycles`` cell.
  Its Index 2 part is reversed (``I8N2`` becomes ``N2I8``) for a run whose
  workflow reads the i5 reversed and whose RunInfo.xml *does* mark that; the
  same string otherwise.

A run is in at most one of those two states, so at most one of the two pairs
differs. Both ``samplesheet_`` values are ``null`` when the sheet's cell
would be empty (a sample with no i5, a sample with no Override Cycles), and
when SeqSetup can no longer say what the sheet would write -- a run whose
instrument has no settings any more, for which no Sample Sheet can be
written either.

A run marked Ready before these two keys existed keeps the export stored
for it, which has neither key. The API serves that stored export and
nothing else, and the download route falls back to generating one live only
for a run that has none stored at all. Archiving keeps the stored export
and Archived is terminal, so that shape stays for good; returning the run
to Draft discards the stored export, and marking the run Ready again writes
a new one with both keys. A consumer should therefore test that
``samplesheet_index2`` is present rather than read a missing key as "this
sample has no i5".

The JSON export includes information not representable in the SampleSheet
v2 format, such as sample names, projects, descriptions, and free-form
metadata. It does **not** include a sample's Test ID, its index kit name,
per-sample barcode-mismatch overrides, or any user/timestamp tracking for
the run -- those fields are not serialized.

Export Validation Report (JSON)
-------------------------------

``GET /runs/{run_id}/export/validation-report``

Download the validation report in JSON format. Its ``timestamp`` is when
the report was made, in the server's time zone with its offset from UTC
(for example ``2026-03-10T10:17:04.512345+01:00``).

:``run_id``: Run UUID

====== ============================================================
Status Meaning
====== ============================================================
200    Returns the validation report JSON as a file download.
403    Run is a draft (exports are only available for ready or
       archived runs).
404    Run not found.
500    Error generating the validation report.
503    The synced instrument settings cannot be used; the
       message names the config sync to run.
====== ============================================================

Export Validation Report (PDF)
------------------------------

``GET /runs/{run_id}/export/validation-pdf``

Download the validation report as a PDF document.

:``run_id``: Run UUID

====== ============================================================
Status Meaning
====== ============================================================
200    Returns the validation report PDF as a file download.
403    Run is a draft (exports are only available for ready or
       archived runs).
404    Run not found.
500    Error generating the validation PDF.
503    The synced instrument settings cannot be used; the
       message names the config sync to run.
====== ============================================================

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
     - No
   * - Sample metadata and descriptions
     - No
     - Yes
   * - Timestamps and user tracking
     - No
     - No
   * - Run UUID for traceability
     - Yes (in header)
     - Yes
