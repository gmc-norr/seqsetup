Export
======

SeqSetup supports exporting run configuration in two formats.

SampleSheet v2
--------------

The primary export format is the Illumina SampleSheet v2 CSV format, used by
BCLConvert and DRAGEN on modern Illumina instruments.

The exported sample sheet contains the following sections:

``[Header]``
   Run metadata including file format version, run name, run description, and
   instrument platform.

``[Reads]``
   Cycle counts for Read 1, Read 2, Index 1, and Index 2.

``[BCLConvert_Settings]``
   Demultiplexing settings including barcode mismatch tolerances, adapter behavior,
   global override cycles (if applicable), and FASTQ compression format.

``[BCLConvert_Data]``
   Per-sample data rows with sample ID, index sequences, project, and optionally
   per-sample override cycles, lane assignments, and barcode mismatch overrides.

``[DRAGENPipeline_Settings]`` and ``[DRAGENPipeline_Data]``
   If DRAGEN onboard analysis is configured, additional sections for each pipeline
   type (Germline, Somatic, RNA) are included with reference genome paths and
   sample assignments.

A UUID is embedded in the sample sheet to enable linkage with the JSON metadata
export.

Instrument-Specific Adjustments
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The exported sample sheet includes instrument-specific adjustments:

- **i5 orientation** -- For instruments that read i5 in reverse-complement (NovaSeq X,
  NovaSeq 6000, HiSeq 4000, HiSeq X), the Index 2 override cycles segment is
  automatically reversed.
- **Platform name** -- The instrument platform name matches the Illumina-expected value.

JSON Metadata
-------------

All run and sample metadata can be exported in JSON format. The JSON export includes:

- Sample identifiers and test identifiers
- Index sequences and kit information
- Override cycles and barcode mismatch settings
- Lane assignments
- Instrument configuration (type, flowcell, run cycles)
- Analysis configurations
- User information and run comments
- Timestamps and the shared UUID

The JSON file represents the complete dataset for the sequencing run, including
information that is not supported by the SampleSheet v2 format (e.g., test
identifiers, detailed metadata).
