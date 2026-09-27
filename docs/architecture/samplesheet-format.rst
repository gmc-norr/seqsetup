SampleSheet v2 Format Reference
================================

SeqSetup generates Illumina SampleSheet v2 CSV files. This page documents the
output format.

File Structure
--------------

The sample sheet is a CSV file with named sections, each starting with a section
header in square brackets.

[Header]
^^^^^^^^

.. code-block:: text

   [Header]
   FileFormatVersion,2
   RunName,MyRun_001
   RunDescription,Whole genome sequencing
   InstrumentPlatform,NovaSeq X Series

Required fields: ``FileFormatVersion``, ``InstrumentPlatform``.
Optional fields: ``RunName``, ``RunDescription``.

[Reads]
^^^^^^^

.. code-block:: text

   [Reads]
   Read1Cycles,151
   Read2Cycles,151
   Index1Cycles,10
   Index2Cycles,10

Specifies the number of cycles for each segment of the run.

[BCLConvert_Settings]
^^^^^^^^^^^^^^^^^^^^^

.. code-block:: text

   [BCLConvert_Settings]
   SoftwareVersion,4.3.6
   FastqCompressionFormat,gzip
   NoLaneSplitting,false
   CreateFastqForIndexReads,0
   OverrideCycles,Y151;I8N2;N2I8;Y151

Settings for BCLConvert demultiplexing. ``OverrideCycles`` is included here only
when all samples share the same override cycles string. Otherwise, it appears
per-row in ``[BCLConvert_Data]``. ``BarcodeMismatchesIndex1``/``BarcodeMismatchesIndex2``
are per-sample overrides and are written in ``[BCLConvert_Data]``, not here.

``NoLaneSplitting`` and ``CreateFastqForIndexReads`` always appear (reflecting
the run's settings). ``SoftwareVersion`` and ``AdapterBehavior`` are optional --
``AdapterBehavior`` is omitted when at the default ``trim``.

[BCLConvert_Data]
^^^^^^^^^^^^^^^^^

.. code-block:: text

   [BCLConvert_Data]
   Lane,Sample_ID,Index,Index2,OverrideCycles
   1,Sample_001,ATTACTCG,TATAGCCT,Y151;I8N2;N2I8;Y151
   1,Sample_002,TCCGGAGA,ATAGAGGC,Y151;I10;I10;Y151

Columns:

- ``Lane`` -- Present only when samples have lane assignments
- ``Sample_ID`` -- User-provided sample identifier
- ``Index`` -- i7 index sequence (capitalized, for IMS compatibility)
- ``Index2`` -- i5 index sequence, in the orientation the sample sheet expects
  (capitalized, for IMS compatibility)
- ``OverrideCycles`` -- Present only when samples don't all share the same
  override cycles string (see ``[BCLConvert_Settings]`` above)
- ``BarcodeMismatchesIndex1``, ``BarcodeMismatchesIndex2`` -- Present only when
  per-sample overrides exist

Each sample-lane combination produces a separate row.

DRAGEN Sections
^^^^^^^^^^^^^^^

When DRAGEN onboard analysis is configured, additional sections are generated:

.. code-block:: text

   [DragenGermline_Settings]
   ReferenceGenomeDir,hg38
   MapAlignOutFormat,cram

   [DragenGermline_Data]
   Sample_ID
   Sample_001
   Sample_002

Supported pipeline types: ``DragenGermline``, ``DragenSomatic``, ``DragenRNA``.

When application profiles are used, the section names and settings are driven by
the profile definitions.

CSV Escaping
^^^^^^^^^^^^

Values containing commas, double quotes, or newlines are enclosed in double quotes.
Double quotes within values are escaped by doubling (``""``).

UUID Linkage
^^^^^^^^^^^^

A UUID is embedded in the exported sample sheet and JSON metadata, enabling
traceability between the instrument-compatible CSV and the complete metadata export.
