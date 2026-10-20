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
   RunDescription,0f8e2a43-5c1d-4b7e-9a6f-3d2c1b0a9e8f
   InstrumentPlatform,NovaSeqXSeries
   IndexOrientation,Forward
   Custom_UUID,0f8e2a43-5c1d-4b7e-9a6f-3d2c1b0a9e8f

Required fields: ``FileFormatVersion``, ``InstrumentPlatform``.
Optional fields: ``RunName``, ``RunDescription``.

SeqSetup writes the run's UUID twice: as ``RunDescription``, a standard key
the NovaSeq X keeps in the sheet it runs with, and as ``Custom_UUID``, a
custom key it leaves out. Another tool ties a run folder back to its
SeqSetup run by ``RunDescription``, which every instrument keeps;
``Custom_UUID`` is there only where the instrument keeps custom keys. The
run's typed description is not written into the sheet
(``docs/design/2026-10-19-lab-profile-layout-design.md``).

[Reads]
^^^^^^^

.. code-block:: text

   [Reads]
   Read1Cycles,151
   Read2Cycles,151
   Index1Cycles,10
   Index2Cycles,10

Specifies the number of cycles for each segment of the run.

Application sections
^^^^^^^^^^^^^^^^^^^^^

For every sample's **Test ID** and test version, SeqSetup resolves the
test profile they point to (the newest synced version that matches) and
the application profiles that test profile references, and
writes one ``[AppName_Settings]`` / ``[AppName_Data]`` pair for each
``ApplicationName`` -- for example ``[BCLConvert_Settings]`` /
``[BCLConvert_Data]``, or ``[DragenGermline_Settings]`` /
``[DragenGermline_Data]``. The sheet plan (``services/sheet_plan.py``, see
:doc:`services`) decides the sections; profiles that share an application
share its section when their ``Settings`` and columns match, each row
filled from its own profile. ``_write_application_section``
(``samplesheet_v2_exporter.py``) takes the ``Data`` section's columns
entirely from the application profiles' own field/column definitions
(``data_fields`` and ``translate``) -- there is no fixed section list and
no fixed column set.
The shipped profiles under ``config/profiles/application_profiles/``
give four DRAGEN application names (``DragenGermline``, ``DragenSomatic``,
``DragenRna``, ``DragenEnrichment``) plus ``BCLConvert``.

.. code-block:: text

   [BCLConvert_Settings]
   SoftwareVersion,4.3.6
   FastqCompressionFormat,gzip
   NoLaneSplitting,false
   CreateFastqForIndexReads,0

   [BCLConvert_Data]
   Lane,Sample_ID,Index,Index2,OverrideCycles
   1,Sample_001,ATTACTCG,TATAGCCT,Y151;I8N2;N2I8;Y151
   1,Sample_002,TCCGGAGA,ATAGAGGC,Y151;I10;I10;Y151

This is a NovaSeq X Series run: its ``RunInfo.xml`` marks the reversed
i5 read, so the i5 is written forward and the Index 2 part of
OverrideCycles for Sample_001's 8-base i5 on a 10-cycle read is written
``N2I8`` (see :doc:`instruments`). It is the shape the shipped
``BCLConvert`` profile happens to produce --
a different profile defines its own settings and columns and can, for
example, leave ``Lane`` or ``OverrideCycles`` out entirely. When a
profile's columns do include ``Lane``, a sample assigned to more than one
lane produces one row per lane; otherwise each sample gets a single row.
For the ``BCLConvert``-named profile specifically, the exporter also
injects the run's own ``NoLaneSplitting`` / ``CreateFastqForIndexReads`` /
``AdapterBehavior`` settings for any key the profile does not already
pin, so the operator's per-run toggles still take effect.
``NoLaneSplitting`` true next to a ``Lane`` column is a plan problem:
DRAGEN 4.3 converts without lane splitting only when the sheet has no Lane
column. A sample without an i7 or an i5 gets ``na`` in that
``BarcodeMismatchesIndex`` column. A ``Sample_Project`` or ``Sample_Name``
column -- in any application's section -- holds the sample's own project or
name, and the profile's ``Data`` default only for a sample that has none;
every other column the writer does not fill itself gets that default in
every row.

``export()`` only takes this profile-driven path when both a
``TestProfileRepository`` and an ``ApplicationProfileRepository`` are
supplied; the running application always supplies both (``startup.py``,
``routes/runs.py``, ``routes/export.py``). Without them, ``export()``
falls back to a hardcoded ``[BCLConvert_Settings]`` / ``[BCLConvert_Data]``
pair and, for each configured DRAGEN onboard analysis, a matching
``DragenGermline``, ``DragenSomatic`` or ``DragenRna`` section pair
(``_write_bclconvert_settings``, ``_write_bclconvert_data``,
``_write_dragen_sections``) -- this path exists in the exporter but the
running application never calls it.

A sample without a Test ID, a sample with a test but no test version, a
test, version or profile that cannot be found, or any other plan problem
stops the writer (``SheetPlanProblem``) instead of
leaving the sample out; Mark Ready reports the same problems as errors
first.

[Cloud_Settings] and [Cloud_Data]
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Written unconditionally on every export (``_write_cloud_sections``), for
compatibility with Illumina's Instrument Management Service -- regardless
of whether any application section above was written:

.. code-block:: text

   [Cloud_Settings]
   GeneratedVersion,2.7.0

   [Cloud_Data]
   Sample_ID,ProjectName,LibraryName
   Sample_001,MyRun_001,Sample_001_ATTACTCG_TATAGCCT

``ProjectName`` is the run's own name, not a per-sample field. ``LibraryName``
is ``{Sample_ID}_{i7}_{i5}`` when both indexes are assigned, or just the
``Sample_ID`` otherwise.

CSV Escaping
^^^^^^^^^^^^

Values containing commas, double quotes, or newlines are enclosed in double quotes.
Double quotes within values are escaped by doubling (``""``).

UUID Linkage
^^^^^^^^^^^^

A UUID is embedded in the exported sample sheet and JSON metadata, enabling
traceability between the instrument-compatible CSV and the complete metadata export.
