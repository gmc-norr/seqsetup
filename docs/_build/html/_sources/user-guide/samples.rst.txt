Samples
=======

Samples represent individual DNA libraries to be sequenced in a run.

Adding Samples
--------------

Clipboard Paste
^^^^^^^^^^^^^^^

The primary method for adding samples is pasting from a spreadsheet or text source:

1. Copy tab-separated data containing sample IDs and optional test IDs
2. Click **Add Samples** or paste directly into the sample table
3. SeqSetup parses the data and creates sample entries

The expected format is tab-separated columns with at minimum a sample identifier.
Additional columns (test ID, project, description) are mapped based on position.

API Import
^^^^^^^^^^

If a sample API is configured, samples can be imported by providing identifiers
that are resolved against the external system.

Sample Table
------------

The sample table displays all samples in the run with the following columns:

- **Sample ID** -- User-provided sample identifier
- **Sample Name** -- Optional display name
- **Test** -- Associated test identifier
- **Project** -- Project assignment
- **Index (i7)** -- Assigned i7 index name and sequence
- **Index (i5)** -- Assigned i5 index name and sequence
- **Lanes** -- Lane assignments
- **Override Cycles** -- Per-sample override cycle string

Editing Samples
^^^^^^^^^^^^^^^

Individual sample fields can be edited directly in the table. Click on a field to
modify its value.

Removing Samples
^^^^^^^^^^^^^^^^

Select one or more samples and use the **Remove** action to delete them from the run.
This also removes any associated index and lane assignments.
