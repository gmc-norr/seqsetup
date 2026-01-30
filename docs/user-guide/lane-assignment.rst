Lane Assignment
===============

For multi-lane flowcells, samples can be assigned to specific lanes.

Default Behavior
----------------

By default, samples are not assigned to any specific lane. This means the sample
will be sequenced on all lanes of the flowcell (default BCLConvert behavior).

Assigning Lanes
---------------

1. Select one or more samples in the sample table
2. Click **Set Lanes**
3. A selection menu displays all available lanes for the current flowcell type
4. Select the desired lanes
5. Click **Apply** to assign the selected lanes to all selected samples

The number of available lanes depends on the flowcell type. For example, a NovaSeq X
10B flowcell has 8 lanes.

Lane Display
------------

In the sample table, lanes are displayed as a comma-separated list (e.g., ``1,2,3``)
or ``All`` if no specific lanes are assigned.

In the exported sample sheet, each sample-lane combination becomes a separate row in
the ``[BCLConvert_Data]`` section. A sample assigned to lanes 1 and 2 produces two
rows.

Clearing Lanes
--------------

To remove lane assignments, select the sample(s), click **Set Lanes**, deselect all
lanes, and apply. The sample returns to the default "all lanes" behavior.
