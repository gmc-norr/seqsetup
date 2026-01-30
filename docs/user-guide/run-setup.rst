Run Setup
=========

Creating a new sequencing run is done through a guided wizard.

Starting a New Run
------------------

From the dashboard, select **New Run** to start the wizard.

Step 1: Instrument and Flowcell
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Select the sequencing instrument and flowcell type:

- **Instrument platform** -- Choose from supported instruments (NovaSeq X, MiSeq i100,
  NextSeq 1000/2000, etc.)
- **Flowcell type** -- Available options depend on the selected instrument
- **Reagent kit** -- Determines the maximum available cycles

Step 2: Run Cycles
^^^^^^^^^^^^^^^^^^

Configure the number of cycles for each segment:

- **Read 1 cycles** -- Number of sequencing cycles for the first read
- **Read 2 cycles** -- Number of sequencing cycles for the second read
- **Index 1 cycles** -- Number of cycles for the i7 index read
- **Index 2 cycles** -- Number of cycles for the i5 index read

The total cycles (Read1 + Read2 + Index1 + Index2) must not exceed the reagent kit
capacity.

Step 3: Run Details
^^^^^^^^^^^^^^^^^^^

Provide additional run metadata:

- **Run name** -- A descriptive name for the run
- **Run description** -- Optional notes or comments
- **Barcode mismatches** -- Default mismatch tolerance for i7 and i5 (default: 1)

After completing the wizard, you proceed to the sample configuration view where
samples, indexes, and lanes are managed.

Editing Run Settings
--------------------

Run-level settings (instrument, cycles, mismatches) can be modified after creation
through the run configuration panel in the sample view.
