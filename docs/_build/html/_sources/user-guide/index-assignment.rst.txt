Index Assignment
================

Sequencing indexes (barcodes) are assigned to samples to enable demultiplexing after
the run.

Index Kits
----------

Indexes are organized into kits. Each kit contains a set of index pairs (i7 + i5)
designed to work together.

Kit Modes
^^^^^^^^^

**Unique Dual Indexing (UDI)**
   Pre-defined pairs of i7 and i5 indexes. Each pair is assigned as a unit. This is
   the most common mode for modern instruments.

**Combinatorial**
   i7 and i5 indexes are selected independently and combined freely. Any i7 can be
   paired with any i5 from the kit.

**Single Index**
   Only i7 indexes are used. No i5 index is assigned.

Assigning Indexes
-----------------

Drag and Drop
^^^^^^^^^^^^^

1. Select an index kit from the kit selector in the index panel
2. Available index pairs are displayed in the panel
3. Select one or more index pairs by clicking (use Shift/Ctrl for multi-select)
4. Select one or more target samples in the sample table
5. Drag the indexes onto the selected samples, or click **Assign**

Indexes are assigned in order: the first selected index pair goes to the first
selected sample, the second pair to the second sample, and so on.

Bulk Assignment
^^^^^^^^^^^^^^^

When multiple index pairs and multiple samples are selected, indexes are assigned
sequentially in the order they appear.

Clearing Indexes
^^^^^^^^^^^^^^^^

To remove index assignments:

- Select the sample(s) and click **Clear Indexes**
- This removes the index pair, kit association, and resets override cycle patterns

Kit Defaults
^^^^^^^^^^^^

When indexes from a kit are assigned, the kit may provide default settings that
are applied to the sample:

- **Effective index cycles** -- The number of cycles the kit expects for its indexes
- **Index override patterns** -- Pre-defined override patterns (e.g., ``I8N2``)
- **Read override patterns** -- Pre-defined read patterns (e.g., ``N2Y*``, ``U8Y*``)

These defaults are populated automatically but can be overridden per sample.
