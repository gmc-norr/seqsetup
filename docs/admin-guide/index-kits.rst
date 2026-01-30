Index Kit Management
====================

Administrators can add and manage index adapter kits used for sample demultiplexing.

Index Kit Structure
-------------------

Each index kit defines:

- **Name** -- Kit identifier (e.g., "IDT for Illumina DNA/RNA UD Indexes")
- **Version** -- Kit version string
- **Description** -- Optional description
- **Index type** -- The indexing mode:

  - ``unique_dual`` -- Pre-defined i7+i5 pairs
  - ``combinatorial`` -- Independent i7 and i5 sets
  - ``single`` -- i7 only

- **Index pairs** (for UDI kits) -- Each pair has a name, i7 index, and i5 index
- **i7 indexes** and **i5 indexes** (for combinatorial kits) -- Separate lists

Each index has:

- **Name** -- Index identifier (e.g., "D701")
- **Sequence** -- Nucleotide sequence (e.g., "ATTACTCG")
- **Index type** -- ``i7`` or ``i5``

Adding Index Kits
-----------------

Index kits can be added through:

1. **Admin interface** -- Manual entry through the web UI
2. **CSV import** -- Upload a CSV file with index definitions
3. **GitHub sync** -- Automatic synchronization from a GitHub repository

Default Index Cycles
^^^^^^^^^^^^^^^^^^^^

Kits can specify default effective index cycle counts. When indexes from such a kit
are assigned to a sample, these defaults are used to calculate override cycles
instead of the actual sequence length.

This is useful for kits where the physical index length differs from the intended
read length (e.g., a 10bp index that should only be read for 8 cycles).

Default Override Patterns
^^^^^^^^^^^^^^^^^^^^^^^^^

Kits can also provide default override patterns for:

- **Index reads** -- e.g., ``I8N2`` for an 8bp read with 2 masked cycles
- **Sequencing reads** -- e.g., ``U8Y*`` for 8 UMI cycles followed by sequencing
