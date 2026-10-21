SeqSetup Documentation
======================

.. note::

   **Use at your own risk.** SeqSetup is provided as is, without warranty of any
   kind. Its authors and the organisations they work for are not responsible for
   any harm, loss or damage that comes from using it. See the LICENSE file in the
   repository.

SeqSetup is a web-based application for configuring and managing sample information
for Illumina DNA sequencing workflows. It generates Illumina Sample Sheet v2 files
and associated metadata for instruments including NovaSeq X, MiSeq i100, and others.

Key features:

- Guided wizard for sequencing run setup
- Drag-and-drop index assignment with collision detection
- Automatic override cycles calculation
- Support for UMI and custom read patterns
- SampleSheet v2 and JSON metadata export
- Multi-lane flowcell support
- DRAGEN onboard analysis configuration
- LDAP/AD authentication with role-based access
- Application and test profile management

.. toctree::
   :maxdepth: 2
   :caption: Contents

   getting-started/index
   user-guide/index
   admin-guide/index
   api-reference/index
   architecture/index
   development/index
