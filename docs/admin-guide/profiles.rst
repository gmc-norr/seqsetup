Profiles
========

SeqSetup uses a profile system to define reusable configurations for test
types and analysis pipelines. Every user can browse profiles from
**Settings > Profiles**; only an administrator can bring new ones in
(below).

Overview
--------

The profile system consists of two types:

**Test Profiles**
   Define a sequencing test, named by its ``TestName``, and link it to one
   or more application profiles. When a sample has a test ID -- a
   ``TestName`` -- and a test version, SeqSetup resolves the test profile
   (the newest synced version that matches; see *Test versions* below) and
   includes the associated application pipelines in the sample sheet.

**Application Profiles**
   Define what the instrument runs: BCL Convert and the on-instrument DRAGEN
   pipelines, each writing its own sample sheet sections. The same folder
   may hold profiles for other tools (``ApplicationType`` other than
   ``Dragen``), which SeqSetup skips (see `Profiles for other tools`_). No
   profile appears in the JSON metadata export.

Test Profiles
-------------

A test profile defines a sequencing test and its associated analysis
pipelines. A sample names its test by the test's ``TestName``; several tests
may share a ``TestType``, which is shown beside the name.

Required Fields
~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 25 15 60

   * - Field
     - Type
     - Description
   * - ``TestType``
     - string
     - The kind of test, such as ``WGS``, shown beside its name; several
       tests may share one
   * - ``TestName``
     - string
     - The test's name, matching the test ID assigned to samples exactly;
       it may not begin or end with a space or hold a hidden character
   * - ``Description``
     - string
     - Description of the test
   * - ``Version``
     - string
     - Three whole numbers joined by dots, each at most 9 digits and without
       a leading zero, e.g. ``1.0.0`` (see `Test versions`_)
   * - ``TestApplicationProfiles``
     - map
     - ``OnInstrument`` and ``DownstreamAnalysis`` (see below)

Application Profile References
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``TestApplicationProfiles`` holds two lists. The same test profile files can
be read by other tools, such as the lab's pipeline automation:

- ``OnInstrument`` (required, at least one entry) -- the application
  profiles the instrument runs, which SeqSetup writes into the Sample Sheet.
  Each entry has exactly these two keys:

  - ``ApplicationProfileName`` -- Name of the application profile, exactly
    as that profile gives it; it may not begin or end with a space or hold
    a hidden character
  - ``ApplicationProfileVersion`` -- Version constraint (PEP 440 format), as
    text: ``"~=1.0"`` matches any 1.x. A bare ``1`` is refused; a quoted
    ``"1"`` matches only a profile whose version is exactly ``1``

- ``DownstreamAnalysis`` (optional) -- the pipelines other tools run after
  the sequencer. SeqSetup does not store or use it. It checks only that it
  is a list of maps whose keys are plain names (letters, digits, ``_``,
  ``-``) and whose values are text (at most 4,096 characters), whole numbers
  or ``true``/``false`` -- such as ``ApplicationProfileName``,
  ``ApplicationProfileVersion`` and ``DependsOn``

A test profile with the old top-level ``ApplicationProfiles`` list is
refused, saying to move the list under ``TestApplicationProfiles`` >
``OnInstrument``.

Version constraints support:

- Exact versions: ``1.0.0``
- Compatible releases: ``~=1.0.0`` (matches 1.0.x)
- Range specifiers: ``>=1.0,<2.0``

Every test's ``OnInstrument`` lists exactly one profile whose
``ApplicationName`` is ``BCLConvert`` -- without one, its samples would not be demultiplexed -- and
at most one profile for any other application, each once. A test that lists
one application twice (two profiles, or the same profile twice, also as
``1.0`` and ``~=1.0``) would write its samples twice. **Mark Ready** refuses
both (the sync cannot: it does not know the referenced profiles'
applications).

Test versions
~~~~~~~~~~~~~

One test can have several versions, each in its own file with the same
``TestName`` and its own ``Version``. Two tests may share a ``TestType`` and
a ``Version`` -- two whole-genome tests, one per downstream pipeline, are each
their own file with their own ``TestName``. Every sample names its test and a
version: ``1`` picks the newest synced 1.x.x, ``1.2`` the newest 1.2.x, and
``1.2.3`` exactly 1.2.3, comparing numbers (1.10.0 is newer than 1.9.0).
**Mark Ready** picks the version, checks and writes the Sample Sheet with
it, and saves it on the Ready run; a version synced later does not change
a Ready run.

The sync refuses a test file whose ``Version`` is not three whole numbers
(``1.0``, ``1``, ``1.0.0rc1``, ``01.0.0`` and ``v1.0.0`` are all refused),
and refuses **every** file of a test and version that is in more than one
file -- a sample could get either -- naming each by its path in the
repository, since two folders of the tree can hold the same file name::

   Test profiles refused: WGS 1.2.0 is in profiles/test_profiles/Wgs_a.yaml and profiles/test_profiles/archive/Wgs_a.yaml. A test and version may be in one file only.

It also refuses **every** file of two tests whose ``TestName`` differs only
in letter case. A ``TestName`` is matched exactly, so ``Wgs`` and ``WGS``
are two different tests with their own application profiles, while every
page and the Sample Sheet show what a reader takes for one test. It names
each file by its path too::

   Test profiles refused: WGS in profiles/test_profiles/WGS.yaml and Wgs in profiles/test_profiles/Wgs.yaml differ only in capitals. Two tests may not differ only in capitals.

Pick one spelling for the test and use it in every file of it.

**Any refused test file stops every test profile change**: one that breaks
these rules, cannot be read as YAML, is empty, or sits in a sub-folder that
cannot be listed. The sync then stores no test profile, keeps the ones
already stored, still syncs the application profiles, and ends with
**error**, naming each file::

   Test profile files were refused, so no test profiles were stored and the stored ones are kept: profiles/test_profiles/Wgs_1.3.yaml:1:1: the file: is empty. Synced 3 application profiles.

Keeping the stored ones also keeps any version you deleted from the
repository on purpose, which a sync without a refusal would have removed.
The message therefore names every stored test and version this sync did
not read::

   ... Kept test profiles this sync did not read: RNA 1.0.0, WGS 1.2.0 -- each is in a refused file or no longer in the repository. Synced 3 application profiles.

Each one is either in a file this sync refused or no longer in the
repository at all -- a refused file cannot be read, so SeqSetup cannot tell
which. Until a sync runs with no refusal, a sample asking for that test can
still resolve to a version you meant to remove.

Without this, a refused newest file would quietly make ``1`` pick an older
version. Fix the file and sync again. Removing a file on purpose is not a
refusal: the next sync stores the files that are left. The **Config Sync**
page shows the last sync, manual or scheduled -- its time, whether it
succeeded and its message -- in red when it failed (see :ref:`config-sync`).

A test file is any file in the test profile folder whose name ends in
``.yaml`` or ``.yml``, in any case (``Wgs_1.3.YAML`` is read too). Other
files there, such as a ``README.md``, are skipped.

**Mark Ready** refuses a sample whose version no synced file matches
(*"No synced WGS version matches 1. Synced WGS versions: 2.0.0."*).

Example Test Profile
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: yaml

   ---
   TestType: WGS
   TestName: WGS
   Description: Germline whole genome sequencing with variant calling
   Version: 1.0.0

   TestApplicationProfiles:
     OnInstrument:
       - ApplicationProfileName: BCLConvertNextera
         ApplicationProfileVersion: "~=1.0.0"

       - ApplicationProfileName: DragenGermlineIdtWgs
         ApplicationProfileVersion: "~=1.0.0"

     DownstreamAnalysis:   # read by other tools, not by SeqSetup
       - ApplicationProfileName: NfCoreRareDisease
         ApplicationProfileVersion: "~=1.0"
         DependsOn: BCLConvertNextera

Application Profiles
---------------------

Application profiles describe what the instrument runs. SeqSetup reads a
profile only when its ``ApplicationType`` is ``Dragen``: each one a sample's
test lists under ``OnInstrument`` writes an ``[AppName_Settings]`` /
``[AppName_Data]`` pair into the Sample Sheet, named after its
``ApplicationName`` (``BCLConvert``, ``DragenGermline``, ...). A profile of
any other type is for other tools that read the same folder, and SeqSetup
skips it (see `Profiles for other tools`_).

Application and test profile data is never included in the JSON metadata
export, regardless of ``ApplicationType``.

One section per application
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A Sample Sheet has one ``[AppName_Settings]`` and one ``[AppName_Data]``
section for each application, however many tests in the run use it. When
two tests use two different profiles for the same application -- the
shipped ``DragenEnrichmentGermline`` and ``DragenEnrichmentSomatic``, for
example -- the profiles share the section if their ``Settings`` and their
columns (after ``Translate``, in order) are the same; each sample's row
then takes its own profile's ``Data`` values (``GermlineOrSomatic`` here).
If they differ, **Mark Ready** refuses and names both profiles: put those
tests in separate runs, or give the profiles the same ``Settings`` and
columns.

What the BCL Convert profile must carry
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``BCLConvert`` profile must have a column for every value a sample
needs, or **Mark Ready** refuses and names the samples and the column:

- ``Index`` for a sample with an i7, ``Index2`` for a sample with an i5;
- ``Lane`` for a sample on some lanes only. With a ``Lane`` column, every
  sample needs its lanes picked: its Lane cell would otherwise be empty,
  and Illumina says a Lane cell holds one lane number;
- ``OverrideCycles`` for a sample whose OverrideCycles is not the run's
  full reads (``Y151;I10;I10;Y151``) -- a shorter index, UMI reads, or a
  typed value;
- with a ``BarcodeMismatchesIndex1`` or ``BarcodeMismatchesIndex2`` column,
  a value in the cell for each sample that has that index: a sample whose
  number was cleared takes the profile's ``Data`` default, and an empty or
  ``na`` default is refused for it. A sample without that index gets
  ``na``, whatever its own number or the default: DRAGEN wants a setting
  that does not apply to a sample blank or ``na``.

Without the mismatch columns every sample gets the profile's ``Settings``
number, or 1, BCL Convert's default. Mark Ready's collision check uses the
number the sheet gives BCL Convert, so it checks what will be
demultiplexed. A sample whose own number differs from it gets a warning on
the validation page (the sheet cannot carry it); add the column to use the
samples' numbers.

A ``Settings`` mismatch number needs that index in every sample: with a
sample that has no i7 (``BarcodeMismatchesIndex1``) or no i5
(``BarcodeMismatchesIndex2``), **Mark Ready** refuses and names the
samples, because DRAGEN takes the setting only then. Use the column
instead.

With a ``Lane`` column, ``NoLaneSplitting`` may not be true -- in the
profile's ``Settings``, or the run's own setting when the profile does not
set it. DRAGEN 4.3 converts a run without lane splitting only when the
sheet has no Lane column, so **Mark Ready** refuses it.
``NoLaneSplitting,false`` next to a Lane column is fine.

Columns taken from the sample
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A column SeqSetup does not fill itself gets the profile's ``Data`` default,
the same text in every row. Two columns are an exception, in **every**
application's section:

- ``Sample_Project`` holds the sample's own project, and
- ``Sample_Name`` holds the sample's own name,

whenever the sample has one; the profile's ``Data`` default is written only
for a sample that has none. BCL Convert writes a sample's FASTQ files into a
directory named after ``Sample_Project`` and names the files after
``Sample_Name``, so one project for the whole run would put every patient's
reads in one directory. The v1 sheet has always written each sample's own
name and project.

Names are compared ignoring case. SeqSetup fills and reads these names
itself, in this spelling only: in every profile's ``Settings``,
``SoftwareVersion``; in every profile's columns, ``Sample_Project`` and
``Sample_Name``; in the ``BCLConvert`` profile, the columns
``Sample_ID``, ``Lane``, ``Index``, ``Index2``, ``OverrideCycles``,
``BarcodeMismatchesIndex1``, ``BarcodeMismatchesIndex2`` and the settings
``BarcodeMismatchesIndex1``, ``BarcodeMismatchesIndex2``,
``NoLaneSplitting``, ``CreateFastqForIndexReads``, ``AdapterBehavior``.

Required Fields (All Profiles)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

These fields are required in every application profile SeqSetup reads:

.. list-table::
   :header-rows: 1
   :widths: 30 15 55

   * - Field
     - Type
     - Description
   * - ``ApplicationProfileName``
     - string
     - Unique profile identifier; it may not begin or end with a space or
       hold a hidden character
   * - ``ApplicationProfileVersion``
     - string
     - Version (PEP 440 format, e.g., ``1.0.0``)
   * - ``ApplicationName``
     - string
     - One of Illumina's applications (e.g., ``BCLConvert``,
       ``DragenGermline``; see `Application Profile Validation`_)
   * - ``ApplicationType``
     - string
     - ``Dragen``; a profile of any other type is skipped (see `Profiles for
       other tools`_)

DRAGEN Profile Fields
~~~~~~~~~~~~~~~~~~~~~~

When ``ApplicationType`` is ``Dragen``, these additional fields are required:

.. list-table::
   :header-rows: 1
   :widths: 20 15 65

   * - Field
     - Type
     - Description
   * - ``Settings``
     - dict
     - Key-value pairs for the ``[AppName_Settings]`` sample sheet section.
       Common keys: ``SoftwareVersion``, ``AppVersion``, ``MapAlignOutFormat``
   * - ``Data``
     - dict
     - Default values for the ``[AppName_Data]`` section columns
   * - ``DataFields``
     - list
     - Column names to include in the ``[AppName_Data]`` section

Optional DRAGEN field:

.. list-table::
   :header-rows: 1
   :widths: 20 15 65

   * - Field
     - Type
     - Description
   * - ``Translate``
     - dict
     - Field name mappings. Maps profile field names to sample sheet column
       names (e.g., ``IndexI7: Index`` maps the i7 index to the ``Index`` column)

Example DRAGEN Profile
~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: yaml

   ---
   ApplicationProfileName: DragenGermlineIdtWgs
   ApplicationProfileVersion: 1.0.0
   ApplicationType: Dragen
   ApplicationName: DragenGermline

   Settings:
     SoftwareVersion: 4.3.6
     AppVersion: 1.2.1
     MapAlignOutFormat: bam
     KeepFastq: true

   Data:
     ReferenceGenomeDir: hg38-alt_masked.cnv.graph.hla.rna-8-1667497097-2
     VariantCallingMode: AllVariantCallers
     QcCoverage1BedFile: na
     QcCoverage2BedFile: na
     QcCoverage3BedFile: na

   DataFields:
     - ReferenceGenomeDir
     - VariantCallingMode
     - QcCoverage1BedFile
     - QcCoverage2BedFile
     - QcCoverage3BedFile
     - Sample_ID

This generates sample sheet sections like:

.. code-block:: text

   [DragenGermline_Settings]
   SoftwareVersion,4.3.6
   AppVersion,1.2.1
   MapAlignOutFormat,bam
   KeepFastq,true

   [DragenGermline_Data]
   ReferenceGenomeDir,VariantCallingMode,...,Sample_ID
   hg38-alt_masked...,AllVariantCallers,...,Sample_001

Profiles for other tools
~~~~~~~~~~~~~~~~~~~~~~~~~

The application profile folder may also hold profiles other tools read, such
as the lab's pipeline automation: a profile whose ``ApplicationType`` is
anything but ``Dragen`` (``nextflow``, ``snakemake``, ...). SeqSetup skips
such a file. It is not stored, and nothing in it is checked beyond being
readable under the rules in `Every Profile File`_ (a decimal version in
quotes, no key given twice), so its ``ApplicationName`` may hold a ``/``
(``nf-core/raredisease``): it never reaches the Sample Sheet.

- The sync's message names each skipped file and its type, for example
  *"Skipped 1 application profile file for other tools (its type is not
  Dragen): profiles/application_profiles/NfCoreRareDisease.yaml
  (nextflow)."* ``pixi run check-settings`` prints a line for each and
  counts them apart from the files checked
- A profile whose ``ApplicationName`` is one of Illumina's applications is
  refused unless its type is ``Dragen`` (see `Application Profile
  Validation`_)
- A folder in which every file is skipped holds no profile for SeqSetup. A
  sync then keeps the stored application profiles, as it does for an empty
  folder, and names the skipped files; ``pixi run check-settings`` reports
  it as an error. A test that lists a skipped profile under
  ``OnInstrument`` gets the Check page's "not found" error for its samples

Validation
----------

Every Profile File
~~~~~~~~~~~~~~~~~~~

- Every key a profile can have is in the tables above; any other key is
  refused, also inside a test's application profile reference. A misspelt
  key such as ``Setings:`` or ``ApplicationProfile:`` was ignored before.
  The keys inside ``Settings`` and ``Data`` are free names (see below)
- Values are read the plain way, as for instrument files: a whole number as
  plain digits, true/false as ``true`` or ``false`` (``yes``, ``no``,
  ``on`` and ``off`` are refused), a decimal number or a date in quotes.
  YAML tags (``!!int``), anchors and aliases (``&a``, ``*a``), merge keys
  (``<<``) and a key given twice are refused. ``012`` in a ``Settings``
  value, written as ``10`` before, is refused: put it in quotes
- Text is written as text: a whole number where text belongs, such as
  ``TestType: 5`` or ``ApplicationProfileVersion: 1``, is refused -- put it
  in quotes. Required text must hold more than spaces. A name, type, test or
  version is at most 256 characters, a ``Description`` and a ``Settings`` or
  ``Data`` value at most 4,096
- Each problem is reported as *file:line:column: place: problem*, for
  example *"profiles/test_profiles/Wgs.yaml:2:11: TestType: must be text:
  put it in quotes"*. The **Config Sync** page lists every problem of the
  last sync, and its message names each refused file with its first
  problem. ``pixi run check-settings`` checks both profile folders before a
  sync (see :doc:`instruments`, "Checking settings before a sync")

Test Profile Validation
~~~~~~~~~~~~~~~~~~~~~~~~

- All required fields must be present and non-empty; a field with nothing
  after it (``Version:``) is empty
- ``Version`` must be three whole numbers joined by dots, each at most 9
  digits and without a leading zero (see `Test versions`_). A PEP 440
  version that is not three whole numbers, such as ``1.0.0rc1``, is refused
- ``TestApplicationProfiles`` must hold ``OnInstrument``, a non-empty
  list, and may hold ``DownstreamAnalysis`` (see `Application Profile
  References`_); the old top-level ``ApplicationProfiles`` is refused
- Each ``OnInstrument`` reference must have a name and a version
  constraint, and the constraint must itself be valid PEP 440
- A version written as a number with a decimal point -- ``Version: 1.10``,
  or ``ApplicationProfileVersion: 1.10`` in a reference -- is refused: YAML
  reads it as the number 1.1. Put it in quotes: ``"1.10"``. For a test
  profile's ``Version`` the quotes alone are not enough -- ``"1.10"`` is
  still refused, since it is not three whole numbers; write ``"1.10.0"``

Application Profile Validation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- All four required fields must be present and non-empty; a field with
  nothing after it is empty
- ``ApplicationProfileVersion`` must be a valid PEP 440 version, in quotes
  when it has a decimal point (``"1.10"``; unquoted, YAML reads it as 1.1,
  and two versions could become one)
- ``ApplicationName`` may only contain letters, digits, ``_`` and ``-`` --
  it becomes a section name in the Sample Sheet (``[<name>_Settings]``),
  written exactly as given
- When ``ApplicationType`` is ``Dragen`` (in any case, spaces around it
  ignored), ``ApplicationName`` must be one of Illumina's applications:
  ``BCLConvert``, ``DragenGermline``, ``DragenSomatic``, ``DragenRna``,
  ``DragenEnrichment`` or ``DragenMethylation``, so a misspelt
  ``DragenGermlin`` is refused. A profile of another type is skipped (see
  `Profiles for other tools`_), unless its ``ApplicationName`` is one of
  these, in any case: then it is refused, since skipping it would leave the
  application out of the Sample Sheet unseen
- ``SoftwareVersion`` in ``Settings`` must be a version written as text:
  letters, digits, ``.``, ``_`` and ``-``. ``SoftwareVersion: 4`` is
  refused (write ``"4"``): **Mark Ready** compares it with the instrument's
  software versions
- ``Settings``, ``Data``, ``DataFields`` and ``Translate`` may not hold a
  hidden character anywhere -- no line break, tab or other invisible
  control character, in a key or a value. They are written into the Sample
  Sheet as cells, and a line break there would start a new line in it.
  A YAML block value (``|`` or ``>``) ends in a line break, so it is
  refused; write the value on one line, or use ``>-`` with no blank line
  inside
- Every name -- a ``Settings`` or ``Data`` key, a ``DataFields`` entry, and
  both sides of ``Translate`` -- must be text made only of letters, digits,
  ``_`` and ``-``. Names start a line or name a column in the Sample Sheet,
  and a name such as ``[BCLConvert_Data]`` would start a section of its
  own. Quote a name that YAML would read as a number or as true/false
  (``"1"``, ``"yes"``, ``"on"``); the same goes for ``ApplicationName``
- No ``Settings`` or ``Data`` value may start with ``[``, even after
  spaces -- written first on a line, it would start a new section. A value
  written as a YAML list is written as ``['a', 'b']``, so it is refused too
- Every ``Settings`` and ``Data`` value must be text, a whole number or
  ``true``/``false``. These are refused, because the Sample Sheet would not
  get what the file says:

  - a number with a decimal point, such as ``SoftwareVersion: 4.10`` --
    YAML reads it as 4.1. Put it in quotes: ``"4.10"``
  - an empty value (a key with nothing after it). Write ``''`` for an empty
    cell
  - a mapping or a list, which would be written as Python text
  - a date such as ``2024-01-01`` (or a date and time), which YAML reads as
    a date, and any other value YAML does not read as text, a number or
    ``true``/``false`` (``!!binary``, ``!!set``). Put a date in quotes:
    ``"2024-01-01"``

- ``BarcodeMismatchesIndex1`` and ``BarcodeMismatchesIndex2`` (BCL Convert
  allows at most 2 mismatches): as a ``Settings`` entry, 0, 1 or 2. As a
  ``Data`` default for a sample's column -- also a column that
  ``Translate`` renames to one of them -- 0, 1, 2, blank (``''``) or ``na``,
  which Illumina uses for a setting that does not apply to a sample.
  ``true`` and ``false`` are refused
- In the profile whose ``ApplicationName`` is ``BCLConvert``, ``Settings``
  may not set ``OverrideCycles``, ``OverrideReads``,
  ``RunInfoIndex2ReverseComplement``, ``Index2ColumnReverseComplement`` or
  ``IndexOrientation`` (in any mix of capitals). They change how BCL Convert reads the i5 or
  the OverrideCycles that SeqSetup writes for the run's instrument (see
  :doc:`instruments`). ``OverrideCycles`` as a data column is fine. A
  profile already stored with one of them stops **Mark Ready** with
  *"Failed to generate exports"*
- The data section must have a ``Sample_ID`` column, or no row would name
  its sample: ``Sample_ID`` must be in ``DataFields`` (or, when
  ``DataFields`` is missing or empty, be a key of ``Data``), as it is or
  renamed to it by ``Translate``
- No column may be written twice, whatever its case -- a ``Translate``
  typo such as ``IndexI5: Index`` would write ``Index`` twice and no i5
- In the ``BCLConvert`` profile, no name may be both in ``Settings`` and a
  data column, whatever its case: BCL Convert allows a setting in one
  place only
- The names SeqSetup fills or reads itself (above) must be spelled exactly:
  ``index`` or ``softwareversion`` is refused
- ``Settings``, ``Data`` and ``Translate`` must be mappings and
  ``DataFields`` a list, when given. A section left empty (``Settings:``
  with nothing under it) means "none"
- If ``ApplicationType`` is ``Dragen``: ``Settings`` and ``Data`` must be
  present and be dicts, and ``DataFields`` must be present and be a list.
  For a DRAGEN profile an empty section is refused

.. note::
   These checks run when a profile file is pulled in by :ref:`Config Sync
   <config-sync>`. The sync also refuses **every** file of a profile name
   and version that is in more than one file -- a test's reference could get
   either -- naming each by its path in the repository. Versions are
   compared as versions, so ``1.0`` and ``1.0.0`` are one version.

   **Any refused application profile file stops every application profile
   change**, as for test profiles (see `Test versions`_): one that fails
   these checks, cannot be read as YAML, is empty, cannot be downloaded, or
   sits in a sub-folder that cannot be listed. The sync then stores no
   application profile, keeps the ones already stored, still syncs the test
   profiles, and ends with **error**, naming each file and its first
   problem (the page lists them all)::

      Application profile files were refused, so no application profiles were stored and the stored ones are kept: profiles/application_profiles/Guard_1.0.1.yaml:5:16: the file: a [ list ] that is not closed. Synced 4 test profiles.

   As for test profiles, the message also names every stored profile and
   version this sync did not read, since a version deleted from the
   repository on purpose is kept too. Without this, a refused newest file
   would quietly replace a stored newer version, and ``~=1.0.0`` would pick
   an older one. A refused file of a version that was never stored is as if
   it were not synced yet: until it is fixed, ``~=1.0.0`` still picks the
   newest stored version, and only the **Config Sync** page shows the
   refusal. Fix the file and sync again.

   An application profile file is any file in the application profile
   folder whose name ends in ``.yaml`` or ``.yml``, in any case. A link to a
   file is refused: GitHub serves the link's target path, not the file it
   points to, so put the file itself in the folder.

Runtime Validation
~~~~~~~~~~~~~~~~~~~

When validating a sequencing run (see :doc:`/user-guide/validation`),
SeqSetup checks:

1. Test profiles exist for all samples with test IDs
2. Referenced application profiles exist with compatible versions
3. DRAGEN applications are available on the selected instrument
4. Software versions match instrument capabilities
5. No version conflicts across samples in the same run
6. Every test lists one ``BCLConvert`` profile and one profile per
   application; profiles that share a section match; the ``BCLConvert``
   profile has the columns its samples need; no column is written twice, no
   setting is in two places, and no name SeqSetup uses is spelled
   otherwise (all above). A profile stored before these checks existed is
   refused here too

If a sync changes a profile while **Mark Ready** is writing the exports,
**Mark Ready** refuses with *"The profiles changed while the exports were
being generated, so the Sample Sheet would not match what was checked. The
run is still a Draft. Mark it Ready again."* The next **Mark Ready** checks
and writes against the new profiles. A sync that both starts and finishes
while **Mark Ready** runs is refused the same way: *"The profiles or
instrument settings changed while the exports were being generated, so the
Sample Sheet might not match what was checked. The run is still a Draft.
Mark it Ready again."* So is a Mark Ready during which an index kit was
uploaded or removed, an instrument switched on or off, or another run's
Mark Ready refused because the profiles changed under it.

.. _config-sync:

Bringing profiles in: Config Sync
-------------------------------------

Application profiles and test profiles reach SeqSetup in exactly one way:
synced in from a GitHub repository, from **Admin > Config Sync**. There is
no form to create or edit a profile directly in the app -- write the YAML
(the local files under ``config/profiles/`` in this repository are examples
of the format to use), push it to your own repository, and sync. SeqSetup
reads the repository without signing in to GitHub, so it must be public.

.. figure:: /_static/screenshots/admin/config-sync.png
   :alt: The GitHub Config Sync form, with a repository URL and branch filled in and the Save Configuration button outlined.

   The **Config Sync** form, with **Save Configuration** outlined.

What one sync does
~~~~~~~~~~~~~~~~~~~~~

A sync (manual or scheduled) always does all of the following:

- **Application profiles** and **test profiles** are fetched recursively
  from their configured repository paths and **completely replace** what is
  already stored -- every application and test profile not present in this
  sync is gone afterwards, whether or not **Enable scheduled sync** is
  checked. If any file of one kind is refused, that kind is not changed at
  all: the stored ones stay, and the sync reports that it failed and names
  each refused file (see `Test versions`_ and `Application Profile
  Validation`_).
- **Instruments** and **index kits** are each synced only if their own
  checkbox (**Also sync instruments** / **Also sync index kits**) is on.
  Instruments are also replaced wholesale, but an instrument's **Enabled**
  state (see :doc:`instruments`) is carried forward across the replace by
  matching on its samplesheet name -- disabling one is not undone by the
  next sync. If any instrument file or folder is refused -- it cannot be
  downloaded or read, a subfolder cannot be listed, it breaks a rule, or
  two files give the same instrument -- **no** instrument settings are
  stored and the stored ones, with their switches, stay; the sync reports
  that it failed and names each refused file, and still syncs the
  profiles and index kits (see :doc:`instruments`). Index kits keep any
  kit uploaded directly through the UI; only previously *synced* kits are
  replaced. A kit file is one ending in ``.yaml`` or ``.yml``, in any
  letter case. An index kit file that breaks a rule, or cannot be read, is
  not stored: the sync reports that it failed, names each such file and
  why -- *"Index kit files were refused, so they were not stored:
  index_kits/lab.yaml (Lab Kit 1.0): ..."* -- and keeps the kit stored
  before from that file until the file is fixed (*"Kept the stored index
  kits Lab Kit 1.0 until the file is fixed."*). Every other kit file is
  synced as usual. A file that cannot be read names no kit, so then every
  stored kit this sync did not read is kept, and named; a sub-folder that
  cannot be listed is reported and handled the same way. A kit file with
  the same name and version as a kit uploaded through the UI is refused
  too, and the uploaded kit is kept.
- While a kit is stored, its name and version mean the same indexes. A
  kit file that changes a stored synced kit's indexes or settings -- a
  sequence, an index name, the order, a well, the defaults, an adapter --
  but keeps its name and version is refused, and the stored kit stays
  (*"index_kits/lab.yaml (Lab Kit 1.0): a kit of this name and version is
  stored with other indexes or settings; give the changed kit a new
  version"*); give the changed kit a new version. A changed description
  or comment alone is stored as usual. Two kit files with the same name
  and version are both refused, each naming the other, and a kit stored
  before under it stays. A kit whose file left the repository is removed
  at that sync, so a later sync stores a file of that name and version
  with whatever indexes it holds, as an upload after a delete is (see
  :doc:`index-kits`). A run page loaded before a kit changed cannot
  assign from it either (see :doc:`/user-guide/index-assignment`).
- As a safety net, a sync that would replace an existing, non-empty
  collection with **zero** fetched items is refused rather than applied --
  a misconfigured path or a network blip cannot wipe out reference data
  that was already there. (When an instrument file was refused, no
  instruments are stored anyway; the index kits a refused kit file keeps
  count as stored.)
- The stored records are replaced one at a time, so the replacing is not
  one step. Before a sync deletes the application profiles, the test
  profiles or the instrument settings, it notes them; it strikes them off
  when the whole sync has finished. While the note names any -- a sync is
  writing right now, or one stopped part-way, say because the database
  could not be reached -- **Mark Ready** refuses every run: *"A
  configuration sync started at ... did not finish writing the test
  profiles, so they may be incomplete. Mark Ready is paused until a sync
  writes them again. If a sync is running now, try again in a minute;
  otherwise an admin can press Sync now on the Config Sync page."* The
  **Config Sync** page shows the pause in red. When the database can be
  reached, the stopped sync's own message ends *"The settings were only
  partly written, so Mark Ready is paused until a sync writes them
  again."* Only a sync that writes those records again lifts the pause: a
  sync that refuses the test files, or runs with **Also sync instruments**
  off, leaves them as they were, and its message says what to do: *"Mark
  Ready stays paused: a sync that stopped earlier left the test profiles
  incomplete, and this sync did not write them again. Fix the refused
  files, then sync again."* (or *"Switch on Also sync instruments, then
  sync again."*). After a sync that stopped part-way, the scheduled sync
  tries again every 5 minutes instead of waiting its interval; after one
  that finished but could not lift the pause, it waits its interval, since
  another sync would not lift it either. An instrument switched off before
  a sync stopped stays off; one an admin switches on or off during the
  pause keeps that switch.
  Synced index kits are not part of the pause: a kit never reaches a
  sheet, because assigning one copies its sequences onto the sample. Runs
  already Ready or Archived keep their exports. One sync runs at a time: a
  **Sync now** pressed during a scheduled sync waits for it to end.

.. warning::
   Syncing instruments changes what a **new** run can be set up on -- see
   the warning on :doc:`instruments`. Syncing profiles or index kits does
   not touch any existing run's own stored data, but it can change how that
   run validates the *next* time it is checked (a profile version bump or
   removal can turn a passing run into a failing one, or the reverse). A
   run's already pre-generated exports (Ready or Archived) are not
   regenerated by a sync -- only re-opening its validation, or moving it
   through Ready again, sees the new definitions.

Manual vs. scheduled
~~~~~~~~~~~~~~~~~~~~~~~

**Run Manual Sync** runs a sync immediately, regardless of the **Enable
scheduled sync** checkbox -- that checkbox only controls the background
scheduler described next.

SeqSetup also syncs on a schedule, in a background thread that starts with
the application and checks once a minute whether a sync is due. A scheduled
sync runs only when **all** of these are true: **Enable scheduled sync** is
checked, a **Repository URL** is configured, and at least **Sync Interval
(minutes)** (1-1440, default 60) has passed since the last sync. With no
repository configured -- the default -- nothing ever runs on its own.

Both the interactive and the scheduled sync record an entry on the
:doc:`audit-trail` page.

The page's status panel shows the **Last sync**: when it ran, whether it
succeeded (``success`` or ``error``) and its message, in red when it
failed -- for a scheduled sync too, which has no other place to say so. A
manual sync's result is shown above the panel, in red when it failed.

A sync records which repository and branch it read. When the saved
**Repository URL** or **Branch** is not the one the last sync read -- the
moment you save a new one, before you sync it -- the panel says *"The
repository and branch saved here have not been synced yet"* and names the
repository and branch the time, status and message below it belong to. It
says it for a new branch of a repository already synced too: the
repository has been read, that branch has not. Nothing has been fetched
from what is saved now until a sync runs, manually or on the schedule.
Writing the same repository another way is not a change: a trailing slash
or a ``.git`` suffix is compared as the sync reads it, so re-saving the
URL that way raises nothing. A status stored by an older SeqSetup carries
no repository, and the panel then says nothing about it rather than
claiming the repository is unsynced.

Who can do this
-------------------

Viewing profiles, from **Settings > Profiles**, needs no special role.
Configuring or triggering Config Sync, from **Admin > Config Sync**,
requires the **Admin** role.
