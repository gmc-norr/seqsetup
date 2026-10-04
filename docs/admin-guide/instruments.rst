Instrument Configuration
========================

SeqSetup ships a built-in list of Illumina instruments and their flowcells in
``config/instruments.yaml`` -- read once at startup, and requiring a restart
(or the ``INSTRUMENTS_CONFIG`` environment variable, to point at a different
file) to change. This shipped list cannot be edited or individually disabled
from the UI.

SeqSetup checks this file at every start, the same way a config sync checks
synced instruments. If an instrument in it has a mistake -- say
``i5_read_orientation: forwards`` in one of its ``i5_workflows`` -- or the
file cannot be read, SeqSetup does not start, and the error names the file,
each instrument and each problem: *"instruments.yaml has errors, so
SeqSetup will not start: MiSeq: i5_workflows: i5_read_orientation must be
forward or reverse-complement (got: 'forwards')"*. Fix the file and start
again.

**Admin > Instruments** lets an admin manage a *different*, additional set:
instrument definitions synced in from GitHub (see :doc:`profiles`). Until at
least one instrument has been synced, the page shows a note pointing at that
fallback file instead of a management table -- there is nothing to enable or
disable yet.

.. figure:: /_static/screenshots/admin/instruments.png
   :alt: The Synced Instruments table, with one instrument's Enabled checkbox outlined.

   The synced-instrument table, with one instrument's **Enabled** checkbox
   outlined.

.. warning::
   Syncing instrument definitions is **not additive**. As soon as any
   instrument has ever been synced, the New Run instrument dropdown offers
   *only* the synced set -- ``config/instruments.yaml`` stops being
   consulted for that dropdown entirely, even for instrument names the sync
   never mentioned. If your synced repository defines only a subset of the
   instruments your lab actually runs (say, just NovaSeq X Series), the rest
   disappear from **New Run** the moment that sync completes, until they are
   added to the synced set too. While any instrument is synced, one that
   is not among them has no settings at all -- SeqSetup does not fall back
   to ``config/instruments.yaml`` for it. A run **already** on it shows the
   instrument as **(not available)**, its Check panel says *"<instrument>
   is not among the synced instruments. Pick another instrument in Run
   Setup."*, and **Mark Ready** refuses it until another instrument is
   picked or the instrument is synced. Ready and Archived runs keep their
   Sample Sheets.

Enabling and disabling
--------------------------

Once at least one instrument is synced, each row has its own **Enabled**
checkbox, and there are **Enable All** / **Disable All** buttons above the
table. Toggling any of these takes effect immediately, with no
confirmation, and the resulting state is saved right away.

Switching an instrument off does three things:

- **New Run** no longer offers it, and choosing it from a page opened
  earlier is refused.
- A **Draft** run already on it shows an error in the Check panel --
  *"NovaSeq X Series is disabled by an administrator. Pick another
  instrument in Run Setup before marking the run ready."* -- and **Mark
  Ready** refuses it until another instrument is picked. This includes a
  new run, which starts on NovaSeq X Series, and a run made from a
  template, which copies the template's instrument. **Mark Ready** reads
  the switch again just before it saves the run as Ready.
- **Ready** and **Archived** runs are not touched: they keep their Sample
  Sheets.

.. note::
   The checkbox's state survives a later sync: SeqSetup matches the old
   and new instrument sets by their samplesheet name and carries the
   disabled flag forward, rather than resetting every instrument back to
   enabled on each sync.

The i5 (Index 2)
-------------------

Each instrument gives two facts about the i5, in ``config/instruments.yaml``
and in each synced instrument file:

.. code-block:: yaml

   # How the instrument reads the i5, per workflow. The first one is the standard one.
   i5_workflows:
     - name: Index-first
       i5_read_orientation: forward
     - name: Read-first
       i5_read_orientation: reverse-complement
   # In a run whose i5 read is reversed, does RunInfo.xml mark it IsReverseComplement="Y"?
   runinfo_marks_i5_reversed: true

``i5_workflows``
   Each way the instrument runs that reads the i5 differently, with a
   ``name`` and an ``i5_read_orientation``: ``forward`` (the i5 is read as
   the index kit lists it) or ``reverse-complement``. Required, at least
   one. A name is 1-64 characters -- letters, digits, spaces, ``.``, ``_``
   and ``-``, starting with a letter or digit -- and no two of an
   instrument's names may be the same, ignoring case. The first workflow
   is the **standard** one: a new run, and a run moved to this instrument,
   gets it. Where an instrument lists more than one, the run setup page
   offers the choice (see :doc:`/user-guide/run-setup`).

``runinfo_marks_i5_reversed``
   ``true`` or ``false`` (not text). Required. ``true`` means: in a run
   whose i5 read is reversed, this instrument's ``RunInfo.xml`` marks that
   read ``IsReverseComplement="Y"``, and the BCL Convert that reads the
   Sample Sheet acts on it. Set ``false`` if the instrument's control
   software does not write the tag, or your BCL Convert does not act on
   it.

From these SeqSetup decides, for each run, from the run's workflow:

- **The i5 as the instrument reads it** -- the workflow's
  ``i5_read_orientation``. The dark-start and colour-balance checks read
  the i5 this way, and so does the v1 Sample Sheet (bcl2fastq).
- **The v2 Index2 column** -- written as the i5's reverse complement when
  the workflow reads the i5 reversed and ``runinfo_marks_i5_reversed`` is
  ``false``; otherwise as the kit lists it. The header line
  ``IndexOrientation,Forward`` is written only when the column is forward.
- **The Index 2 part of OverrideCycles** -- SeqSetup stores it in reading
  order, the index first (``I8N2``). It is written reversed (``N2I8``)
  when the workflow reads the i5 reversed and ``runinfo_marks_i5_reversed``
  is ``true``, because BCL Convert reverses it back, as Illumina's NovaSeq
  X Settings page shows; otherwise as stored.

For an 8-base i5 on a 10-cycle Index 2 read, with the shipped instruments:

.. list-table::
   :header-rows: 1
   :widths: 50 20 30

   * - Run
     - Index2 column
     - Index 2 part of OverrideCycles
   * - NovaSeq X Series, NextSeq 1000/2000, MiSeq i100 Series read-first
     - forward
     - ``N2I8``
   * - MiSeq i100 Series index-first
     - forward
     - ``I8N2``
   * - NextSeq 500/550, MiniSeq standard kits, NovaSeq 6000 v1.5 reagents,
       HiSeq 4000, HiSeq X
     - reverse complement
     - ``I8N2``
   * - MiniSeq Rapid kits, NovaSeq 6000 v1.0 reagents
     - forward
     - ``I8N2``
   * - MiSeq, HiSeq 2000/2500, GAIIx
     - forward
     - ``I8N2``

The shipped instruments, in ``config/instruments.yaml`` and the example
files in ``config/instruments/``:

.. list-table::
   :header-rows: 1
   :widths: 30 45 25

   * - Instrument
     - ``i5_workflows`` (first = standard)
     - ``runinfo_marks_i5_reversed``
   * - MiSeq i100 Series
     - Index-first: forward; Read-first: reverse-complement
     - true
   * - MiniSeq
     - Standard kits: reverse-complement; Rapid kits: forward
     - false
   * - NovaSeq 6000
     - v1.5 reagents: reverse-complement; v1.0 reagents: forward
     - false
   * - NextSeq 500/550, HiSeq 4000, HiSeq X
     - Standard: reverse-complement
     - false
   * - NextSeq 1000/2000, NovaSeq X Series
     - Standard: reverse-complement
     - true
   * - MiSeq, HiSeq 2000/2500, GAIIx
     - Standard: forward
     - false

They come from Illumina's `Indexed Sequencing Overview for Paired-End Flow
Cells
<https://knowledge.illumina.com/library-preparation/general/library-preparation-general-reference_material-list/000002099>`_
(and, for the HiSeqs on paired-end flow cells, the Indexed Sequencing
Overview Guide, document 15057455), `Planning a Manual Mode Run on MiSeq
i100 Series
<https://knowledge.illumina.com/instrumentation/miseq-i100-series/instrumentation-miseq-i100-series-reference_material-list/000009499>`_
(index-first is that instrument's default), `DRAGEN v4.5 BCL conversion
<https://help.dragen.illumina.com/dragen-v4.5/product-guides/dragen-v4.5/bcl-conversion>`_
and the `i5 Index Orientation Table
<https://help.connected.illumina.com/run-set-up/overview/index-orientation-guide/i5-index-orientation-table>`_.
GAIIx keeps the forward direction it always had; no Illumina source was
found for it.

This rests on three things:

- The Sample Sheet is read by BCL Convert, standalone or as onboard
  DRAGEN, in a version that acts on ``IsReverseComplement`` (Illumina does
  not say from which version; the v3.7.5 guide does not mention it), and
  the instrument's control software writes the tag. If not, set
  ``runinfo_marks_i5_reversed: false``.
- The index kit files store each i5 as its forward-strand sequence, as the
  kit's documentation lists it.
- A BCL Convert application profile cannot change it: its ``Settings`` may
  not set ``OverrideCycles``, ``OverrideReads``,
  ``RunInfoIndex2ReverseComplement`` or ``Index2ColumnReverseComplement``
  (see :doc:`profiles`).

.. important::
   **Check it before first clinical use.** For each instrument and
   workflow your lab uses, demultiplex a real run that has an i5 shorter
   than its index read, using the Sample Sheet SeqSetup writes, with
   ``CreateFastqForIndexReads,1`` (**Create FASTQ for index reads**). Look
   at the share of Undetermined reads in ``Demultiplex_Stats.csv`` and at
   ``Top_Unknown_Barcodes.csv``, and check in the I2 FASTQ that the index
   sits where the mask says. Or compare with a Sample Sheet that Illumina's
   own run setup wrote for such a run.

Upgrading from an older SeqSetup
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The keys ``i5_read_orientation`` (at the top level of an instrument) and
``samplesheet_v2_i5_orientation`` were replaced by ``i5_workflows`` and
``runinfo_marks_i5_reversed``. Nothing is worked out from the old keys --
the shipped files carried a wrong read direction for three instruments --
so a file that still has them is refused, with *"Replaced by i5_workflows
and runinfo_marks_i5_reversed; see Instruments in the admin guide"*:

- a lab's own ``config/instruments.yaml`` stops SeqSetup from starting
  until it is updated (the shipped file is already updated);
- synced instrument files must all be updated and synced, with **Also
  sync instruments** on. Until then the stored records cannot be used: run pages show the message described
  under *When the synced instruments cannot be used* below, and **Mark
  Ready** is refused;
- an instrument your lab does not sync is not available while you sync
  others.

SBS chemistry and names
--------------------------

**SBS chemistry**
   ``2-color`` or ``4-color``. Two-color chemistry has a "dark" base with no
   fluorescent signal, which is why SeqSetup runs a color-balance check for
   those instruments (see :doc:`/user-guide/validation`) and does not for
   four-color ones.

**Sample sheet name and onboard application names**
   The sample sheet name (e.g. ``NovaSeqXSeries``) is written on the Sample
   Sheet's ``InstrumentPlatform`` line, and each onboard application name
   (e.g. ``BCLConvert``) decides which application profiles the instrument
   can run. Both may only contain letters, digits, ``_`` and ``-``; an
   onboard application's ``software_version`` may also contain ``.``. A
   synced instrument file that breaks this is refused, and then the sync
   stores no instrument settings at all (see *When a sync refuses an
   instrument file* below). As a second check, SeqSetup will not write a
   Sample Sheet whose ``InstrumentPlatform`` name, or whose application
   profile's ``ApplicationName`` (see :doc:`profiles`), breaks the rule, so
   a run cannot be marked Ready with one.

.. warning::
   A reagent kit's maximum total cycle count (Read 1 + Index 1 + Index 2 +
   Read 2) is an **optional** field on an instrument definition
   (``reagent_kit_max_cycles``), and the shipped
   ``config/instruments.yaml`` sets it for **no instrument at all** -- so
   the "too many cycles for this kit" check never fires unless an admin
   syncs an instrument definition that supplies it. If your lab relies on
   that check, it only ever exists after a GitHub sync brings in a
   definition that sets it.

When a sync refuses an instrument file
-----------------------------------------

A synced instrument file or folder that does not give valid instruments,
for any reason, is refused: it cannot be downloaded or read as YAML, a
subfolder cannot be listed, it breaks a rule on this page, or two files
give the same instrument name or samplesheet name. One bad entry refuses
its whole file. When anything is refused:

- the sync stores **no** instrument settings, and the stored ones, with
  their **Enabled** switches, stay as they were;
- application profiles, test profiles and index kits are synced as usual;
- the sync reports that it failed, on the Config Sync page and in its
  stored status, naming each refused file and its problem, and says what
  it did sync.

When the synced instruments cannot be used
--------------------------------------------

While any instrument is synced, only the synced ones count. If a stored
record cannot be used -- one in the old format, or a damaged one -- or the
database cannot be read, SeqSetup stops and says so. It never falls back
to ``config/instruments.yaml``.

- Run pages (Draft, Ready and Archived), the setup page, the live exports
  and **Mark Ready** show *"The synced instrument settings cannot be used:
  <instrument>: <problem>. Update the instrument files and run a config
  sync with Also sync instruments on (Admin > Config Sync)."* -- or, for a
  database problem, *"The synced
  instrument settings could not be read from the database. Try again, or
  ask an administrator to check the database."* The details of a database
  problem go to :doc:`Admin > Logs <logs>` only.
- **Mark Ready** saves nothing, and the refusal is in the audit trail
  (``run.status.denied``, reason ``synced_instruments_unusable``).
- Exports made when a run was marked Ready, and the API, keep working.
- **Admin > Config Sync** keeps working. A sync with **Also sync
  instruments** on and every instrument file good replaces the stored
  records, keeping each instrument's **Enabled** switch, and the next page
  load works again. With that box off, a sync stores no instrument records.
- On **Admin > Instruments**, a switch you change is saved, and the page
  then shows the message instead of the list. When the database cannot be
  read, the page shows the database sentence.

Who can do this
-------------------

Viewing and changing which synced instruments are enabled requires the
**Admin** role. The shipped ``config/instruments.yaml`` file itself is
edited on the server's filesystem, outside the application.
