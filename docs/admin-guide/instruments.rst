Instrument Configuration
========================

SeqSetup ships a built-in list of Illumina instruments and their flowcells in
``config/instruments.yaml`` -- read once at startup, so changing it needs a
restart. This shipped list cannot be edited or individually disabled from the
UI.

To use your own file instead, set the ``INSTRUMENTS_CONFIG`` environment
variable to its path. When that variable is set to anything, it decides which
file is read: the shipped file is not read at all, and not used as a
fallback. If it names a path that is not a file, SeqSetup does not start, and
the error names the path: *"INSTRUMENTS_CONFIG names /srv/seqsetup/ours.yaml,
which is not a file, so SeqSetup will not start. Point it at the instruments
file, or leave it unset to use the file SeqSetup ships."* -- reading the
shipped file in its place would use i5 facts nobody chose, and those decide
the i5 direction in every Sample Sheet. With the variable unset (or set to
nothing), the shipped file is read, as before. Either way the log line
*"Reading instruments from <path>"* at the start says which file it was.

SeqSetup checks the file it reads at every start, with the same rules a
config sync checks synced instruments with (see *The keys of an instrument
file* below). If the file has a mistake -- say ``i5_read_orientation:
forwards`` in one of an instrument's ``i5_workflows``, or a key it does not
know -- or the file cannot be read, SeqSetup does not start, and the error
names the file and, for each problem, its line and column, the place and
the problem: *"instruments.yaml has errors, so SeqSetup will not start:
instruments.yaml:456:30: instruments > MiSeq > i5_workflows > item 1 >
i5_read_orientation: must be one of: 'forward' or 'reverse-complement'"*.
Fix the file and start again. ``pixi run check-settings`` checks a file
before you start (see *Checking settings before a sync* below).

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

**Mark Ready** saves, with each run's Sample Sheets, what they were written
for, this rule included (see :ref:`api-exports`); a later change here does
not change a Ready run's sheets or that record. A sync that changes an
instrument's i5 settings while **Mark Ready** is writing a run's exports
makes it refuse; the run stays a Draft.

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
  ``RunInfoIndex2ReverseComplement``, ``Index2ColumnReverseComplement`` or
  ``IndexOrientation`` (see :doc:`profiles`).

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

The keys of an instrument file
------------------------------------

Every key an instrument file can have is listed here, and **any other key
is refused**: a misspelt key such as ``lane:`` for ``lanes`` or
``colour_balance_enabled`` for ``color_balance_enabled`` once fell back to a
default without a word (one lane; no colour balance check). A fact that
changes a Sample Sheet or a check must be written out; only labels may be
left out, and ``samplesheet_versions``, which then means ``[2]``.

A synced instrument file holds one instrument at the top level, or several
under ``instruments:`` -- a map of each instrument's name to its keys, with
nothing beside it. An instrument listed under a name may leave out ``name``;
if it gives one, it must be the name it is listed under. The local file
(``config/instruments.yaml``) has three top-level keys, all required:
``instruments`` (as above), ``default_cycles`` and ``index_cycle_options``.

Values are read as written: a whole number is plain digits (``012``,
``0x10``, ``1_000`` and ``1:20`` are refused, because YAML would read them as
other numbers); a yes/no value is ``true`` or ``false`` (``yes``, ``no``,
``on`` and ``off`` are refused); a version is text, so ``1.10`` must be in
quotes (YAML reads it as the number 1.1); a date must be in quotes. YAML
tags (``!!int`` and the like), anchors (``&name``) and merge keys (``<<``)
are refused, and so is a key given twice in one map.

**An instrument**

``name``
   The instrument's name, as the pages show it. Required in a file holding
   one instrument.
``samplesheet_name``
   Required. Written on the Sample Sheet's ``InstrumentPlatform`` line, so
   only letters, digits, ``_`` and ``-``.
``version``
   Required in a synced file (the version of the file's content); a local
   entry has none.
``chemistry_type``
   Required: ``2-color`` or ``4-color``.
``sbs_chemistry``, ``error_tendencies``
   Labels, shown on the instruments page. May be left out.
``has_dragen_onboard``
   Required: ``true`` or ``false``.
``i5_workflows``, ``runinfo_marks_i5_reversed``
   Required: the two i5 facts (see *The i5 (Index 2)* above). Each workflow
   has exactly a ``name`` and an ``i5_read_orientation`` (``forward`` or
   ``reverse-complement``); no two names may differ only in capitals.
``color_balance_enabled``
   Required: ``true`` or ``false``.
``dye_channels``, ``base_colors``, ``channel1_name``, ``channel1_bases``, ``channel2_name``, ``channel2_bases``, ``dark_base``
   The colour balance facts: all required on a 2-color instrument with
   ``color_balance_enabled: true``, checked when given on one with it off,
   and refused on a 4-color instrument, where nothing reads them.
   ``base_colors`` names each of ``A``, ``C``, ``G`` and ``T`` once; the
   bases are ``A``, ``C``, ``G`` or ``T``. A dye channel other than Blue,
   Green, Red or Yellow is a warning, not a refusal.
``samplesheet_versions``
   The Sample Sheet versions the instrument reads: ``[2]``, ``[1, 2]`` or
   ``[1]``. Left out, it means ``[2]``.
``onboard_applications``
   Required: a map of each application the instrument runs to its
   ``software_version``. The names are Illumina's (``BCLConvert``,
   ``DragenGermline``, ``DragenSomatic``, ``DragenRna``,
   ``DragenEnrichment``, ``DragenMethylation``); the version may hold
   letters, digits, ``.``, ``_`` and ``-``.
``flowcells``
   Required, at least one: a map of each flow cell's name to its
   ``lanes`` (required, 1 to 8), ``reagent_kits`` (required: the reagent
   kits' cycles, 1 to 2000 each, none twice; ``[]`` means the flow cell
   sets no kit limit), ``reads`` and ``description`` (labels, may be left
   out).
``reagent_kit_max_cycles``
   Optional: a map of a reagent kit's cycles to the most cycles it allows
   (all reads together, at least the kit's own cycles). A kit no flow cell
   offers is a warning.

**The local file's cycle sections**

``default_cycles``
   A map of a reagent kit's cycles (1 to 2000) to the cycles a new run with
   that kit starts with: ``read1`` (1 to 600), ``read2``, ``index1`` and
   ``index2`` (0 to 600 each; ``read2: 0`` is a single-end run).
``index_cycle_options``
   The index cycle counts the run page offers: at least one, each 1 to 600,
   none twice.

Checking settings before a sync
----------------------------------

``pixi run check-settings <folder>`` checks a settings folder with the rules
the sync uses, with no database, no network and no running SeqSetup -- for
example on every change to your settings repository. It reads what the sync
reads: every ``.yaml`` and ``.yml`` file in the folder's ``instruments/`` and
the folders below it, but not a link (``--instruments <path>`` names another
folder inside the settings folder). An ``instruments/`` folder that is not
there, or holds no instrument file, is an error. ``--local-instruments
<file>`` also checks a local instruments file. It prints one problem per line, *"instruments/miseq.yaml:30:5:
flowcells > v2 Standard > lane: is not a key this file can have (check
the spelling)"* for a ``lane:`` written under the flow cell's ``lanes:``, marks warnings, and ends with a failure when there is an error.
``pixi run check-settings --schema <dir>`` writes a JSON Schema for each kind
of instrument file, which an editor can use to point out mistakes as you
type; the command, not the schema, is the full check.

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
  stored status, naming each refused file and its first problem, and says
  what it did sync. The page lists every problem with its file, line and place,
  warnings too, and the sync's audit row carries them; a very long list is
  cut there and on the page, which say how many are not shown
  (``pixi run check-settings`` lists them, up to 1,000 per file).

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
