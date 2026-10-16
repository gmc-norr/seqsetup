Export
======

A Draft run cannot be downloaded. Before any file can leave SeqSetup, the
run must be promoted to **Ready** -- which requires the **Check** panel
(see :doc:`validation`) to show zero errors -- and every export is
generated at that moment, once, from the run as it stood when you
selected **Mark Ready**.

Marking a run Ready
---------------------

The run's status bar, at the top of its page, always shows a **Mark Ready**
button while the run is a Draft -- clicking it is what actually checks the
run; there is nothing to unlock first. A hint next to the button reads
"Check must pass first" until the Check panel's error count reaches zero.

If the run still has errors, **Mark Ready** refuses the transition and
lists every one of them right under the status bar -- the same
messages the Check panel and the Issues tab already show:

.. figure:: /_static/screenshots/ready/mark-ready-refused.png
   :alt: The "Cannot mark ready" message, under the status bar, listing every blocking validation error.

   The Mark Ready refusal, under the status bar, outlined.

The validation report saved with the exports is made from a second check,
run while they are written. If a sync changes something in between so
that this check finds an error, **Mark Ready** refuses too: *"The checks
found an error while the exports were being generated, so the run was not
marked Ready. The run is still a Draft. Read the Check panel, then mark it
Ready again."* Nothing is saved.

**Mark Ready** also waits while a configuration sync has not finished
writing the profiles or instrument settings, because they may then be
incomplete: *"A configuration sync started at ... did not finish writing
the test profiles, so they may be incomplete. Mark Ready is paused until a
sync writes them again. If a sync is running now, try again in a minute;
otherwise an admin can press Sync now on the Config Sync page."* (see
:ref:`config-sync`). And if the settings change while **Mark Ready** runs
-- a sync, an index kit uploaded or removed, an instrument switched on or
off -- it refuses with *"The profiles or instrument settings changed while
the exports were being generated, so the Sample Sheet might not match what
was checked. The run is still a Draft. Mark it Ready again."* Nothing is
saved in either case.

A run with one very large file is refused too, for that file's size. Each
of the five files SeqSetup writes for a Ready run -- both Sample Sheets,
the JSON, and the check report as JSON and as a PDF -- is stored on its
own, and SeqSetup stores at most 16 MB in one file. A run's files are
therefore no longer measured together, only one at a time. The check
report's per-lane pictures and index tables grow with the number of
**different** samples in each lane, and at 200 different samples per lane
on an eight-lane flowcell -- with the longest sample names SeqSetup
accepts -- its JSON is about 15 MB, close to that limit. Over it, **Mark
Ready** refuses and says which file it was and the size it measured;
nothing is saved and the run stays a Draft. This is a limit of how
SeqSetup stores a file, not a problem with the run: tell your SeqSetup
administrator.

A run record itself is held to the same 16 MB, for what the run says
rather than for its files: its settings, and every sample with its names,
test, worksheet and description. Thousands of samples with long
descriptions can reach it. **Mark Ready** refuses that too, with the size
it measured, and again nothing is saved.

Once every error is fixed, selecting **Mark Ready** again succeeds: the
status badge changes to **Ready**, the run is locked against further
edits, and its exports are generated:

.. figure:: /_static/screenshots/ready/mark-ready.png
   :alt: The run status bar's status badge, outlined, reading "Ready", next to Return to Draft and Archive buttons.

   The status badge just after Mark Ready succeeds, outlined.

Generating the exports includes drawing the validation report's charts.
For a large run this takes a while -- about two minutes for 96 samples on
all 8 lanes of a NovaSeq X 10B -- and the button reads **Checking...**
until it is done. Everyone else can keep working in SeqSetup meanwhile.

If the run has no errors but a lane has a color balance error (see
:doc:`validation`), **Mark Ready** does not go ahead yet. It asks, under
the status bar, and names the lanes:

.. figure:: /_static/screenshots/ready/mark-ready-color-balance.png
   :alt: The "Color balance errors" question under the status bar, naming lane 1, with a "Mark Ready anyway" button.

   The color balance question, outlined.

Select **Mark Ready anyway** to promote the run; your answer, and the
lanes it covered, are recorded in the audit trail. If the run changes
before you answer, the question comes back for the new state.

A message Mark Ready shows stays under the status bar until the run's
status changes; an error from a save that was refused stays in the red
banner at the top of the page, even after the run becomes Ready -- read
it before you rely on the value you typed.

.. note::
   Validation runs again, in real time, at the moment you select **Mark
   Ready** -- not the last time the Check panel happened to refresh. A
   change made anywhere on the page always gets a fresh check before the
   run is allowed to lock.

Downloading exports
----------------------

Once a run is **Ready** or **Archived**, its Export panel offers a
download for each of (a Draft has nothing to download, so its page shows
no Export panel):

- **Download Sample Sheet v2** -- the CSV consumed by BCLConvert / DRAGEN.
- **Download Sample Sheet v1** -- the legacy IEM format, only for
  instruments that still use it (MiSeq and NovaSeq 6000), and only when it
  can carry the run's settings (see `Sample Sheet v1`_ below).
- **Download JSON** -- the complete run and sample metadata.
- **Download Validation Report (JSON)** and **Download Validation Report
  (PDF)** -- the same validation result the Check panel and the validation
  page showed at the moment the run was marked Ready.

.. figure:: /_static/screenshots/export/panel-ready.png
   :alt: The Export panel on a Ready run, outlined; Download Sample Sheet v2 stands out in teal while the other three buttons render grey.

   The Export panel on a Ready run, outlined. The grey buttons are styled
   differently from **Download Sample Sheet v2**, but they are not
   disabled -- all four are enabled here.

Each download is named after the run. A Sample Sheet's name also says its
version and the software that reads it, so the two never share a name:
``RUN_v2_BCLConvert.csv`` and ``RUN_v1_bcl2fastq.csv``. A run named in an
alphabet other than the Latin one -- or with accents -- still downloads:
the file keeps the run name's own letters, after the same tidying every
download name gets, with a plain-ASCII name as the fallback for older
browsers (and the export's own name, such as
``SampleSheet_v2_BCLConvert.csv``, when nothing ASCII is left of the
run's).

The two Sample Sheet buttons additionally require every sample in the run
to have an index assigned -- if any sample does not, they stay disabled
even though the run is Ready; the JSON and validation downloads have no
such requirement.

.. _api-exports:

API Exports
-------------

A program with an API token (see :doc:`/api-reference/index`) reads the
same stored files. To see exactly what it gets, select **API Exports** in
the sidebar, or **See this run in API Exports** in a Ready or Archived
run's Export panel.

The first page lists the runs the API lists -- Ready, or Archived, never a
Draft -- newest change first, as ``GET /api/runs`` gives them (the API hands
them out a page at a time; this page shows them all):

.. figure:: /_static/screenshots/export/served-runs.png
   :alt: The API Exports page: Ready and Archived tabs above a table of Ready runs, with a See files link outlined.

   The runs the API serves, with **See files** outlined.

**See files** opens one run: each address the API answers for it, and
under it the file exactly as stored when the run was marked Ready, with
a **Download** button for it -- the same file the Export panel gives.
Nothing is made anew here. Where nothing is stored, the page shows the
API's answer instead, such as *"404: No v1 sheet for this run: ..."*, and
no download. The PDF shows its size. A Draft's page says the API does not
serve it.

Above each Sample Sheet, **Target instrument and software** says what the
sheet was written for:

- **Instrument** -- the run's instrument.
- **Software** -- BCL Convert, with the version the v2 sheet states in
  its ``[BCLConvert_Settings]``, for the v2 sheet; bcl2fastq for the v1
  sheet.
- **i5 workflow** -- the run's i5 workflow (see :doc:`run-setup`).
- **i5 column** -- each sample's i5 as stored, or its reverse complement
  (see the note on the i5 under `Sample Sheet v2 format`_); *None* when no
  sample has an i5.

When the sheet relies on BCL Convert acting on the
``IsReverseComplement="Y"`` mark that ``RunInfo.xml`` puts on the i5 read
-- with the shipped instruments, a NovaSeq X, NextSeq 1000/2000 or MiSeq
i100 read-first run -- the box says so: the sheet is right only for a BCL
Convert that acts on the mark. The v2 sheet's box also says that its
index collisions were checked as DRAGEN's built-in BCL conversion checks
them -- standalone ``bcl-convert`` 3.10.5 or later is stricter (see
:doc:`validation`). Mark Ready saves the target with the
sheets; it is not worked out again later, so a change to an instrument's
settings afterwards does not change it. If a sync changes the instrument's
i5 settings while **Mark Ready** is writing the exports, **Mark Ready**
refuses with *"The instrument's i5 settings changed while the exports were
being generated, so the Sample Sheets could disagree with each other. The
run is still a Draft. Mark it Ready again."* **Back to Draft** clears it with the stored files. A run
marked Ready before SeqSetup saved targets says *"Not recorded"*. The API
gives the same facts as ``target`` in its run list (see
:doc:`/api-reference/runs`).

.. figure:: /_static/screenshots/export/served-run.png
   :alt: One run's Sample Sheet v2 on the API Exports page: its Download button and address, and the Target instrument and software box outlined above the sheet's text.

   One run's Sample Sheet v2 on the API Exports page, its target outlined.

Anyone signed in can open these pages, as anyone signed in can download
a Ready run's files. Opening a Ready or Archived run's page is recorded in
the audit trail as ``export.viewed``.

Sample Sheet v2 format
-------------------------

The exported file follows the Illumina Sample Sheet v2 CSV format:

``[Header]``
   Run metadata including file format version, run name, run description,
   and instrument platform.

``[Reads]``
   Cycle counts for Read 1, Read 2, Index 1, and Index 2.

One ``[AppName_Settings]`` / ``[AppName_Data]`` pair per application
   For every sample's **Test ID** and test version, SeqSetup resolves the
   matching test profile and the application profiles it references, and writes one
   ``Settings``/``Data`` section pair for each application, named after it
   -- for example ``[BCLConvert_Settings]`` / ``[BCLConvert_Data]``, or
   ``[DragenGermline_Settings]`` / ``[DragenGermline_Data]``. Every sample
   is in ``[BCLConvert_Data]``, once (once per lane with a ``Lane``
   column). Two tests that use different profiles for one application
   share its section, each row with its own profile's values, when the
   profiles' ``Settings`` and columns match; otherwise **Mark Ready**
   refuses. Which sections appear, and which columns each ``Data`` row has,
   is defined by the application profiles the run's samples resolve to
   (see :doc:`/admin-guide/profiles`) -- there is no fixed section list and
   no fixed column set. A ``BCLConvert`` profile's ``Data`` section commonly
   carries index sequences, lane assignment, override cycles, and barcode
   mismatch overrides; it has no project column unless a profile explicitly
   adds one.

``[Cloud_Settings]`` and ``[Cloud_Data]``
   Written on every export, unconditionally, for compatibility with
   Illumina's Instrument Management Service. ``[Cloud_Data]`` lists each
   sample's ID, project name, and a library name computed from the sample
   ID and index sequences.

A UUID is embedded in the sample sheet to link it to the JSON metadata
export of the same run.

**Mark Ready** refuses a run whose sheet would leave a sample out of
``[BCLConvert_Data]``, write one twice, or not carry a value the checks
used: a sample without a Test ID or without a test version, a test,
version or profile that is not stored, a
test without a ``BCLConvert`` profile, or a ``BCLConvert`` profile without
a column a sample needs (see :doc:`/admin-guide/profiles`). The sheet
writer checks the same again before it writes, so a profile changed or
removed in between -- by a sync, for example -- stops **Mark Ready**
instead of reaching the sheet.

The collision check uses the barcode mismatch numbers the sheet gives BCL
Convert: each sample's number in the ``BarcodeMismatchesIndex1`` /
``BarcodeMismatchesIndex2`` columns, else the profile's ``Settings``
number, else 1, BCL Convert's default. A sample without an i7 or an i5
gets ``na`` in that mismatch column: DRAGEN wants a setting that does not
apply to a sample blank or ``na``. ``NoLaneSplitting`` true next to a
``Lane`` column stops **Mark Ready**: DRAGEN 4.3 converts without lane
splitting only when the sheet has no Lane column.

.. note::
   How the i5 and the Index 2 part of Override Cycles are written depends
   on the run's instrument and i5 workflow (see
   :doc:`/admin-guide/instruments`). SeqSetup stores the Index 2 part in
   reading order, the index first (``I8N2``). Where the instrument reads
   the i5 reversed and its ``RunInfo.xml`` marks that read -- NovaSeq X,
   NextSeq 1000/2000, MiSeq i100 read-first -- BCL Convert reverses the
   Index 2 part back, so it is written ``N2I8``, and the i5 column stays
   forward. Where the instrument reads the i5 reversed and does not mark
   it -- NextSeq 500/550, MiniSeq with standard kits, NovaSeq 6000 with
   v1.5 reagents, HiSeq 4000, HiSeq X -- the i5 column is written as its
   reverse complement, the Index 2 part stays ``I8N2``, and the header has
   no ``IndexOrientation,Forward`` line. Everywhere else nothing is
   reversed.

Sample Sheet v1
------------------

A v1 sheet has one pair of barcode mismatch numbers for the whole run, no
OverrideCycles, and a ``Lane`` column only when some sample has lanes. When
it cannot carry the settings the checks used, no v1 sheet is made: when a
sample was checked with mismatch numbers other than the run's, has an
OverrideCycles other than the one its index lengths give (a typed value,
UMI reads, a kit's index cycles), or has no lanes picked while other
samples do. **Mark Ready** still works and makes the v2 sheet. The
validation page warns before Mark Ready (*"No v1 sheet will be made for
this run: ..."*); after it, the run page's Export panel, the v1 download and
the API say *"No v1 sheet for this run: ..."* with the samples and reasons,
as they were when the run went Ready.

An index shorter than its read (``I8N2``) stays in the v1 sheet at its own
length. bcl2fastq, which reads v1 sheets, uses such a shortened sequence;
BCL Convert needs OverrideCycles for it, which only the v2 sheet has, so
give BCL Convert the v2 sheet (Illumina's comparison of bcl2fastq and BCL
Convert). The v1 sheet is for bcl2fastq and the MiSeq.

JSON metadata
----------------

The JSON export serializes the run and its samples as structured data,
including some information the Sample Sheet v2 format has no place for:

- Sample identifiers, names, and index sequences
- Override cycles, lane assignments, description, and free-form metadata
  (per sample)
- Per sample, the i5 and the Override Cycles **as the v2 sheet writes
  them** (``samplesheet_index2``, ``samplesheet_override_cycles``) next to
  the same two values **as typed** (``index2``, ``override_cycles``). On
  some instruments the sheet writes the i5 reverse-complemented, and on
  others the Index 2 part of the Override Cycles reversed (``I8N2`` becomes
  ``N2I8``); these keys say which characters the sequencer was actually
  given. They come from the same code that writes the sheet
- Instrument configuration (platform, flowcell, run cycles) and the
  run-level BCL Convert settings (barcode mismatch defaults, adapter
  behavior, lane splitting, global override cycles)
- Analysis configurations
- The run description and the shared UUID

It does not carry everything about the run. Missing from the export: a
sample's **Test ID**, its index kit name, and any per-sample
barcode-mismatch override -- only the run-level default is serialized, not
what an individual sample overrides it to. Also missing, at the run level:
who created or last updated the run, and when -- there is no user tracking
and no timestamps in the JSON export.

Returning to Draft
---------------------

A Ready run's status bar offers **Return to Draft** instead of **Mark
Ready**:

.. figure:: /_static/screenshots/ready/back-to-draft.png
   :alt: The run status bar's status badge, outlined, reading "Draft" again, next to "You are editing this run", Done editing and Mark Ready, after returning from Ready.

   The status badge just after returning a Ready run to Draft, outlined.

Whoever returns the run to Draft is its editor at once; others see it
read-only until you press **Done editing** (see :doc:`run-setup`).

.. warning::
   Returning to Draft drops every export the run pointed at -- the Sample
   Sheet, the JSON metadata, and both validation reports. They are not
   written again until the run is marked Ready again, so downloads are
   unavailable for the run in the meantime. This is deliberate: it stops a
   later re-promotion from ever handing out files written before the edits
   that sent the run back to Draft. Marking it Ready again writes a fresh
   set of files; the old ones are kept in the database, where nothing
   points at them.

Archiving a run
------------------

A Ready run's status bar also offers **Archive**:

.. figure:: /_static/screenshots/archive/archive-button.png
   :alt: The Archive button in the run status bar of a Ready run.

   The Archive button, outlined.

Archiving keeps the run's stored exports -- unlike Return to
Draft, nothing is discarded, and every download from the previous section
keeps working exactly as it did while the run was Ready. The Export panel
itself looks no different on an Archived run -- the same buttons, all
still enabled, as in the Ready screenshot above. What changes is the
status bar and the transitions on offer: instead of **Return to Draft**
and **Archive**, an Archived run's status bar shows a single **Reset to
Draft** button.

.. warning::
   Archived is a dead end. The status bar still shows a button in its
   place, but selecting it is refused outright, with an error banner and
   toast reporting the rejection -- nothing about the run changes.
   Double-check a run before archiving it: once archived, the only way to
   sequence it again is to build a new run.

Archiving does not touch the run's :doc:`Change History <change-history>`.
An administrator can still delete an Archived run (see :doc:`dashboard`); a
copy of it, with its history, is then kept on
:doc:`/admin-guide/deleted-runs`.
