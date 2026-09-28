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

Once every error is fixed, selecting **Mark Ready** again succeeds: the
status badge changes to **Ready**, the run is locked against further
edits, and its exports are generated:

.. figure:: /_static/screenshots/ready/mark-ready.png
   :alt: The run status bar's status badge, outlined, reading "Ready", next to Return to Draft and Archive buttons.

   The status badge just after Mark Ready succeeds, outlined.

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
download for each of:

- **Download Sample Sheet v2** -- the CSV consumed by BCLConvert / DRAGEN.
- **Download Sample Sheet v1** -- the legacy IEM format, only for
  instruments that still use it (MiSeq and NovaSeq 6000).
- **Download JSON** -- the complete run and sample metadata.
- **Download Validation Report (JSON)** and **Download Validation Report
  (PDF)** -- the same validation result the Check panel and the validation
  page showed at the moment the run was marked Ready.

.. figure:: /_static/screenshots/export/panel-ready.png
   :alt: The Export panel on a Ready run, outlined; Download Sample Sheet v2 stands out in teal while the other three buttons render grey.

   The Export panel on a Ready run, outlined. The grey buttons are styled
   differently from **Download Sample Sheet v2**, but they are not
   disabled -- all four are enabled here.

The two Sample Sheet buttons additionally require every sample in the run
to have an index assigned -- if any sample does not, they stay disabled
even though the run is Ready; the JSON and validation downloads have no
such requirement. On a Draft run the panel shows a single line, "Downloads
open when the run is Ready," instead of any buttons.

Sample Sheet v2 format
-------------------------

The exported file follows the Illumina Sample Sheet v2 CSV format:

``[Header]``
   Run metadata including file format version, run name, run description,
   and instrument platform.

``[Reads]``
   Cycle counts for Read 1, Read 2, Index 1, and Index 2.

One ``[AppName_Settings]`` / ``[AppName_Data]`` pair per application profile
   For every sample with a **Test ID**, SeqSetup resolves the matching test
   profile and, for each application profile it references, writes one
   ``Settings``/``Data`` section pair named after that profile's
   application name -- for example ``[BCLConvert_Settings]`` /
   ``[BCLConvert_Data]``, or ``[DragenGermline_Settings]`` /
   ``[DragenGermline_Data]``. Which sections appear, and which columns each
   ``Data`` row has, is defined entirely by the application profiles the
   run's samples resolve to (see :doc:`/admin-guide/profiles`) -- there is
   no fixed section list and no fixed column set. A ``BCLConvert`` profile's
   ``Data`` section commonly carries index sequences, lane assignment,
   override cycles, and barcode mismatch overrides; it has no project
   column unless a profile explicitly adds one.

``[Cloud_Settings]`` and ``[Cloud_Data]``
   Written on every export, unconditionally, for compatibility with
   Illumina's Instrument Management Service. ``[Cloud_Data]`` lists each
   sample's ID, project name, and a library name computed from the sample
   ID and index sequences.

A UUID is embedded in the sample sheet to link it to the JSON metadata
export of the same run.

.. warning::
   If none of a run's samples have a **Test ID** that resolves to a test
   profile referencing at least one application profile, SeqSetup writes
   none of the application sections described above -- the exported Sample
   Sheet v2 contains only ``[Header]``, ``[Reads]``, ``[Cloud_Settings]``,
   and ``[Cloud_Data]``. There are no index sequences, no OverrideCycles,
   no Lane column, and no demultiplexing data of any kind, and **Mark
   Ready does not catch this**: an unresolved application profile is not
   one of the checks the Check panel runs. Confirm every sample's Test ID
   resolves to the test and application profiles you expect before relying
   on the exported Sample Sheet.

.. note::
   Whether Index 2's override-cycles segment is written forward
   (``I8N2``) or with its N-mask leading (``N2I8``) depends on how the
   *sample sheet* expects the i5 sequence to be written for that
   instrument, not which way the instrument physically reads it. NovaSeq
   6000, HiSeq 4000, HiSeq X, NextSeq 500/550 and MiniSeq all expect a
   reverse-complemented i5 in the sample sheet and get the flipped form;
   NovaSeq X, MiSeq i100, NextSeq 1000/2000, MiSeq, HiSeq 2000/2500 and
   GAIIx expect it forward and keep ``I8N2``. NovaSeq X in particular
   physically *reads* i5 as its reverse complement, but that is not what
   ends up in its sample sheet -- the two are tracked separately, and it
   is the sample-sheet orientation that decides what gets written here.

JSON metadata
----------------

The JSON export serializes the run and its samples as structured data,
including some information the Sample Sheet v2 format has no place for:

- Sample identifiers, names, and index sequences
- Override cycles, lane assignments, description, and free-form metadata
  (per sample)
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
   :alt: The run status bar's status badge, outlined, reading "Draft" again, with the Mark Ready button restored, after returning from Ready.

   The status badge just after returning a Ready run to Draft, outlined.

.. warning::
   Returning to Draft discards every export that was generated -- the
   Sample Sheet, the JSON metadata, and both validation reports. They are
   not recomputed until the run is marked Ready again, so downloads are
   unavailable for the run in the meantime. This is deliberate: it stops a
   later re-promotion from ever handing out files generated before the
   edits that sent the run back to Draft.

Archiving a run
------------------

A Ready run's status bar also offers **Archive**:

.. figure:: /_static/screenshots/archive/archive-button.png
   :alt: The Archive button in the run status bar of a Ready run.

   The Archive button, outlined.

Archiving keeps the run's already-generated exports -- unlike Return to
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
