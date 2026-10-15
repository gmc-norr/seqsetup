Samples
=======

A sample is one DNA library to sequence. You get samples into a Draft run
three ways: paste a single row, paste a whole block from a spreadsheet, or
import a worklist from a configured LIMS. Each way goes through a preview
screen -- nothing is saved until you confirm what was read. A worklist
import adds only what its preview showed (see "Importing from a worklist
(LIMS)" below).

Adding samples
---------------

Open **+ Add Samples (paste or import)** above the sample table. It starts
open on an empty run and collapsed once the run already has samples.

.. figure:: /_static/screenshots/samples/add-button.png
   :alt: The "+ Add Samples (paste or import)" toggle above the sample table, outlined.

   The Add Samples toggle, outlined.

.. figure:: /_static/screenshots/samples/paste-form.png
   :alt: The paste form: a textarea for pasted rows, a file picker, a Test picker and a Version box for rows without one, lane checkboxes, and a Preview button.

   The paste form, outlined.

Paste rows from a spreadsheet into the box, or choose a ``.csv``, ``.tsv``
or ``.txt`` file instead -- if you choose a file, its contents are read
and whatever is typed in the box is ignored. A single pasted line adds
one sample; several lines add a block. Columns can be tab- or
comma-separated:

- With a header row, columns are matched by name: ``sample_id``,
  ``test_id``, ``test_version``, ``index_i7``, ``index_i5``,
  ``index_pair_name``, ``i7_name``, ``i5_name``. Any column you leave out is
  simply not used. A column named only ``version`` is not read.
- If the paste has more than one column that could be the sample ID, the
  one that names the sample ID wins, wherever it sits: ``sample_id``,
  ``sampleid``, ``sample id`` or ``sample-id`` beats ``sample`` or ``id``,
  which beats ``name``, ``sample_name`` or ``samplename``. So a paste headed
  ``Sample_Name``, ``Sample_ID`` takes the Sample ID from ``Sample_ID`` and
  leaves ``Sample_Name`` unused. Two columns of the same rank: the leftmost
  wins. A paste whose only such column is ``Sample_Name`` still reads it as
  the sample ID. The preview's **Columns used** line names the column it
  actually read, so check it there.
- A test version is ``1`` (the newest synced 1.x.x), ``1.2`` (the newest
  1.2.x) or ``1.2.3`` (exactly that one); **Mark Ready** picks the version
  and saves it (see :doc:`/admin-guide/profiles`). Any other text in the
  ``test_version`` column rejects the **entire** paste, naming its rows.
  A spreadsheet can turn ``1.10`` into ``1.1`` before you copy it: format
  the ``test_version`` column as text, and check the preview's **Version**
  column.
- Without a header row, only the first two columns are read: sample ID,
  then test. A paste without a header row that has anything in a third
  column is refused, naming its rows: SeqSetup does not guess which column
  holds the i7 and which the i5. Add a header row, for example
  ``sample_id``, ``test_id``, ``index_i7``, ``index_i5``. The header row
  must be the first line: a title line above it makes the paste read as
  one without a header row.
- A header row is found wherever a column named ``sample_id`` (or
  ``sampleid``, ``sample id``, ``sample-id``) sits, so ``Well``,
  ``Sample_ID`` is a header, not a sample named Well. ``sample``, ``id``
  and ``name`` mark a header only in the first column. A header row with
  no sample ID column reads its first column as the sample ID, unless that
  column is an index or lane column, which refuses the paste.
- With a header row, a column whose name looks like an index or a lane --
  it has *index* or *barcode* anywhere in it, or a word starting with
  *i7*, *i5* or *lane* -- must be one SeqSetup reads. The i7 is read from
  ``index``, ``index1``, ``i7``, ``index_i7``, ``i7_index`` or
  ``index i7``; the i5 from ``index2``, ``i5``, ``index_i5``,
  ``i5_index`` or ``index i5``; the index names from ``index_pair_name``,
  ``pair_name``, ``index_pair``, ``index pair``, ``index_kit``,
  ``kit_name``, ``kit name`` or ``index kit`` (the pair), ``i7_name``,
  ``i7 name``, ``index_i7_name``, ``index1_name``, ``index_name`` or
  ``index name`` (the i7) and ``i5_name``, ``i5 name``,
  ``index_i5_name`` or ``index2_name`` (the i5). Any other such column --
  ``Index 2``, ``i7_sequence``, ``I7_Index_ID``, ``Lane``, or a second i7
  column -- refuses the **entire** paste, naming the column. Lanes come
  from the **Lanes** picker, never from the paste.
- Data in a column with no header name -- an empty header cell, or a row
  longer than the header -- refuses the **entire** paste, naming its rows
  and the column.
- The **Test for rows without one** picker fills a test only on rows that
  did not already carry one; a row with its own test column keeps it.
  **Version for rows without one** does the same for the version, on rows
  that have a test. A test and its version go together: a row with a
  version but no test (none in the row and none picked) rejects the
  **entire** paste, naming its rows, and so does a row that takes the
  picked test but has no version (none in the row and none in **Version for
  rows without one**).
- **Lanes** picks which lane(s) the new samples start in (lane 1 by
  default). The Lanes column in the table is a display only -- changing a
  sample's lanes afterward is a separate, select-and-apply action covered
  in :doc:`lane-assignment`.

Select **Preview** to see what SeqSetup read, before anything is saved.

.. figure:: /_static/screenshots/samples/paste-preview.png
   :alt: The paste preview: a "Pasted text, N lines" recap next to a count of samples read, will-be-added and skipped, above a per-row table.

   The preview's read counts, outlined -- lines read is not the same
   number as samples read, because blank lines and a header row are not
   samples.

The preview recap line names how it was read (pasted text and its line
count, or the uploaded file's name), then shows one chip per outcome:
samples read, how many will be added, how many are already in the run
(skipped), and how many repeat a sample ID within the paste itself. Each
row below is marked **OK**, **Look** (added, but worth a glance -- e.g. no
matching test, a test with no version, or an index name with no sequence),
**Skipped** (already in
this run; the row already there is kept), or **Repeated** (blocks the
whole paste). A row with a version but no test is marked **Look** with
*"A test version needs a test."*, and blocks the whole paste too. Nothing is written to the run until you select the **Add**
button below the table (it names how many it will add, e.g. **Add 3
samples**); going back to **Edit paste** discards nothing you have not
already added.

A file is read up to 10 MB, and **Edit paste** puts all of it back into the
box, so pressing **Preview** again reads up to 10 MB from the box. The two
are not counted quite the same way -- the box's 10 MB counts what the
browser sends, which includes the line ends it adds -- so a file very close
to 10 MB can still be refused on the way back through the box. Text you
paste or type into the box yourself is read up to 1 MB.

.. warning::
   A pasted or imported row that has *any* content but no sample ID does
   not get silently dropped. SeqSetup rejects the **entire** paste and
   shows *"Row(s) <line numbers>: sample_id is required. Either supply a
   sample_id or remove the row entirely."* -- nothing from that paste is
   added, not even the rows that were fine. Silently skipping one row
   would route that sample's reads into the sequencer's Undetermined
   bucket with no record that anything was lost, so the paste is refused
   as a whole and you fix the source and try again.

.. warning::
   A sample ID made only of zeros (``0``, ``00``, ...) is refused, and the
   whole paste with it (*"Row(s) <line numbers>: A sample ID made only of
   zeros is not a sample ID -- a LIMS may use 0 for an empty well. Give the
   sample its real ID or remove the row entirely."*). A LIMS may use 0 for
   an empty well, so a row for a well with nothing in it looks like a
   sample called 0; stored, it would name a patient sample 0 in the Sample
   Sheet. An ID that merely contains a zero (``0A``, ``100``) is fine.

.. warning::
   A sample ID or test longer than 256 characters is refused, never cut,
   and the whole paste with it (*"Row(s) <line numbers>: the sample_id is
   longer than 256 characters. SeqSetup does not shorten it; shorten it in
   the source."*). A cut ID would be another ID: two IDs alike in their
   first 256 characters would become one.

Two other things block the whole paste before you can add it: the same
sample ID appearing more than once in the pasted text (SeqSetup cannot
tell which row is right), and a paste that would push the run over its
sample cap. A sample ID already in the run is not blocking -- that one row
is skipped and the row already in the run is kept.

Importing from a worklist (LIMS)
----------------------------------

If your administrator has configured and enabled a sample API under
:doc:`/admin-guide/sample-api`, a **Load Worklists** button appears below
the paste form of a **Draft** run. Selecting it lists the worklists the
configured system currently offers. SeqSetup asks the LIMS for a worksheet
by its ID exactly as the list sent it, so a worksheet it cannot fetch for
sure is not in the list:

- its ID is a number with a decimal point (``25.10`` arrives as ``25.1``),
  ``true`` or ``false``, a list or an object;
- its ID has spaces or line breaks around or in it, a sign other than
  ``.``, ``_``, ``-`` and ``~``, or more than 128 characters;
- its entry has the ID under two spellings of one name;
- another worksheet in the list has the same ID.

A warning quotes each one -- the ID SeqSetup read, or the two spellings --
above the list, or under the error when nothing is left to list; at most
ten are shown, then how many more. Ask your administrator to have the LIMS
send each worksheet's ID once, as text, under one name.

Choose one, tick the **Lanes for these samples** they go to (lane 1 is
ticked to start; a one-lane flowcell has no boxes and uses lane 1), and
select **Preview** to see what the import would do. Lanes come from these
boxes, never from the LIMS. The preview names the lanes (*"Worksheet WS1: 2
samples to add to lanes 2, 3"*) and shows the samples the import would
add, each with its Sample ID, test, version, i7 and i5 (``-`` for none), and
the sample IDs already in the run, which the import skips (the first ten,
then how many more). With no lane ticked the preview says *"Pick at least
one lane for the new samples."* If the import would be refused, the preview
shows that refusal instead (*"Importing this worksheet would be refused:
..."*). Picking another worksheet, or changing a lane box, clears the
preview.

Under the samples, the preview's **Import 2 samples** button (it counts
them) adds them to the run; it is off until the import answers. There is
no import without a preview: when every sample of the worksheet is already
in the run, or the import would be refused, the preview has no button. The
import asks the LIMS again and works out again what it would add and
skip, to the lanes the preview named, down to what the preview's table does
not show, such as index names and Override Cycles. If any of that changed since the preview -- in the
LIMS, or through a change to the run's samples or cycles -- nothing is
added and the banner says *"The worksheet or the run changed since the
preview. Nothing was added. Preview again."* Otherwise the result shows in
the banner at the top of
the page (*"Added 2 samples from worklist to lane 1."*). If the import is refused,
its message shows in the banner instead, and the run's samples stay as
they were. An imported
row carries its worksheet ID into the **Worksheet** column -- the picked
worksheet's when the row has none -- and any index sequence it supplies is
assigned immediately, with Override Cycles calculated automatically.

.. warning::
   A worklist import follows the exact same rule as a paste: any LIMS row
   with no sample ID rejects the whole import (*"LIMS row(s) <positions>:
   sample_id is missing or empty."*), not just that one row. A worklist
   that lists the same sample ID more than once is refused as a whole
   too, like a paste (*"Worklist import rejected: these sample IDs appear
   more than once in the worklist: <IDs>. Nothing was added."*). So is a
   row with an i7 or i5 name but no sequence for it (*"Sample 'S1' has an
   i7 name ('D701') but no i7 sequence."*), or with an index pair name and
   no sequence at all: the sample would come in without that index. So is
   a row whose sample ID is made only of zeros, sent as the number ``0`` or
   as text (*"LIMS row(s) <positions>: A sample ID made only of zeros is
   not a sample ID -- a LIMS may use 0 for an empty well. Fix the upstream
   record(s) before retrying."*) -- a LIMS may use 0 for an empty well.
   So is a row whose sample ID, test or worksheet ID is longer than 256
   characters (*"LIMS row(s) <positions>: the sample_id is longer than 256
   characters. SeqSetup does not shorten it. Fix the upstream record(s)
   before retrying."*): it is never cut.
   So is a row with a field that looks like an index or a lane but is not
   one SeqSetup reads, such as ``index``, ``Index 2`` or ``lane``
   (*"LIMS row(s) 1: the field(s) "index" look like an index or a lane,
   but SeqSetup does not read them, so the whole worklist was refused.
   ..."*), and a row with two names for one index, such as ``index1`` and
   ``i7`` (*"LIMS row 1 has more than one name for an i7 sequence ("index1",
   "i7"), so the whole worklist was refused: SeqSetup would read only one
   of them. Send only one."*): the sample would come in without that index,
   or with only one of the two.
   As with a paste, a sample ID already in the run is skipped
   rather than blocking.

Without a sample API configured, this button does not appear at all --
there is nothing to import from, so the paste form is the only way to add
samples.

The sample table
------------------

.. figure:: /_static/screenshots/samples/sample-table.png
   :alt: The sample table listing every sample in the run, with columns for Sample ID, Test ID, Worksheet, Index Kit, Index (i7), Index (i5), Lanes, Override Cycles, MM i7 and MM i5.

   The sample table, outlined.

Every sample in the run appears here: its Sample ID, Test ID (with its
version, e.g. ``WGS 1``; on a Ready run also the exact version saved at
Mark Ready, e.g. ``WGS 1 (1.2.3)``), Worksheet
(from a worklist import, otherwise blank), assigned Index Kit and index
names or sequences, Lanes, Override Cycles, and the two barcode-mismatch
overrides (**MM i7** / **MM i5**). A sample with no index yet shows a drop
target instead of an index cell -- see :doc:`index-assignment`. A row
tinted red and marked with a **!** is flagged by validation -- for any
problem, not only a missing index -- so check :doc:`validation` for what
it found before you rely on that row.

The Sample ID is always shown in full: a long one wraps onto a second line
instead of being cut short, on flagged rows too.

Editing a sample
^^^^^^^^^^^^^^^^^^

**Override Cycles** and the two mismatch counts are the fields you can
change directly in the table; each saves the moment you leave the field.
The screenshot below sets **SAMPLE-A01**'s Override Cycles to
``Y151;I8;I8;Y151``; the field itself is narrow, so the app shows it
truncated (``Y151;I8;I8;Y1…``) even though the full value is what gets
saved.

.. figure:: /_static/screenshots/samples/row-edit.png
   :alt: SAMPLE-A01's Override Cycles field in the sample table, outlined; the table header and surrounding rows are visible for context.

   Editing Override Cycles inline, outlined -- the table around it gives
   context for the edited row.

A mismatch count is 0, 1 or 2 -- the values Illumina's BCL Convert
accepts -- or blank for the default: the BCL Convert profile's, else the
run's. Anything else, such as ``3`` or
a mistyped ``1e``, is refused with a message in the banner, and nothing is
saved. The bulk **Mismatches** row below works the same way.

Each of these three fields saves independently -- changing one does not
touch the others on that row. For a sample that already has an index,
clearing Override Cycles back to blank does not leave it empty: SeqSetup
recalculates it from the sample's index and the run's cycle configuration.
An Override Cycles value you type is checked immediately: anything other
than the letters ``Y``, ``I``, ``U``, ``N``, digits, ``;`` and ``,`` is
rejected and nothing is saved.

You can go on typing while a change saves: the changes of one row are sent
one after another, and a field keeps what you type in it meanwhile.
**Done editing** and **Mark Ready** wait until they are saved, and leaving
the page before then asks first. If the row is redrawn before a change of
yours was sent -- an index dropped on it or cleared, a bulk **Apply** -- a
note under the banner names the change that was not saved; enter it again.
If a note says the row may show an older value, reload the page.

A sample ID is never made only of zeros: adding a sample called ``0`` or
``00`` is refused (*"A sample ID made only of zeros is not a sample ID --
a LIMS may use 0 for an empty well."*) and nothing is saved. A sample ID,
name, project or test longer than 256 characters is refused too, when a
sample is added or changed, and never cut (*"The sample ID is longer than
256 characters. Nothing was saved."*).

Sample ID is set when a sample is added and cannot be changed afterward in
this table; to correct a typo, remove the sample and add it again. Test ID
cannot be changed per row either -- the only way to change it after adding
is the bulk **Test ID** row below.

Changing several samples at once
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Tick more than one sample's checkbox to reveal the bulk-action panel above
the table (the same panel used for :doc:`lane-assignment`). Its
**Mismatches** row applies the i7 and i5 boxes to every ticked sample when
you select **Apply**. A box left blank leaves that value as it is on every
ticked sample, so you can change i7 without touching i5. **Clear** resets
both to the default in one step. With profiles, that is the BCL Convert
profile's ``Data`` default when the profile has the mismatch column, else
its ``Settings`` value, else 1, BCL Convert's default; the run's numbers
count only for a run without profiles. When the profile has no mismatch column, every
sample gets the same number, and a sample's own number cannot reach the
sheet: the validation page warns, and the checks use the sheet's number
(see :doc:`/admin-guide/profiles`). Where the sheet has a ``Lane`` column,
every sample needs its lanes picked. **Apply** with both boxes blank
changes nothing and says so. Its **Test ID**
row sets a test and its version together: pick a test, type its version
(the synced versions are listed beside the box) and select **Apply** to
give both to every ticked sample, or **Clear** to remove both. A test
without a version, or a version without a test, is refused. The panel's
**Lanes** and
**Override Cycles** rows are covered in :doc:`lane-assignment` and
:doc:`override-cycles`.

Removing a sample
--------------------

Each row has a small delete button (``x``) that removes that one sample,
after a confirmation prompt. This also drops any index and lane assignment
that sample had -- there is no undo.

To remove several samples at once, tick their checkboxes and select
**Delete Selected** in the bulk-action panel above the table. It deletes
every ticked sample in one action, after the same kind of confirmation
prompt -- just as irreversible as the per-row button.
