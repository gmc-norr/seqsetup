Samples
=======

A sample is one DNA library to sequence. You get samples into a Draft run
three ways: paste a single row, paste a whole block from a spreadsheet, or
import a worklist from a configured LIMS. All three go through the same
paste-and-preview screen -- nothing is saved until you confirm what was
read.

Adding samples
---------------

Open **+ Add Samples (paste or import)** above the sample table. It starts
open on an empty run and collapsed once the run already has samples.

.. figure:: /_static/screenshots/samples/add-button.png
   :alt: The "+ Add Samples (paste or import)" toggle above the sample table, outlined.

   The Add Samples toggle, outlined.

.. figure:: /_static/screenshots/samples/paste-form.png
   :alt: The paste form: a textarea for pasted rows, a file picker, a Test picker for rows without one, lane checkboxes, and a Preview button.

   The paste form, outlined.

Paste rows from a spreadsheet into the box, or choose a ``.csv``, ``.tsv``
or ``.txt`` file instead -- if you choose a file, its contents are read
and whatever is typed in the box is ignored. A single pasted line adds
one sample; several lines add a block. Columns can be tab- or
comma-separated:

- With a header row, columns are matched by name: ``sample_id``,
  ``test_id``, ``index_i7``, ``index_i5``, ``index_pair_name``, ``i7_name``,
  ``i5_name``. Any column you leave out is simply not used.
- Without a header row, the first four columns are read in that fixed
  order: sample ID, test, i7 index, i5 index.
- The **Test for rows without one** picker fills a test only on rows that
  did not already carry one; a row with its own test column keeps it.
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
matching test, or an index name with no sequence), **Skipped** (already in
this run; the row already there is kept), or **Repeated** (blocks the
whole paste). Nothing is written to the run until you select the **Add**
button below the table (it names how many it will add, e.g. **Add 3
samples**); going back to **Edit paste** discards nothing you have not
already added.

.. warning::
   A pasted or imported row that has *any* content but no sample ID does
   not get silently dropped. SeqSetup rejects the **entire** paste and
   shows *"Row(s) <line numbers>: sample_id is required. Either supply a
   sample_id or remove the row entirely."* -- nothing from that paste is
   added, not even the rows that were fine. Silently skipping one row
   would route that sample's reads into the sequencer's Undetermined
   bucket with no record that anything was lost, so the paste is refused
   as a whole and you fix the source and try again.

Two other things block the whole paste before you can add it: the same
sample ID appearing more than once in the pasted text (SeqSetup cannot
tell which row is right), and a paste that would push the run over its
sample cap. A sample ID already in the run is not blocking -- that one row
is skipped and the row already in the run is kept.

Importing from a worklist (LIMS)
----------------------------------

If your administrator has configured and enabled a sample API under
:doc:`/admin-guide/sample-api`, a **Load Worklists** button appears below
the paste form. Selecting it lists the worklists the configured system
currently offers. Choosing one and selecting **Preview** shows its
samples first, if you want to check them -- this step is optional.
Selecting **Import Samples** adds them to the run right away, without a
separate confirm step. An imported row also carries its worksheet ID into
the **Worksheet** column, and any index sequence it supplies is assigned
immediately, with Override Cycles calculated automatically.

.. warning::
   A worklist import follows the exact same rule as a paste: any LIMS row
   with no sample ID rejects the whole import (*"LIMS row(s) <positions>:
   sample_id is missing or empty."*), not just that one row. As with a
   paste, a sample ID already in the run is skipped rather than blocking.

Without a sample API configured, this button does not appear at all --
there is nothing to import from, so the paste form is the only way to add
samples.

The sample table
------------------

.. figure:: /_static/screenshots/samples/sample-table.png
   :alt: The sample table listing every sample in the run, with columns for Sample ID, Test ID, Worksheet, Index Kit, Index (i7), Index (i5), Lanes, Override Cycles, MM i7 and MM i5.

   The sample table, outlined.

Every sample in the run appears here: its Sample ID, Test ID, Worksheet
(from a worklist import, otherwise blank), assigned Index Kit and index
names or sequences, Lanes, Override Cycles, and the two barcode-mismatch
overrides (**MM i7** / **MM i5**). A sample with no index yet shows a drop
target instead of an index cell -- see :doc:`index-assignment`.

Editing a sample
^^^^^^^^^^^^^^^^^^

**Override Cycles** and the two mismatch counts are the fields you can
change directly in the table; each saves the moment you leave the field.

.. figure:: /_static/screenshots/samples/row-edit.png
   :alt: A sample row's Override Cycles field, edited to a specific cycle pattern, outlined.

   Editing Override Cycles inline, outlined.

Each of these three fields saves independently -- changing one does not
touch the others on that row. For a sample that already has an index,
clearing Override Cycles back to blank does not leave it empty: SeqSetup
recalculates it from the sample's index and the run's cycle configuration.
An Override Cycles value you type is checked immediately: anything other
than the letters ``Y``, ``I``, ``U``, ``N``, digits, ``;`` and ``,`` is
rejected and nothing is saved.

Sample ID is set when a sample is added and cannot be changed afterward in
this table; to correct a typo, remove the sample and add it again.

Removing a sample
--------------------

Each row has a small delete button (``x``) that removes that one sample,
after a confirmation prompt. This also drops any index and lane assignment
that sample had -- there is no undo.
