Index Kit Management
=====================

An index kit is the library of i7/i5 barcodes that samples are assigned in a
run. Every user can browse and use the index kits already in SeqSetup, from
**Settings > Index Kits**; importing a new one requires the **Admin** role.

.. figure:: /_static/screenshots/admin/index-kits-list.png
   :alt: The Index Kits list page, showing one kit's card below the header, with the "+ Import Index Kit" link outlined in that header.

   The **Index Kits** list. **+ Import Index Kit** is shown only to admins.

Importing a kit
-------------------

Select **+ Import Index Kit** and fill in the form:

- **Index kit file** -- a YAML, CSV, or TSV file, up to 1 MB.
- **Index mode** -- **Unique Dual** (i7+i5 pairs), **Combinatorial**
  (independent i7 and i5 lists), or **Single** (i7 only).
- **Kit name** / **Kit version** / **Description** -- optional; when left
  blank, SeqSetup takes them from the file itself where the format provides
  them.
- Adapter sequences and default override-cycle patterns -- optional; see the
  page's own **Override cycles help** for the notation. Adapter sequences are
  stored with the kit and are never written to a Sample Sheet -- see
  `Viewing a kit`_ below.

.. figure:: /_static/screenshots/admin/index-kit-upload.png
   :alt: The Import Index Kit form with a CSV file selected and the kit name and version filled in, and the Upload Index Kit button outlined.

   The import form, filled in, with **Upload Index Kit** outlined.

Select **Upload Index Kit** to import it.

What is checked on import
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Before a kit is saved, SeqSetup checks, in order:

1. **Size** -- the upload is capped at 1 MB.
2. **Content type** -- the file's first bytes are checked against common
   binary formats (PNG, JPEG, PDF, ZIP/xlsx/docx, gzip, executables, and
   more), and against a stray NUL byte or invalid UTF-8 in the first 8 KB.
   A file that looks binary is rejected outright: index kits must be plain
   text.
3. **Parsing** -- a file that breaks one of the rules below is rejected with
   every problem it has, each naming the line, the column and the key
   (*"line 7: ownr: is not a key this file can have (check the spelling)"*).
   Before, anything the format's own checks did not catch became one
   sentence -- "Failed to parse file. Please check the format and try
   again." -- with no line and no key. In
   **Unique Dual** mode an Illumina YAML or TSV file, which lists its i7 and
   i5 indexes apart, is paired by name: an i7 only with the i5 of the same
   name. A file whose names do not pair up is refused and the indexes left
   without a partner are named (*"The file's i7 and i5 indexes do not pair
   up by name, so nothing was saved. ... No i5 has the same name as these
   i7: 'D701', 'D702'. No i7 has the same name as these i5: 'D501',
   'D502'. If any i7 may go with any i5, upload the kit as Combinatorial.
   ..."*); a file with no i5 at all is told to upload as **Single** if the
   kit is i7 only. SeqSetup once guessed pairs from names that look alike
   -- ``D701`` with ``D501`` -- and so saved a combinatorial kit as fixed
   pairs, offering a sample an i5 its tube does not have. It cannot tell a
   combinatorial kit whose i7 and i5 happen to share names (``1`` to ``8``
   on both sides) from one of fixed pairs, so pick the mode the kit really
   is. In any mode, a name given twice in one list of a YAML or TSV file is
   refused, naming it: only the second entry was kept, so the first index
   vanished and its name carried the other's sequence. Spaces around a
   name are dropped, so ``D701`` and ``D701 `` are one name given twice. A
   key given twice anywhere in a YAML file is refused the same way. An
   Illumina YAML
   file whose index names YAML does not read as text -- an unquoted ``012``
   is the number 10, ``yes`` is true -- is refused too; quote such names.
   So is one whose sequence is empty or not text. A
   kit
   name or version made only of dots (``.``, ``..``) is refused at this step
   too, whether it came from the form or from the file: the name and the
   version are the kit's place in the URL of its own detail, download and
   delete links, so such a kit would be listed and usable but could never be
   deleted.

   Nine more faults refuse the whole file, with nothing saved.

   * **i5 data with Single picked.** A Single kit saves the i7 indexes
     only, so a file's ``index2`` column, ``i5Index2`` or ``Index2`` list,
     ``IndexNumber 2`` lines, ``[i5]`` section or ``i5_indexes`` list went
     nowhere -- or into a kit whose panel never shows them. The file is
     refused naming where the i5 data is: upload it as **Unique Dual** or
     **Combinatorial**, or take the i5 data out. A SeqSetup-format file that
     lists ``index_pairs`` is refused the same way, since a Single kit never
     reads the pairs.
   * **A row that is not an index.** A CSV row with content but no name or
     no i7 sequence, and a TSV ``[Indices]`` line that is not a name, a
     sequence and 1 (i7) or 2 (i5), were dropped without a word, so the kit
     held fewer indexes than the file listed. Such lines are now named
     (*"These rows have content but no index name or no i7 sequence, so
     nothing was saved: line 3, line 7."*), as a pasted worklist's are.
     A blank line is still a blank line.
   * **Two keys for one list.** An Illumina YAML that gives both
     ``i7Index1`` and ``Index1``, or both ``i5Index2`` and ``Index2``, had
     one read and every index in the other dropped. Both keys are named;
     keep one.
   * **A SeqSetup-format name YAML does not read as text.** The same
     refusal the Illumina format already made: an unquoted ``012`` is the
     number 10, so quote such a name (``name: '012'``).
   * **A column the format cannot place.** A CSV column is matched by its
     name in lower case with spaces and underscores taken out, so
     ``INDEX``, ``Index 2``, ``index_2`` and ``I5`` are read as the columns
     they plainly are -- matching the header text exactly meant such a
     column was ignored, and a file whose i5 column was spelled one of
     those uploaded as Single lost the i5 without a word. A name that
     still looks like an index or a lane but names no column of the format
     -- ``Lane``, ``Barcode``, ``I7_Index_ID``, ``Index_Plate`` -- is
     refused by name. So are two columns that name one column of the format
     (``index`` and ``INDEX``), since one would be read and the other's
     values go nowhere. A name that looks like neither an index nor a lane
     -- ``plate``, ``Description`` -- is still ignored.
   * **A cell under no column name.** A row with more cells than the header
     has columns, or with a cell in a column whose header name is blank (or
     only ``_``): that cell was dropped unseen -- an i5 there was lost from a
     Single upload -- and the row is named by its line. A blank column with
     nothing in it, as a spreadsheet's trailing separators give, is still
     read. A file written with a row-number column that has no name, as
     pandas' ``to_csv()`` writes by default, is refused for this.
   * **A double quote that does not close where it should.** A quoted cell
     with text after its closing quote (``P1,"ACGT"NNNN``) was read as
     ``ACGTNNNN``, and a quote never closed took the rest of the file into
     one cell; a quoted cell over more than one line merged the rows after
     it into the cell. Each is refused naming its line. A line break inside
     a cell is refused as well, in any column, even an ignored
     ``Description``: each row must be on one line.
   * **A line that is in no section, or in a section the format does not
     read.** In an ``[i7]``/``[i5]`` CSV, lines before the first ``[i7]``
     were read as part of it, so an ``[IndexKit]`` preamble became its
     header. In a TSV, a line before the first section, between the two
     sections, or under a marker spelled ``[Indexes]`` had no branch at all
     and vanished while the file's other lines kept the kit valid -- every
     index under a misspelled marker, gone with nothing said. Such lines
     are named, with the section they are in.
   * **An index list the chosen mode does not read.** Unique Dual reads
     ``index_pairs``, Combinatorial ``i7_indexes`` and ``i5_indexes``, and
     Single ``i7_indexes``; a list a mode does not read was kept in the kit
     where the index panel never shows it. The list and the mode are named.
     The same check runs on a kit synced from GitHub.

   A section marker written ``[i7],`` or ``"[i7]"`` -- as a spreadsheet
   writes it when the sheet has more than one column -- is still the
   marker, and a UTF-8 byte order mark no longer hides the first column
   name.

   Three things are still dropped quietly, and are known: a TSV
   ``[IndexKit]`` key the reader does not use (``AdapterRead1`` among
   them), a fourth column in ``[Indices]``, and the first line of
   ``[Indices]``, which is read as its header when no cell of it holds a
   sequence. None of them can hide an index -- a line carrying a sequence
   is never read as a header -- but check a TSV kit's adapters and
   defaults on its detail page after uploading it.
4. **Field validation** -- the kit name is required; the version must be a
   valid semantic version; adapter sequences, and every i7/i5 sequence, must
   be DNA (``A``, ``C``, ``G``, ``T``, ``N`` only); every index pair needs a
   name and, in Unique Dual mode, both an i7 and an i5 sequence; a duplicate
   pair *name* is an error and blocks the upload. An index cycles value --
   the kit's i7 or i5 cycles, from the form or from the file -- must equal
   the length of every index in that slot, or the upload is refused naming
   the kit, the slot, the value and the lengths (*"Index kit 'Dual kit': i7
   index cycles is 8, but its i7 indexes are 10 bases long. An index is read
   over as many cycles as it has bases, so set it to the index's length or
   leave it empty."*): an index must have as many bases as the cycles read
   for it. A kit that says *fewer* cycles than its indexes have bases makes
   **Mark Ready** refuse every run that uses it; one that says *more* is
   refused the same way unless the run's own index cycles cap the
   OverrideCycles back to the index length, and then the run passes (see
   :doc:`/user-guide/override-cycles`). A slot with no indexes
   is not checked. The same check runs on a kit synced from GitHub (see
   :doc:`profiles`): a kit file that fails it is refused and not stored,
   and the sync names the file and why. A synced kit file that gives one key
   twice is refused the same way -- YAML would keep the last value and lose
   the first -- and the stored kit of that name and version stays as it was.
   So is a kit too large to store as one record: MongoDB stores at most
   16 MiB in one, and a file under the sync's 10 MiB download limit can be
   more once stored, because each pair's stored id repeats the kit's name.
   The sync deletes what it replaces before it writes, so such a kit took
   the stored synced kits with it; every kit, profile and instrument a sync
   reads is now measured first, and one too large is a refused file.
5. **Name + version clash** -- a kit with the same name and version already
   present is rejected rather than silently overwritten. A kit deleted
   and then uploaded again under its name and version is stored, even
   with other indexes: give a changed kit a new version instead. A run
   page loaded before the change cannot assign from the new kit (see
   :doc:`/user-guide/index-assignment`).

.. warning::
   A duplicate pair *sequence* under a different name -- two indexes that
   are physically indistinguishable at demultiplexing time -- is detected
   internally but is **not shown anywhere**: it neither blocks the upload
   nor appears on any page after it. The kit saves normally. If you
   suspect a kit has this problem, check for it yourself by comparing
   sequences in the downloaded YAML (**Download YAML**, below).

Only the **content type** check (2) and a file that fails to **parse** (3)
are recorded on the :doc:`audit-trail` on rejection, alongside a
**successful** upload. A refusal by the rules below is recorded too, under
the reason it was refused for (``kit_file_problems``, ``repeated_names``,
``columns_not_read``, ``kit_names_nothing``, ``kit_mode_differs``, or
``form_box_refused`` for a value typed in the form). The **size** cap (1),
**field validation** (4), and a **name + version clash** (5) reject the
upload without an audit trail entry -- nothing is recorded for those three.

.. note::
   A rejected upload never partially saves. Nothing is added to the kit
   library until every check above passes.

What a kit file may hold
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Every kit file -- uploaded in any format, or read by the configuration sync --
is checked against one set of rules. **A key the rules do not name is
refused** (a misspelt ``ownr:`` was ignored before), and every problem names
the file, the line, the column and the key, so a file is fixed in one pass
instead of one problem at a time.

These are the keys of SeqSetup's own YAML format, the one **Download YAML**
writes and the configuration sync reads. The other formats are read into the
same shape: an Illumina YAML's ``Name``, ``Version``, ``Description`` and
``IndexSequences``; an Illumina TSV's ``[IndexKit]`` and ``[Indices]``
sections; a CSV's columns.

.. list-table::
   :header-rows: 1
   :widths: 24 12 64

   * - Key
     - Required
     - Value
   * - ``name``
     - yes
     - text, 1 to 256 characters, not made only of dots
   * - ``version``
     - yes
     - text, 1 to 256 characters, no ``:`` and no ``/``
   * - ``index_mode``
     - yes
     - ``unique_dual``, ``combinatorial`` or ``single``
   * - ``description``
     - no
     - text, at most 256 characters
   * - ``comments``
     - no
     - text, at most 256 characters
   * - ``is_fixed_layout``
     - no (``false`` when absent)
     - ``true`` or ``false``
   * - ``adapter_read1``, ``adapter_read2``
     - no
     - a DNA sequence of A, C, G, T and N, at most 1000 bases
   * - ``default_index1_cycles``, ``default_index2_cycles``
     - no
     - a whole number, 1 to 600
   * - ``default_read1_override``, ``default_read2_override``
     - no
     - ``Y``, ``I``, ``U``, ``N``, digits and ``*``, at most 256 characters
   * - ``index_pairs``
     - in ``unique_dual``
     - a list of at least one pair, at most 20,000
   * - ``i7_indexes``
     - in ``combinatorial`` and ``single``
     - a list of at least one index, at most 20,000
   * - ``i5_indexes``
     - in ``combinatorial``
     - a list of at least one index, at most 20,000

An **index** holds ``name`` (text, 1 to 256 characters), ``sequence`` (a DNA
sequence of A, C, G, T and N, 1 to 1000 bases) and, if the kit has a layout,
``well_position`` (text, at most 256 characters). A **pair** holds ``name``,
``index1``, an ``index2`` (leave it out for an i7-only pair) and
``well_position``.

A list the mode does not read is refused rather than kept where the index
panel never shows it: *"i7_indexes: is not read when index_mode is
unique_dual, which reads index_pairs: the index panel would never show these
indexes, so no sample could be given one."* An empty list is allowed.

How a value is written
~~~~~~~~~~~~~~~~~~~~~~~~~

YAML changes some values before any check sees them, so a kit file takes one
plain spelling per value:

* a whole number is plain digits (``8``), with no leading zero and no
  ``0x``, ``_`` or ``:``;
* ``true`` or ``false``, never ``yes``, ``no``, ``on`` or ``off``;
* a decimal number must be quoted: ``version: 1.10`` is read as the number
  1.1 and was stored as the version ``1.1``, so write ``version: "1.10"``;
* text that YAML would read as something else is quoted: an index named
  ``012`` is the number 10 unless it is written ``'012'``;
* a YAML tag (``!!int``, ``!!str``), an anchor (``&name``), an alias
  (``*name``) and a merge key (``<<``) are refused;
* a key given twice is refused, naming both lines: *"The file gives the key
  'D701' twice in one section (line 5), so nothing was saved: the second
  would replace the first without a word."*

The kit's name and version
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A kit's name and version are its identity: the address of its page, its
download and its **Delete**, and what the configuration sync compares between
runs. **Neither is ever invented.**

* A **synced** file must write ``name`` and ``version``. A file with no name
  was stored under the file's own name made into a title
  (``my_kit_file.yaml`` became the kit *My Custom Kit*), and one with no
  version under ``1.0``.
* An **uploaded** file may give them in the file or in the **Kit name** and
  **Kit version** boxes; a value typed in a box wins over the file's. A file
  that gives neither, with the matching box empty, is refused naming both
  places.
* The two **CSV** shapes carry no name and no version at all, so a CSV upload
  needs both boxes filled in. Before, the kit took the upload's filename
  without its ending and the version ``1.0``.
* The form's boxes follow the same rules as the file's keys and are
  **refused, never cut**, each named in the refusal: **Kit name**, **Kit
  version**, **Kit description**, **Comments**, **Adapter Read 1**, **Adapter Read 2**, **Default Index1 Override**, **Default Index2 Override**,
  **Default Read1 Override** and **Default Read2 Override**. A **Kit name** of
  300 characters was quietly cut to 256 -- a cut name is another name -- an
  **Adapter Read 1** of 8,000 bases was stored whole, and a **Default Read1
  Override** of 402 characters became a 410-character ``OverrideCycles`` on
  every sample the kit touched.
* **Default Index1 Override** and **Default Index2 Override** take ``I`` and
  the number of index cycles (``I8``), ``I*``, or nothing; both ``I*`` and an
  empty box mean each index's own length. Anything else is refused naming
  the box. Only the start of the box was read: ``N2I8`` meant no override,
  ``I8garbage`` meant 8, and the ``N2`` of ``I8N2`` went nowhere.

The mode picked on the form wins, as before, and a file that names a
**different** mode is refused naming both: *"The file says index_mode:
combinatorial but the kit was uploaded as single, so nothing was saved: the
mode decides which indexes a sample can be given, and only one of the two can
be right."* Before, the file's key was never read.

Checking a settings repository before a sync
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``pixi run check-settings <folder>`` checks a settings repository with these
same rules, with no database and no network, and prints one problem per line
as ``file:line:column: key: problem``. It reads the kit folder the sync reads
(``index_kits`` by default; ``--index-kits <folder>`` names another, and
``--no-index-kits`` is for a lab whose sync does not read kits), runs the same
field checks on each built kit, and names a kit name and version that two
files give. It does not measure how large a kit is once stored; the sync
does, and refuses one too large to store as one record.

Viewing a kit
----------------

Select a kit's name, or **View**, to see its full contents: every index
pair (or i7/i5 list) with its name and sequence, plus the kit's adapter
and default-override settings. An empty field shows a dash.

.. warning::
   **A kit's Adapter R1 and R2 are stored with the kit and are not written
   to the Sample Sheet.** Nothing that writes a sheet reads them. A sheet's
   ``AdapterRead1`` and ``AdapterRead2`` cells are filled from the run's
   application profile (see :doc:`profiles`), so they are written empty
   when the profile lists the columns and gives no value -- as the shipped
   ``BCLConvertNextera`` profile does. Filling a kit's adapter boxes
   therefore changes no sheet and makes BCL Convert trim nothing; the
   values are a record of what the kit contains, and the kit's
   **Download YAML** carries them back out. The page says so too.

A kit's name may hold a ``/`` -- Illumina's own ``IDT for Illumina DNA/RNA
UD Indexes Set A`` does -- and it opens, downloads and deletes like any
other: its address reads the version as the last part and the name as
everything before it. A kit *version* may therefore not hold a ``/``, and
neither the name nor the version may have a part made only of dots between
slashes (``a/./b``): the browser rewrites such an address, so the kit could
be created but never opened or removed.

.. figure:: /_static/screenshots/admin/index-kit-detail.png
   :alt: The index kit detail page, showing the kit's name and version, its adapter and default-override settings, and its Index Pairs table listing each pair's name and its i7 and i5 sequences, with the Delete button outlined at the bottom next to Download YAML.

   A kit's detail page: name, version, settings, and index pairs with
   their sequences, with **Delete** outlined.

Select **Download YAML** to export the kit as a YAML file, in SeqSetup's own
format -- useful for backing up a kit, or for checking it into a GitHub repo
that :doc:`Config Sync <profiles>` will later pick up.

The file is named after the kit and its version, lower-cased
(``asciikit_v1_0.yaml``). A kit named in an alphabet other than the Latin
one still downloads: the file keeps the kit name's own letters, after that
same lower-casing and tidying, with a plain-ASCII name as the fallback for
older browsers.

Deleting a kit
-----------------

Select **Delete**, on the list or the detail page, and confirm.

.. warning::
   Deleting a kit is immediate and permanent, and **SeqSetup does not check
   whether any run is using it first** -- a Draft, Ready, or even Archived
   run can reference a kit that no longer exists. This is safe for samples
   that already have an index assigned: assigning an index copies its name
   and sequence onto the sample at that moment, so a sample's actual
   barcode is unaffected by a later change or deletion of the kit it came
   from. It does mean a Draft run can no longer assign *new* samples from a
   deleted kit, and its kit picker will report the kit as not found. Before
   deleting a kit that might still be in use, download it first (above) so
   it can be re-imported if needed.

Who can do this
-------------------

Anyone can view the kit list and a kit's detail page. Importing a kit
requires the **Admin** role. Deleting a kit is allowed for an admin (any
kit) or for a standard user deleting a kit *they themselves* uploaded --
not other users' kits.
