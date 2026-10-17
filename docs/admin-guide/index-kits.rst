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
3. **Parsing** -- a file that fails to parse in the selected format is
   rejected with a generic "check the format and try again" message. In
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
   and the sync names the file and why.
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
**successful** upload. The **size** cap (1), **field validation** (4), and a
**name + version clash** (5) reject the upload without an audit trail
entry -- nothing is recorded for those three.

.. note::
   A rejected upload never partially saves. Nothing is added to the kit
   library until every check above passes.

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
