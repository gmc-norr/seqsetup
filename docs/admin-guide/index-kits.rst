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
  page's own **Override cycles help** for the notation.

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
   rejected with a generic "check the format and try again" message.
4. **Field validation** -- the kit name is required; the version must be a
   valid semantic version; adapter sequences, and every i7/i5 sequence, must
   be DNA (``A``, ``C``, ``G``, ``T``, ``N`` only); every index pair needs a
   name and, in Unique Dual mode, both an i7 and an i5 sequence; a duplicate
   pair *name* is an error and blocks the upload.
5. **Name + version clash** -- a kit with the same name and version already
   present is rejected rather than silently overwritten.

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

.. figure:: /_static/screenshots/admin/index-kit-detail.png
   :alt: The index kit detail page, showing the kit's name and version, its adapter and default-override settings, and its Index Pairs table listing each pair's name, with the Delete button outlined at the bottom next to Download YAML.

   A kit's detail page: name, version, settings, and index pairs by name,
   with **Delete** outlined.

Select **Download YAML** to export the kit as a YAML file, in SeqSetup's own
format -- useful for backing up a kit, or for checking it into a GitHub repo
that :doc:`Config Sync <profiles>` will later pick up.

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
