Deleted Runs
============

**Admin > Deleted runs** lists every run that was deleted after it had been
Ready -- an Archived run, or an empty Draft that was Ready once -- with a
copy of the run and its :doc:`/user-guide/change-history`.

Before such a run is deleted, SeqSetup saves a full copy of it as it is at
that moment: its settings, its samples, and any sample sheet, JSON export
and validation report it still has. An Archived run still has them,
exactly as they were made. A Draft that was sent back from Ready does not:
sending a run back to Draft clears them. If the copy cannot be saved, the
run is not deleted. Change history is never deleted, for any run.

An empty Draft that was never Ready is deleted without a copy: it never
produced a sample sheet.

.. figure:: /_static/screenshots/admin/deleted-runs.png
   :alt: The Deleted runs page: a table with one deleted run, showing its status when deleted, its number of samples, who created and who deleted it, when, and its state, with the table outlined.

   The Deleted runs list.

The list
--------

Newest first. Each row shows the run's name, its status when it was
deleted, how many samples it had, who created it, who deleted it and when,
and its **State**:

- **Deleted** -- the run was deleted and the copy is complete.
- **Deleted — not confirmed** -- the run was deleted, but SeqSetup stopped
  (or could not write to its database) before it marked the copy done. The
  copy is still the run as it was when it was deleted. If two people tried
  to delete it at the same moment and neither try was marked done, both are
  named under **Deleted by** ("anna or bo"): SeqSetup cannot tell which of
  them deleted it.

A delete that did not go through is not listed. If someone changes a run at
the moment it is being deleted, the delete is refused with "Someone else
changed or deleted this run at the same moment…", and the run stays as it
is. The :doc:`audit-trail` records every try as ``run.deleted`` or
``run.delete.failed``.

One deleted run
---------------

Select a run's name to see the copy: its description, status when deleted,
instrument and flowcell, who created and last changed it, who deleted it
and when, its Sample IDs, and its change history.

.. figure:: /_static/screenshots/admin/deleted-run.png
   :alt: One deleted run: its details, its list of Sample IDs, and its change history, with the Sample IDs outlined.

   One deleted run, with its Sample IDs and change history.

The page is read only. A deleted run cannot be brought back from here, and
its sample sheet cannot be downloaded from here.

Who can do this
---------------

This page requires the **Admin** role.
