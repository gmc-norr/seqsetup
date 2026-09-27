Run Templates
=============

A run template is a saved snapshot of a run's setup -- instrument, flowcell,
cycles, mismatch tolerances and the other fields on its setup page -- that
you can reuse to start a new Draft without re-entering them. Templates are
listed and managed on their own page, **Run Templates** in the sidebar.

Saving a run as a template
---------------------------

Every run's page, at the bottom, has a **Save as template** box:

.. figure:: /_static/screenshots/templates/save-as-template.png
   :alt: The Save as template box at the bottom of a run's page, with a name typed in and the Save as template button outlined.

   The Save as template box, outlined.

Type a name and select **Save as template**. This works on a run in any
status -- Draft, Ready or Archived -- since a template only reads the run,
it never changes it.

.. note::
   Saving as a template captures the run's setup only: instrument
   platform, flowcell, reagent cycles, read and index cycle lengths,
   barcode mismatch tolerances, adapter behavior and the FASTQ/lane-
   splitting switches. It does **not** capture the run's samples, their
   indexes, lanes, override cycles, or any per-sample analysis -- a run
   made from a template today always starts with zero samples, no matter
   how many the source run had.

Managing templates
-------------------

**Run Templates**, in the sidebar, lists every saved template: its name,
instrument platform, how many samples it will pre-load, and who last
changed it.

.. figure:: /_static/screenshots/templates/manage.png
   :alt: The Run Templates list, with one template's Delete button outlined.

   The Run Templates list, with a template's Delete button outlined.

Selecting **Delete** asks you to confirm, then removes the template
immediately. Deleting a template never touches any run that was already
made from it -- a run copies the template's settings once, at creation,
and keeps no link back to it afterward.

Starting a new run from a template
------------------------------------

Each template's row has its own **New run** button:

.. figure:: /_static/screenshots/templates/new-run-from-template.png
   :alt: A new Draft run's title and status bar, named after the template it was started from and showing Draft status.

   A new Draft started from a template, named after it.

Selecting it creates a fresh Draft immediately, named after the template,
with its setup filled in and no samples yet -- add samples and indexes the
same way you would on any other new run. The same "start from a template"
choice is also offered on the New Run page itself when at least one
template exists; see :doc:`run-setup`.

.. warning::
   If the template's instrument is no longer enabled, or its flowcell or
   reagent-cycle count is no longer offered for that instrument, starting
   a run from it is refused with an error message naming what is missing,
   and nothing is created. This does not check the template's index kit --
   a template never stores samples, so there is no index kit reference to
   check.
