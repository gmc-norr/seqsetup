Run Templates
=============

A run template is a saved snapshot of a run's setup -- instrument, flowcell,
cycles, mismatch tolerances and the other fields on its setup page -- that
you can reuse to start a new Draft without re-entering them. Templates are
listed and managed on their own page, **Run Templates** in the sidebar.

Saving a run as a template
---------------------------

At the bottom of every run's page, select **More: Save as template ·
Change history** to open the **Save as template** box:

.. figure:: /_static/screenshots/templates/save-as-template.png
   :alt: The Save as template box in the More fold at the bottom of a run's page, with a name typed in and the Save as template button outlined.

   The **Save as template** button, outlined.

Type a name and select **Save as template**. This works on a run in any
status -- Draft, Ready or Archived -- since a template only reads the run,
it never changes it.

.. note::
   Saving as a template captures the run's setup only: instrument
   platform, flowcell, reagent cycles, read and index cycle lengths,
   barcode mismatch tolerances, adapter behavior and the
   FASTQ/lane-splitting switches. It never captures the run's samples or
   their indexes, so a run made from a template starts with no samples,
   however many the source run had. A request that asks to save samples
   in a template is refused, and nothing is saved: *"A template holds a
   run's setup only, not its samples. Nothing was saved."*

Managing templates
-------------------

**Run Templates**, in the sidebar, lists every saved template: its name,
instrument platform, how many samples it will pre-load (none, for a
template saved here), and who last changed it.

Any signed-in user can create a template and start a run from any template.
Only the person who made a template, or an administrator, can delete it; the
**Delete** button shows only for them.

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
   :alt: A new Draft run's title, outlined, named after the template it was started from, next to its Draft status badge.

   The new run's title, outlined -- named after the template it was
   started from.

Selecting it creates a fresh Draft immediately, named after the template,
with its setup filled in and no samples yet -- add samples and indexes the
same way you would on any other new run. The same "start from a template"
choice is also offered on the New Run page itself when at least one
template exists; see :doc:`run-setup`.

.. warning::
   If the template's instrument is no longer enabled, or its flowcell or
   reagent-cycle count is no longer offered for that instrument, starting
   a run from it is refused with an error message naming what is missing,
   and nothing is created. This does not check any index kit: a template
   saved here holds no samples, so it names no kit.
