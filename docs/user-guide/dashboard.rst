Dashboard
=========

After signing in, you land on the dashboard: the list of your sequencing
runs, grouped by status.

Tabs
----

Runs are grouped into three tabs, each with a count of how many runs are
in it:

- **Draft** -- being edited, not yet validated.
- **Ready** -- passed validation and locked; its exports are ready to
  download.
- **Archived** -- a read-only historical record.

.. figure:: /_static/screenshots/dashboard/tabs.png
   :alt: The Draft, Ready and Archived tabs above the run list, with their run counts.

   The status tabs, outlined.

A run's row shows its name, instrument platform, flowcell, sample count,
who created and last modified it, and when it was last updated. The
buttons on the right depend on the run's status:

- **Edit** (Draft) or **Open** (Ready/Archived) -- go to the run.
- **Duplicate** -- start a new Draft copying this run's configuration.
- **Archive** -- Ready runs only.
- **Delete** -- an empty Draft (no samples yet), or an Archived run if you
  are an administrator. An empty Draft that was Ready once -- sent back to
  Draft and emptied -- can only be deleted by an administrator.

Deleting never deletes a run's :doc:`Change History <change-history>`. A
run that was ever Ready is copied first, as it is at that moment, and the
copy is kept on :doc:`/admin-guide/deleted-runs`. An Archived run's copy
has its sample sheet exactly as it was made. A Draft that was sent back
from Ready has no sample sheet any more -- sending a run back to Draft
clears it -- so its copy has none either. If the copy cannot be saved, the
run is not deleted. If someone changes the run at the moment you delete
it, nothing is deleted and you are asked to reload the page.

Search
------

Type in the search box above the tabs to find a run by name, or by any
sample ID it contains, across all three statuses.

.. figure:: /_static/screenshots/dashboard/search.png
   :alt: The dashboard search box outlined, with a query typed in, above the one matching run and its status badge; the status tabs are gone while a search is active.

   Searching by run name -- the tabs are replaced by a match count and the one matching run, its status shown as a badge.

Search results list which sample IDs matched under each run. Clear the
search box to see the tabs again.

.. note::
   Search matches a sample ID that contains what you typed, anywhere in
   the run's list of samples, case-insensitively -- not only an exact
   match, and not only the run you were looking at when you started
   typing.

Starting a new run
-------------------

The **+ New Run** button is in the sidebar on every page, not only the
dashboard.

.. figure:: /_static/screenshots/dashboard/new-run-button.png
   :alt: The + New Run button in the left sidebar, outlined.

   The New Run button, outlined.

Selecting it creates a new Draft run immediately and takes you to
:doc:`run-setup` to configure it.
