Change History
==============

Every run's page ends with a **Change history** panel -- a read-only log of
who changed what on that run, and when. It is available on a run in any
status, and loads the moment you scroll it into view.

.. figure:: /_static/screenshots/history/change-history.png
   :alt: The Change history panel at the bottom of a run's page, listing timestamped entries: who made each change and what field or sample it affected.

   The Change history panel, outlined.

What is recorded
-----------------

Each entry is timestamped and shows who made the change. The first entry
for a run records how it was created -- from scratch, duplicated from
another run, or from a template. After that, every save that actually
changed something adds an entry listing:

- Every run-level setup field that changed, old value and new value --
  including its status, so promoting to Ready, returning to Draft, and
  archiving each show up as an ordinary "status: ..." change alongside
  everything else.
- Every sample that was added, removed, or had a field change -- sample
  ID, name, project, test, lanes, index assignment, override cycles, and
  barcode mismatch overrides are all tracked the same way.

A save that does not actually change anything adds no entry.

.. note::
   A single very large change -- for example pasting hundreds of samples
   at once -- can be recorded as a one-line summary ("N sample changes: X
   added, Y removed, Z modified") instead of the full per-sample detail,
   so that one entry never becomes too large to save. This only happens
   for changes far larger than normal editing produces.

What is not recorded
---------------------

The generated Sample Sheet, JSON and validation exports are not
themselves part of the change history -- only the fact that the run's
status changed (which is what causes them to be (re)generated) is. The
run's own bookkeeping (its internal ID, its own last-updated timestamp,
and in-progress wizard state) is not tracked either, since none of it is
something a person changed.

If a run has no history entries and no record of how it was created, a
note explains that change history began when this feature was deployed,
and that edits made before that point were never captured.

.. warning::
   Change history is **not retained after the run itself is deleted**.
   Deleting an empty Draft, or an Archived run (administrators only),
   removes its entire change history at the same time -- there is no way
   to recover it afterward. A run that must keep a permanent audit trail
   should not be deleted.

Who can see it
---------------

Any signed-in user can open any run's Change history, whether or not they
created it and whether or not they are an administrator -- it is not
restricted to the run's owner. It also cannot be edited, annotated or
deleted from within the app -- entries are only ever added, never
changed.
