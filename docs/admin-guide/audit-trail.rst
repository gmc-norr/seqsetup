Audit Trail
===========

**Admin > Audit trail** is SeqSetup's permanent record of who did what, and
when: sign-ins, user and API token changes, run status and sample changes,
exports, and configuration changes. Changes to a run's own setup -- its
name, instrument, flowcell, cycles -- are not here; they are in that run's
:doc:`/user-guide/change-history`.

Events are kept in the database for good. Nothing in SeqSetup can change or
delete one -- restarting the application does not clear them, and neither
does **Clear Logs** on the :doc:`logs` page. (Someone with direct access to
the database server could still change it; that is outside SeqSetup.)

Finding events
--------------

.. figure:: /_static/screenshots/admin/audit-trail.png
   :alt: The Audit trail page filtered to "run.status", showing the search boxes and a table of run status changes with who made them, when, and the old and new status, with the table outlined.

   Run status changes found by typing ``run.status`` in **What happened**,
   with the results outlined.

- **What happened** -- matches the *start* of the event name. ``login``
  finds ``login.success``, ``login.failure`` and ``login.rate_limited``;
  ``sample.`` finds every sample change.
- **Who** -- the exact name shown in the **Who** column, for example a
  username.
- **On what** -- the exact value shown in the **On what** column, for
  example a run ID or a username.
- **From** / **To** -- dates, both days included, as days in the server's
  time zone. Each time on this page is followed by the zone's name (see
  :ref:`time-zone`).

Select **Search** to apply the boxes, or **Clear** to empty them. Results
are newest first, 100 at a time; **Older** shows the next 100.

Each row shows the time, who acted, the event name, what it acted on, the
result (``success``, ``failure`` or ``denied``) and any details, such as a
run's old and new status.

What is recorded
----------------

The event name says what happened. The main groups are:

- **Signing in** -- ``login.success``, ``login.failure``,
  ``login.rate_limited``, ``logout``. For the two refusals, **Who** holds
  the typed name only when it names an account SeqSetup knows; otherwise it
  reads ``(unknown name)`` and a few hex characters (see
  :ref:`refused-sign-in-names`).
- **Users and access** -- ``user.created``, ``user.updated``,
  ``user.deleted``, ``api_token.created``, ``api_token.revoked``,
  ``auth.method.changed``, ``auth.ldap_config.updated``, and
  ``api.auth.failure`` for a refused API token.
- **Runs and samples** -- ``run.status.changed`` (Mark Ready, back to
  Draft), ``run.status.denied``, ``run.archived``, ``run.deleted``,
  ``run.delete.failed``, ``run.delete.copy_unconfirmed``, ``run.cloned``,
  ``run.created_from_template``, every ``sample.`` change (added, edited,
  deleted, index assigned or cleared, and the bulk actions), and
  ``template.`` changes. ``run.deleted`` says whether a copy was kept
  (``kept_copy``) and which one (``copy_id``); ``run.delete.failed`` gives
  the reason: ``copy_failed``, ``no_copy_store``, ``delete_error`` or
  ``run_changed``. See :doc:`deleted-runs`. A Mark Ready's
  ``run.status.changed`` holds ``test_versions``: each test, the version
  text asked, and the exact version and file the Sample Sheet was written
  with -- kept here after back to Draft clears them from the run.
- **Exports and the API** -- ``export.downloaded``, ``export.viewed`` (a
  run's page under **API Exports**), ``api.run.read``,
  ``api.runs.listed``.
- **Configuration** -- ``config_sync.`` (manual and scheduled syncs),
  ``instrument.toggled``, ``index_kit.upload``, ``index_kit.deleted``,
  ``lims_config.updated``, ``lims.url_blocked``, ``logs.cleared``.

Secrets are never stored: a password or token inside a web address is
removed, and a field named like a password or API key is shown as ``***``.

.. _refused-sign-in-names:

The name in a refused sign-in
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For ``login.failure`` and ``login.rate_limited``, **Who** holds what was
typed into the name box **only when it names an account SeqSetup knows** --
a local account on :doc:`local-users`, matched exactly. Anything else is
recorded as::

   (unknown name) 3f9a1c08

People type their password into the name box; without this, that password
would sit in a record nothing can delete, shown to every admin. The hex
part is a fingerprint of what was typed, so repeated attempts with the same
text group together and you can still see that one source keeps trying one
name. It is computed with a secret key of this deployment's own (derived
from ``SEQSETUP_SESSION_SECRET``), so the text cannot be read back from it,
and cannot be found by trying candidates. Two deployments give different
fingerprints for the same text, and changing the session secret changes
every later fingerprint.

A directory (LDAP / Active Directory) name is recorded the same way when
that person has never signed in: SeqSetup keeps no list of directory users,
and it does not ask the directory about a name that was refused -- a
mistyped password must not be sent anywhere. Once the sign-in succeeds,
``login.success`` holds the name the directory confirmed.

.. _rate-limited-rows:

How many refusals one ``login.rate_limited`` row stands for
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Repeated sign-in attempts from one address, or for one name, are refused
once they pass the limit (see :doc:`/user-guide/authentication`).
**At most one ``login.rate_limited`` row is written per address per limiter
window**, and its details say how many refused requests it stands for::

   ip: 198.51.100.7   retry_after: 43   refused: 12

Without this, a flood of a few thousand refusals wrote a few thousand rows
that all said the same thing, and this page -- which shows 100 at a time --
could show nothing else for a long while.

The count is built like this: the first refusal from an address writes its
row at once, so you see the attack while it is happening; the refusals that
follow in the same window are counted, and their count is carried by that
address's **next** row. Nothing rewrites a row that has gone out: the
trail is insert-only.

A row that carries a count from an earlier window says how much of
``refused`` that was, as ``refused_earlier``::

   ip: 198.51.100.7   retry_after: 43   refused: 12   refused_earlier: 11

The carried number belongs to the **address**, not to the name in the
**Who** column: only the row's own refusal -- one of the twelve above --
was typed with that name, and the other eleven were typed at that address
in the window before, under whatever names were tried then. A row that
carries nothing has no ``refused_earlier``.

.. note::
   A row's count is therefore **at least** that many refusals, not exactly
   that many: the ones that followed it are on the address's next row, and
   there may never be one. A count is lost when **the burst stops** and
   that address is never refused again; when that address is not refused
   again **within three limiter windows** (its count is then dropped, so
   the addresses of a flood cannot pile up in memory for the life of the
   process); and when **SeqSetup is restarted** (or stops) while refusals
   are still being counted. The rows already written are never changed, so
   they read low by however many requests had not yet been carried, with
   nothing on the row to say so. The server log on the :doc:`logs` page,
   and your reverse proxy's own access log, still show every request.

.. note::
   If the database cannot be reached when something happens, the action
   still goes through, and the event is written to the :doc:`logs` page as
   an ``ERROR`` instead. That page is cleared on restart, so check it after
   a database outage.

Who can do this
---------------

This page requires the **Admin** role.
