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
- **From** / **To** -- dates, both days included. Times on this page are
  UTC.

Select **Search** to apply the boxes, or **Clear** to empty them. Results
are newest first, 100 at a time; **Older** shows the next 100.

Each row shows the time, who acted, the event name, what it acted on, the
result (``success``, ``failure`` or ``denied``) and any details, such as a
run's old and new status.

What is recorded
----------------

The event name says what happened. The main groups are:

- **Signing in** -- ``login.success``, ``login.failure``,
  ``login.rate_limited``, ``logout``.
- **Users and access** -- ``user.created``, ``user.updated``,
  ``user.deleted``, ``api_token.created``, ``api_token.revoked``,
  ``auth.method.changed``, ``auth.ldap_config.updated``, and
  ``api.auth.failure`` for a refused API token.
- **Runs and samples** -- ``run.status.changed`` (Mark Ready, back to
  Draft), ``run.status.denied``, ``run.archived``, ``run.deleted``,
  ``run.cloned``, ``run.created_from_template``, every ``sample.`` change
  (added, edited, deleted, index assigned or cleared, and the bulk
  actions), and ``template.`` changes.
- **Exports and the API** -- ``export.downloaded``, ``api.run.read``,
  ``api.runs.listed``.
- **Configuration** -- ``config_sync.`` (manual and scheduled syncs),
  ``instrument.toggled``, ``index_kit.upload``, ``index_kit.deleted``,
  ``lims_config.updated``, ``lims.url_blocked``, ``logs.cleared``.

Secrets are never stored: a password or token inside a web address is
removed, and a field named like a password or API key is shown as ``***``.

.. note::
   If the database cannot be reached when something happens, the action
   still goes through, and the event is written to the :doc:`logs` page as
   an ``ERROR`` instead. That page is cleared on restart, so check it after
   a database outage.

Who can do this
---------------

This page requires the **Admin** role.
