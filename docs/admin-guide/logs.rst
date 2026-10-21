Application Logs
===================

**Admin > Logs** shows an in-memory buffer of SeqSetup's own recent log
lines -- up to the last 2000. It is not a file on disk: restarting the
application clears it.

Every line on this page is **also written to the application's standard error**
at ``INFO`` and above, which is where a container runtime keeps it: with the
shipped Compose file, ``docker compose logs app`` (or
``docker compose logs -f app`` to follow it). That copy is what survives a
restart and what to read when this page cannot be opened -- after a refused
sign-in, for instance, whose reason is logged. Both copies pass through the
same scrub described below, and so do the tracebacks the web server itself
prints. If your deployment already configures Python logging of its own (a
file or syslog handler on the root logger, set up before SeqSetup starts),
SeqSetup leaves standard error alone and your own handler receives these
lines instead, so no line is written twice.

.. note::
   This page shows SeqSetup's **warnings and errors** -- a rejected request,
   a problem reaching an external server -- together with its ``INFO`` lines:
   which instruments file the start read, each config sync's progress and
   result, and each fetch from the sample API. It is not a record of who did
   what: logins, user and token changes, run changes and exports are on the
   :doc:`audit-trail` page instead, which is kept permanently. The one
   exception: if an audit event cannot be saved to the database, it is
   written here as an ``ERROR`` that includes the event, so it is not lost.

Filtering
-----------

- **Level** -- narrow to ``ERROR``, ``WARNING``, ``INFO`` or ``DEBUG``, or
  leave it on **All Levels**.
- **Search** -- matches text anywhere in the log message.

Select **Filter** to apply both.

.. warning::
   **Refresh** does **not** keep the current filters -- it reloads the page
   with no ``Level`` or ``Search`` filter at all, and the two fields reset
   to **All Levels** and empty to match. Use **Filter** again (not
   **Refresh**) to see new entries under the same filter.

.. figure:: /_static/screenshots/admin/logs.png
   :alt: The log entries table filtered to a single row, a WARNING-level entry recording a rejected request, with that row outlined.

   A filtered log entry -- here, a request SeqSetup's CSRF defense
   rejected -- outlined.

.. note::
   SeqSetup scrubs values that look like passwords, API keys, bcrypt hashes
   and similar secrets out of every message before it reaches this buffer,
   replacing them with ``***``. This is a defense against a careless log
   statement leaking a secret here -- it is not a reason to log secrets on
   purpose.

Clearing logs
----------------

Select **Clear Logs** and confirm to empty the buffer immediately. This
cannot be undone, and it removes every entry, not just the ones a filter
currently shows.

Who can do this
-------------------

Every action on this page, including clearing the log buffer, requires the
**Admin** role.
