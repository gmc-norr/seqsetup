Application Logs
===================

**Admin > Logs** shows an in-memory buffer of SeqSetup's own recent log
lines -- up to the last 2000. It is not a file on disk: restarting the
application clears it.

.. note::
   This page shows SeqSetup's **warnings and errors** -- a rejected request,
   a problem reaching an external server -- not routine activity. Who did
   what (logins, user and token changes, run changes, exports) is on the
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
