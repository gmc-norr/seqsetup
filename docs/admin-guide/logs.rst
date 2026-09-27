Application Logs
===================

**Admin > Logs** shows an in-memory buffer of SeqSetup's own recent log
lines -- up to the last 2000. It is not a file on disk: restarting the
application clears it.

.. warning::
   By default, this page mostly shows **warnings and errors**, not routine
   activity. SeqSetup's audit trail (logins, user and token changes,
   configuration changes) is logged at the ``INFO`` level, and nothing in
   SeqSetup raises its own logger above Python's default threshold, which
   only lets ``WARNING`` and more severe messages through. In practice that
   means this page will not show a record of who logged in or who changed
   what -- only failures and unusual conditions, such as a rejected
   request or a problem reaching an external server. A deployment that
   wants the full activity trail on this page needs to raise the logging
   level itself (for example, by calling Python's ``logging.basicConfig``
   with ``level=logging.INFO`` before starting the application).

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
