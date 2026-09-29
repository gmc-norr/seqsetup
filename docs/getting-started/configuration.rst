Configuration
=============

Environment Variables
---------------------

.. list-table::
   :header-rows: 1
   :widths: 25 45 30

   * - Variable
     - Description
     - Default
   * - ``MONGODB_URI``
     - MongoDB connection URI
     - ``mongodb://localhost:27017``
   * - ``MONGODB_DATABASE``
     - Database name
     - ``seqsetup``
   * - ``INSTRUMENTS_CONFIG``
     - Path to instruments YAML config
     - ``config/instruments.yaml``
   * - ``SEQSETUP_SESSION_SECRET``
     - Session encryption secret key (use in production)
     - Auto-generated in ``.sesskey``
   * - ``SEQSETUP_SESSION_IDLE_SECONDS``
     - A login unused for this many seconds ends. Allowed 60 up to the
       maximum age; a value outside is clamped and logged.
     - ``1800`` (30 minutes)
   * - ``SEQSETUP_SESSION_MAX_AGE_SECONDS``
     - Every login ends this many seconds after it began, even while in use.
       Allowed 300–86400; a value outside is clamped and logged.
     - ``28800`` (8 hours)

Environment variables take precedence over configuration files.

Configuration Files
-------------------

All configuration files are in the ``config/`` directory:

``mongodb.yaml``
   MongoDB connection settings (URI and database name).

``instruments.yaml``
   Supported sequencing instruments, flowcell types, reagent kits, SBS chemistry
   definitions, and default cycle configurations. See :doc:`/admin-guide/instruments`
   for details.

``profiles/``
   Application and test profile definitions. See :doc:`/admin-guide/profiles`.

Session Key
-----------

The session secret key is used to encrypt session cookies. For production
deployments, set the ``SEQSETUP_SESSION_SECRET`` environment variable to a
secure random value::

   export SEQSETUP_SESSION_SECRET="$(openssl rand -hex 32)"

If the environment variable is not set, the application falls back to reading
from ``.sesskey`` at the project root. This file is auto-generated on first
startup if it does not exist.

Keep the session secret out of version control. If the secret changes, all
existing sessions are invalidated.

Local Accounts and the First Admin
----------------------------------

Local accounts live only in the database. SeqSetup does not read
``config/users.yaml`` any more; if the file is still there, the app logs a
warning at start. Make the first admin on the server with
``pixi run create-admin`` (see :doc:`installation`), then make the other
accounts on :doc:`/admin-guide/local-users`.

Once LDAP/AD sign-in works, you can stop local accounts being used by
turning **Allow local user fallback** off on
:doc:`/admin-guide/authentication`. If the directory ever fails,
``pixi run use-local-sign-in`` switches sign-in back to local accounts.
