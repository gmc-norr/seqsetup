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
     - Path to the instruments YAML file to read instead of the one SeqSetup
       ships. Set, it decides; SeqSetup does not start when it names a path
       that is not a file. The path read is logged at start.
     - unset: ``config/instruments.yaml``
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

.. note::

   SeqSetup sends no telemetry: it turns FastAPI's OpenTelemetry support
   off. Leave the ``OTEL_*`` variables unset for it all the same. FastAPI
   reads ``OTEL_PROPAGATORS`` as it loads, and a value naming a propagator
   that is not installed (``b3``, for example) stops SeqSetup from starting
   with ``ValueError: Propagator b3 not found``.

Configuration Files
-------------------

All configuration files are in the ``config/`` directory:

``mongodb.yaml``
   MongoDB connection settings. It has one key, ``mongodb``, holding
   ``uri`` and ``database``, and **both must be written out**::

      mongodb:
        uri: "mongodb://user:password@host:27017/seqsetup?authSource=seqsetup"
        database: "seqsetup"

   Start-up stops, naming the file, the line and the key, when a key is
   misspelt or missing, when the file is empty, cannot be read or is not
   UTF-8, when ``uri`` does not begin ``mongodb://`` or ``mongodb+srv://``
   (without a scheme the driver reads the value as a host name and connects
   to it with **no authentication**), or when ``database`` is longer than 63
   bytes or holds a space, ``.``, ``$``, ``/``, ``\``, ``"`` or a hidden
   character -- the characters MongoDB itself refuses. A misspelt key used to
   mean ``mongodb://localhost:27017`` with no word at all.

   **No message, log line or audit row ever repeats a value of this file**:
   it holds the password. ``MONGODB_URI`` and ``MONGODB_DATABASE`` win over
   the file, as before, and their values follow the same rules.

   ``pixi run check-settings <folder> --local-database config/mongodb.yaml``
   checks the file without connecting to anything.

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
