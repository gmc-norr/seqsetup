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

Environment variables take precedence over configuration files.

Configuration Files
-------------------

All configuration files are in the ``config/`` directory:

``mongodb.yaml``
   MongoDB connection settings (URI and database name).

``users.yaml``
   Local user credentials (bcrypt-hashed passwords). Used during development;
   production deployments should use LDAP/AD.

``instruments.yaml``
   Supported sequencing instruments, flowcell types, reagent kits, SBS chemistry
   definitions, and default cycle configurations. See :doc:`/admin-guide/instruments`
   for details.

``profiles/``
   Application and test profile definitions. See :doc:`/admin-guide/profiles`.

Session Key
-----------

A session secret key is stored in ``.sesskey`` at the project root. It is
auto-generated on first startup if it does not exist. Keep this file out of
version control.

Disabling Default Credentials
-----------------------------

The default development users in ``config/users.yaml`` should not be available in
production. The authentication system checks credentials in this order:

1. **LDAP/AD** (if configured and enabled)
2. **Local users in MongoDB** (managed through the admin interface)
3. **``config/users.yaml``** (file-based fallback)

To disable the default credentials, use one or more of the following approaches:

**Remove the YAML users.** Replace the contents of ``config/users.yaml`` with an
empty user list:

.. code-block:: yaml

   users: {}

This disables all file-based logins while keeping the file in place. MongoDB local
users and LDAP authentication continue to work.

**Configure LDAP without local fallback.** Set up LDAP/AD authentication through the
admin interface and set ``allow_local_fallback`` to ``false``. This prevents the local
authentication path from being reached entirely.

**Restrict the config mount in Docker.** By default, ``docker-compose.yml``
bind-mounts the entire ``config/`` directory. You can mount only the files you need
and omit ``users.yaml``, which causes file-based authentication to fail with no
matching users.
