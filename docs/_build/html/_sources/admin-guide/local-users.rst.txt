Local User Management
=====================

Administrators can manage local user accounts stored in MongoDB through the admin
interface.

Creating Users
--------------

To create a new local user, provide:

- **Username** -- Unique login identifier
- **Display name** -- Name shown in the UI
- **Email** -- Optional email address
- **Password** -- Will be hashed with bcrypt before storage
- **Role** -- ``admin`` or ``standard``

Editing Users
-------------

Existing users can have their display name, email, role, and password updated.
Username changes are not supported; create a new user instead.

Deleting Users
--------------

Users can be deleted from the admin interface. This removes the user from MongoDB
but does not affect any runs they created.

Authentication Priority
-----------------------

Local MongoDB users are checked after LDAP/AD but before the ``config/users.yaml``
file. If LDAP is configured with ``allow_local_fallback`` set to ``false``, local
users are not consulted.
