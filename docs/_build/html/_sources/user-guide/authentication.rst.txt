Authentication
==============

SeqSetup requires authentication before accessing any functionality.

User Roles
----------

Two roles are supported:

**Administrator**
   Full access to all features including index kit management, application profile
   management, local user management, and API token management.

**Standard User**
   Access to run setup, sample management, and export functions. Cannot manage
   index kits, profiles, or other administrative settings.

Login
-----

Navigate to the application URL to reach the login page. Enter your username and
password to authenticate.

Authentication is checked in the following order:

1. **LDAP/AD** -- If configured, credentials are verified against the directory server.
2. **Local users** -- Users managed through the admin interface in MongoDB.
3. **Configuration file** -- Fallback to ``config/users.yaml`` (development use).

Session Management
------------------

After successful login, a session is created and maintained via a browser cookie.
The session persists until the user logs out or the session expires.

The session secret key is stored in ``.sesskey`` at the project root and is
auto-generated on first startup.
