Authentication
==============

SeqSetup requires you to sign in before you can see any run, sample or index
data. A request for any page other than the login page itself is redirected
to :guilabel:`/login` if you do not have a session yet.

Signing in
----------

1. Navigate to the application URL. If you are not already signed in, you
   land on the login page.
2. Enter your **Username** and **Password**.
3. Select **Sign In**.

.. figure:: /_static/screenshots/login/login-form.png
   :alt: The SeqSetup login form, with the username field, password field, and Sign In button outlined in red.

   The login form, outlined.

A wrong username or password redisplays this same page with an error
message; the fields are not pre-filled. Repeated failed attempts from the
same address, or against the same username, are rate-limited and rejected
with "Too many login attempts. Try again later." until the limit resets.

Authentication is checked in this order:

1. **LDAP/AD**, if a directory server is configured.
2. **Local users**, managed through the admin interface and stored in
   MongoDB.
3. **Configuration file** (``config/users.yaml``), a fallback most often
   used in development.

.. note::
   Signing in clears any prior session content before applying the new
   one, so an old session id cannot be reused to inherit a different
   user's access.

User roles
----------

Every user has exactly one of two roles:

**Administrator**
   Full access to run setup, samples, and export, plus index kit
   management, application profiles, local users, API tokens, and the
   rest of the admin section.

**Standard User**
   Run setup, sample management, and export. The admin section is not
   shown, and admin-only actions (such as index kit upload) are refused.

Session and logout
-------------------

After signing in, your session is kept in a server-side cookie. It lasts
until you sign out or the session expires. Signing out is a button in the
top-right corner of every page, next to your display name; it always
submits as a request that changes state, so it cannot be triggered from
another site.

The session's signing secret comes from the ``SEQSETUP_SESSION_SECRET``
environment variable when set (the recommended production setup). If it
is not set, SeqSetup falls back to a ``.sesskey`` file at the project
root, generated automatically on first startup.

See :doc:`/admin-guide/authentication` for configuring LDAP/AD and local
users.
