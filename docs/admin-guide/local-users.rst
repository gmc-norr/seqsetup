Local Users
===========

Administrators create and manage local user accounts from **Admin > Users**.
A local user signs in with a username and password that SeqSetup stores in
its own database.

Creating a user
---------------

Fill in the **Create New User** form:

1. **Username** -- letters, digits, ``.``, ``_``, ``@`` and ``-`` only, up to
   128 characters. It cannot be changed later; create a new account instead.
2. **Display Name** -- shown throughout the app in place of the username.
3. **Email** -- optional.
4. **Role** -- **Standard** or **Admin**.
5. **Password** -- at least 8 characters. SeqSetup refuses a password that is
   too short, made of a single repeated character, all digits, or one of a
   short list of very common weak or default passwords.

Select **Create User** to save the account.

.. figure:: /_static/screenshots/admin/users-list.png
   :alt: The Users table, with one user's Edit button outlined.

   A user's **Edit** button, outlined.

Editing a user
---------------

Select **Edit** on a user's row to change their display name, email, role or
password in place, without leaving the list.

.. figure:: /_static/screenshots/admin/user-edit.png
   :alt: A user's row switched into edit mode, showing editable display name, email and role fields, with the Save button outlined.

   A row in edit mode, with **Save** outlined.

The password field in edit mode has no label of its own; its placeholder
text, "Leave blank to keep", is the only clue -- leave it empty to keep the
existing password, or type a new one to replace it. Select **Save** to
apply the changes, or **Cancel** to discard them.

Changing a user's **role** or **password** ends every login that user has
open, in every browser: their next click takes them to the login page, and
they sign in again with the new role or password. The message after saving
says so: *"User 'name' updated. Their open logins were ended."* Changing
only the display name or email does not end their logins. If you change
your own role, you are signed out too.

.. warning::
   SeqSetup refuses to demote or delete the **last remaining Admin**
   account -- doing so would leave every admin-only page unreachable by
   anyone. Create a second Admin account before removing or demoting the
   first.

Deleting a user
-----------------

Select **Delete** on a user's row and confirm. This removes the account from
SeqSetup's database and ends every login the user has open -- the message
says *"User 'name' deleted. Their open logins were ended."* It does not
change or remove any runs that user created, and it does not affect entries
already recorded in a run's change history or in the :doc:`audit-trail`
under that username.

.. warning::
   API tokens are not tied to the user who made them. Deleting or demoting
   an administrator does **not** revoke the API tokens they created -- check
   :doc:`api-tokens` and revoke any that should stop working.

Who can do this
-----------------

Every action on this page requires the **Admin** role. A standard user does
not see **Admin** in the sidebar, and is refused if they visit
``/admin/users`` directly.

How a login is actually checked
---------------------------------

A local user account is one of several sources SeqSetup can authenticate a
login against. See :doc:`authentication` for the exact order LDAP/Active
Directory, local accounts, and the ``config/users.yaml`` file are tried in.
