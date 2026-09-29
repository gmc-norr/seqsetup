Authentication Settings
=========================

SeqSetup supports three ways to sign in, chosen on **Admin > Authentication**:
**Local Authentication**, **Active Directory**, and **LDAP**.

- **Local Authentication** uses the accounts on :doc:`local-users`, kept in
  the SeqSetup database.
- **Active Directory** and **LDAP** ("directory sign-in") check the name and
  password against your directory server.

SeqSetup never signs in to the directory as itself, and it stores no
directory password. It signs in *as the person signing in*, with the name
and password they typed, and reads their own name, email and groups over
that one connection.

How a sign-in is checked
--------------------------

1. A name longer than 64 characters is refused at once.
2. If directory sign-in is on -- the method is **Active Directory** or
   **LDAP** *and* every setting it needs is filled in (see below) --
   SeqSetup signs in to the directory as that person:

   - The name must be letters, digits, ``.``, ``_`` and ``-``, up to 64
     characters. It is used in lower case, so ``Anna`` and ``anna`` are the
     same person.
   - A member of the **Admins group** gets the Admin role. A member of only
     the **Users group** gets the Standard role. On Active Directory,
     membership through groups inside those groups counts too; on LDAP,
     only direct members count.
   - Someone in neither group is refused, even with the right password.

3. If the directory refuses -- a wrong name or password, in neither group,
   or the server cannot be reached -- and **Allow local user fallback** is
   on, the local accounts are tried next. With fallback off, the sign-in is
   refused.
4. With **Local Authentication**, only the local accounts are checked. A
   wrong password is refused; there is no second place with another
   password.

Every failed sign-in shows the same message: *"Sign-in failed. Check your
name and password, or ask an admin whether you have access to SeqSetup."*
The :doc:`audit-trail` records the real reason.

.. warning::
   With directory sign-in on and **Allow local user fallback** off, a broken
   directory, a wrong group setting or an empty Admins group locks everyone
   out, every admin included. Use **Run Sign-in Test** before relying on the
   directory, and see `Getting back in`_ below.

.. figure:: /_static/screenshots/admin/auth-settings.png
   :alt: The Authentication Method panel with LDAP selected, and the Allow local user fallback checkbox outlined.

   The Authentication Method panel, with **Allow local user fallback**
   outlined.

Choosing a method, or ticking or clearing **Allow local user fallback**,
saves at once. The checkbox changes only the fallback; the method stays as
it is.

Directory settings
--------------------

These appear when **Active Directory** or **LDAP** is chosen. Select **Save
LDAP Configuration** to store them.

Until every required setting is filled in, the page says *"Directory sign-in
is chosen but not fully set up, so everyone signs in with local accounts"*
and lists what is missing. Nothing changes for anyone until then.

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Setting
     - Description
   * - **Server URL** (required)
     - e.g. ``ldaps://dc.example.com`` or ``ldaps://dc.example.com:636``
   * - **Use SSL/TLS (LDAPS)**
     - Only for a URL without ``ldap://`` or ``ldaps://``: connect over TLS.
   * - **Verify SSL certificate**
     - Check the server's certificate. See the warning below.
   * - **Base DN** (required)
     - The top of your directory, e.g. ``dc=example,dc=com``
   * - **Sign-in name pattern** (required)
     - How a typed name becomes a directory sign-in name; ``{username}`` is
       replaced by the typed name.

       - Active Directory: ``{username}@example.com``, the accounts' user
         principal name. It must match each account's ``userPrincipalName``.
       - LDAP: a DN inside the Base DN, e.g.
         ``uid={username},ou=people,dc=example,dc=com``.
   * - **Users group** (required)
     - The DN of the group whose members sign in as Standard users.
   * - **Admins group** (required)
     - The DN of the group whose members sign in as Admins.
   * - **Group attribute** (LDAP only)
     - The attribute on a person's entry that lists their groups, default
       ``memberOf``. The server must provide it (OpenLDAP needs its
       ``memberOf`` overlay).
   * - **Display Name Attribute**, **Email Attribute**
     - Defaults ``displayName`` and ``mail``.
   * - **Connect Timeout (s)**, **Receive Timeout (s)**
     - 1-300 seconds each, default 10.

.. warning::
   **Verify SSL certificate** defaults to on. Turning it off lets an attacker
   on the network read every user's password with a forged certificate.
   Only turn it off to test against a server whose certificate the host does
   not trust yet.

.. note::
   SeqSetup refuses an unencrypted (``ldap://``) connection unless the server
   sets ``SEQSETUP_LDAP_ALLOW_CLEARTEXT=1``; see
   :doc:`/getting-started/deployment`.

Testing
---------

**Run Connection Test** checks that the server answers, and says over which
kind of connection: encrypted with the certificate checked, encrypted
*without* the certificate checked, or **unencrypted**. It checks no
password.

**Run Sign-in Test** signs in as the account you type, exactly as the
sign-in page would, without signing you in as that person. It shows the
name, email, role and which of the two groups matched -- or why the
directory refused. It is rate-limited like the sign-in page.

Before relying on directory sign-in, test once with a member of each group
and with someone in neither.

Getting back in
-----------------

If nobody can sign in -- for example the directory is down or a group is
wrong, and local fallback is off -- someone with access to the server:

1. Runs ``pixi run use-local-sign-in`` (with Docker:
   ``docker compose exec app pixi run use-local-sign-in``). Sign-in becomes
   local only; the directory settings are kept.
2. If no local admin can sign in, runs ``pixi run create-admin`` to make a
   new one (see :doc:`/getting-started/installation`). If an old local admin
   only forgot the password, signs in as the new admin and resets it on
   :doc:`local-users`.
3. Signs in, fixes the directory settings, and runs **Run Sign-in Test**.
4. Chooses **Active Directory** or **LDAP** again.

Group changes
---------------

A change to someone's groups takes effect the next time they sign in. A
sign-in already open keeps its role until it ends (30 minutes unused, or 8
hours at most).

Who can do this
-------------------

Every action on this page, including both tests, requires the **Admin**
role.
