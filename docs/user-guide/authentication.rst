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

A wrong username or password redisplays this same page with the message
*"Sign-in failed. Check your name and password, or ask an admin whether you
have access to SeqSetup."*; the fields are not pre-filled. Repeated failed attempts from the
same address, or against the same username, are rate-limited and rejected
with "Too many login attempts. Try again later." until the limit resets.

Authentication is checked in this order:

1. **LDAP/AD**, if directory sign-in is set up.
2. **Local users**, managed through the admin interface and stored in
   MongoDB -- when LDAP/AD is not in use, or it refused and local fallback
   is on.

.. note::
   Every sign-in gets a new ticket and clears anything the browser held
   before, so an old or planted cookie cannot be reused to inherit a
   different user's access.

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

When you sign in, SeqSetup records the login on the server and gives your
browser a random ticket for it, kept in a cookie. Every page you open is
checked against that record, so a login can be ended from the server side.

A login ends when any of these happens:

- **You leave it unused for 30 minutes.** The next thing you open asks you
  to sign in again.
- **8 hours have passed since you signed in**, even if you were working the
  whole time.
- **You sign out.** The sign-out button is in the top-right corner of every
  page, next to your display name. Signing out ends the login on the server
  too, so a copy of the cookie stops working.
- **An administrator deletes your account, or changes your role or
  password.** Every login you have ends at once, in every browser.

An administrator can change the two time limits with
``SEQSETUP_SESSION_IDLE_SECONDS`` and ``SEQSETUP_SESSION_MAX_AGE_SECONDS``
(see :doc:`/getting-started/configuration`).

If your login ended while you were working
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Opening a page takes you to the login page, as usual. But if you were in the
middle of something that saves without leaving the page -- editing a sample,
adding pasted samples, changing cycles -- the page stays where it is, nothing
is saved, and a red message says so:

.. figure:: /_static/screenshots/login/login-ended.png
   :alt: A red message reading "Your login has ended, so this was not saved. What you typed is still on this page. Log in again in a new tab, then try again here.", outlined.

   The message at the top of the page after a login ended, outlined.

What you typed is still on the page. Select **Log in again** -- it opens the
login page in a new tab -- sign in there, come back to this tab, and do the
same thing again. It works the second time.

If signing out itself cannot reach the database, you see *"Logout did not
finish on the server"*. Your browser is signed out anyway, but a copy of the
login may keep working until it times out, so tell your administrator.

.. note::
   Accounts from LDAP/Active Directory are managed outside SeqSetup. If such an account is disabled or removed
   there, SeqSetup does not see it: a login it already has keeps working
   until it ends by one of the time limits above.

The session's signing secret comes from the ``SEQSETUP_SESSION_SECRET``
environment variable when set (the recommended production setup). If it
is not set, SeqSetup falls back to a ``.sesskey`` file at the project
root, generated automatically on first startup.

See :doc:`/admin-guide/authentication` for configuring LDAP/AD and local
users.
