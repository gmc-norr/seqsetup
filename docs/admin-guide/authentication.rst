Authentication Settings
=========================

SeqSetup supports three ways to authenticate a login, configured from
**Admin > Authentication**: **Local Authentication**, **Active Directory**,
and **LDAP**.

How a login is actually checked
---------------------------------

1. If the Authentication Method is **Active Directory** or **LDAP**, *and*
   the connection settings have been saved with both a **Server URL** and a
   **Base DN**, SeqSetup tries an LDAP bind first.

   - If it succeeds, the user is logged in with the role their LDAP group
     membership maps to.
   - If it fails and **Allow local user fallback** is on, SeqSetup falls
     through to local authentication (below).
   - If it fails and fallback is off, the login is refused outright --
     local accounts are not tried at all.

2. Local authentication -- used directly when the Authentication Method is
   **Local Authentication**, and as the fallback above -- checks the local
   user database first, then the ``config/users.yaml`` file, and logs the
   user in on the first matching username *and* password it finds. If the
   username exists in the local database but the password given does not
   match, SeqSetup does not fail immediately -- it also checks
   ``config/users.yaml`` for a user of the same name before finally
   refusing the login.

.. note::
   Selecting **Active Directory** or **LDAP** only reveals the connection
   settings below -- it does not turn LDAP authentication on by itself.
   LDAP is only actually used once the connection settings have also been
   saved with a **Server URL** and a **Base DN** filled in.

.. warning::
   Enabling LDAP/Active Directory with **Allow local user fallback** turned
   off, before the connection has been confirmed working, can lock every
   account out of SeqSetup -- including every Admin account, since local
   accounts are never tried once fallback is off. Use **Run Connection
   Test** and **Run Auth Test** (below) to confirm LDAP works before
   turning fallback off in production.

.. figure:: /_static/screenshots/admin/auth-settings.png
   :alt: The Authentication Method panel with LDAP selected, and the Allow local user fallback checkbox outlined.

   The Authentication Method panel, with **Allow local user fallback**
   outlined.

Connection settings
---------------------

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Setting
     - Description
   * - **Server URL**
     - e.g. ``ldap://dc.example.com`` or ``ldaps://dc.example.com:636``
   * - **Use SSL/TLS (LDAPS)**
     - Connect over LDAPS instead of plain LDAP
   * - **Verify SSL certificate**
     - Validate the server's certificate. See the warning below.
   * - **Base DN**
     - e.g. ``dc=example,dc=com``

.. warning::
   **Verify SSL certificate** defaults to on. Turning it off lets an
   attacker positioned on the network intercept LDAP credentials -- both
   the bind password below and every user's login password -- with a
   forged certificate. Only disable it for testing against a server whose
   certificate the host does not yet trust.

Bind credentials
~~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Setting
     - Description
   * - **Bind DN**
     - The service account SeqSetup uses to search for users, e.g.
       ``cn=admin,dc=example,dc=com``
   * - **Bind Password**
     - Left blank on save, the existing password is kept -- there is no way
       to blank it out from this form, only replace it.

.. note::
   Set the ``SEQSETUP_LDAP_BIND_PASSWORD`` environment variable on the
   server to supply the bind password instead of storing it in this form.
   When set, it is always used in place of whatever is saved here, so the
   secret never has to live in the database.

User search
~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Setting
     - Description
   * - **User Search Base**
     - e.g. ``ou=users,dc=example,dc=com``
   * - **User Search Filter**
     - Default ``(sAMAccountName={username})``
   * - **User DN Pattern (optional)**
     - If set, used instead of the search filter for a direct bind, e.g.
       ``uid={username},ou=users,dc=example,dc=com``

.. note::
   **User DN Pattern** must contain the literal ``{username}`` placeholder,
   and only accepts letters, digits, ``=``, ``,``, ``-``, ``.``, ``_``,
   spaces and that placeholder. SeqSetup rejects anything else with an
   error, so a value cannot be used to inject LDAP filter syntax.

User attributes
~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Setting
     - Description
   * - **Username Attribute**
     - Default ``sAMAccountName``
   * - **Display Name Attribute**
     - Default ``displayName``
   * - **Email Attribute**
     - Default ``mail``

Group-based roles
~~~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Setting
     - Description
   * - **Admin Group DN**
     - Members of this group get the Admin role
   * - **User Group DN**
     - Members of this group get the Standard role
   * - **Group Membership Attribute**
     - Default ``memberOf``

Timeouts
~~~~~~~~~~

**Connect Timeout (s)** and **Receive Timeout (s)** bound how long SeqSetup
waits on the LDAP server, 1-300 seconds each (default 10).

Select **Save LDAP Configuration** to store these settings.

Testing the connection
-------------------------

**Run Connection Test** checks that the server is reachable and the bind
credentials work, without authenticating as any particular user.

**Run Auth Test** performs a real LDAP bind with a username and password you
supply, so you can confirm a specific account resolves correctly before
relying on it. This is rate-limited the same way the login page itself is,
since it triggers a real credential check against LDAP.

Who can do this
-------------------

Every action on this page, including both tests, requires the **Admin**
role.
