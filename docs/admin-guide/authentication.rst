Authentication Settings
=======================

SeqSetup supports multiple authentication methods that can be configured through
the admin interface.

Authentication Methods
----------------------

**Local**
   Authenticate against users stored in MongoDB (managed through the admin interface)
   and the ``config/users.yaml`` file.

**LDAP**
   Authenticate against an LDAP directory server.

**Active Directory**
   Authenticate against Microsoft Active Directory (uses LDAP protocol with AD-specific
   defaults).

Configuring LDAP/AD
-------------------

Navigate to **Settings > Authentication** in the admin interface to configure LDAP or
Active Directory authentication.

Connection Settings
~~~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Setting
     - Description
   * - **Server URL**
     - LDAP server URL (e.g., ``ldap://dc.example.com`` or ``ldaps://dc.example.com:636``)
   * - **Use SSL**
     - Enable SSL/TLS for the connection
   * - **Verify SSL Certificate**
     - Validate the server's SSL certificate. **Enable this in production** to prevent
       man-in-the-middle attacks. Can be disabled for development with self-signed certificates.
   * - **Base DN**
     - Base distinguished name for searches (e.g., ``DC=example,DC=com``)

Bind Credentials
~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Setting
     - Description
   * - **Bind DN**
     - DN of the service account for searching users
       (e.g., ``CN=SeqSetup,OU=Services,DC=example,DC=com``)
   * - **Bind Password**
     - Password for the service account

User Search
~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Setting
     - Description
   * - **User Search Base**
     - Base DN for user searches (e.g., ``OU=Users,DC=example,DC=com``)
   * - **User Search Filter**
     - LDAP filter for finding users. Use ``{username}`` as a placeholder.
       Default: ``(sAMAccountName={username})``
   * - **Username Attribute**
     - Attribute containing the username (default: ``sAMAccountName``)
   * - **Display Name Attribute**
     - Attribute for display name (default: ``displayName``)
   * - **Email Attribute**
     - Attribute for email (default: ``mail``)

Group-Based Roles
~~~~~~~~~~~~~~~~~

Role assignment is based on LDAP group membership:

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Setting
     - Description
   * - **Admin Group DN**
     - DN of the group whose members get the Admin role
   * - **User Group DN**
     - DN of the group whose members get the Standard User role
   * - **Group Membership Attribute**
     - Attribute listing group memberships (default: ``memberOf``)

SSL Certificate Verification
----------------------------

.. warning::

   **Always enable SSL certificate verification in production environments.**

   With verification disabled, connections are vulnerable to man-in-the-middle attacks
   where an attacker could intercept credentials.

For development with self-signed certificates, you can disable verification. For
production:

1. Use certificates signed by a trusted CA
2. Enable "Verify SSL Certificate" in the LDAP settings
3. Ensure the CA certificate is in the system trust store

Local Fallback
--------------

When LDAP/AD is enabled, you can optionally allow local authentication as a fallback.
This is useful for:

- Emergency access if LDAP is unavailable
- Service accounts that don't exist in the directory

Set **Allow Local Fallback** to ``false`` to enforce LDAP-only authentication.

Testing the Connection
----------------------

Use the "Test Connection" button in the admin interface to verify:

- The server is reachable
- Bind credentials are correct
- User search configuration works

Test authentication with a known user before enabling LDAP for production use.
