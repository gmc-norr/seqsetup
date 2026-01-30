API Tokens
==========

API tokens provide programmatic access to SeqSetup's API endpoints using Bearer
authentication.

Creating Tokens
---------------

Administrators can create API tokens through the admin interface. Each token has:

- **Name** -- A descriptive name for the token
- **Created by** -- The admin user who created it

When a token is created, the plaintext value is displayed once. Only the bcrypt hash
is stored in the database. The plaintext token cannot be retrieved after creation.

Using Tokens
------------

Include the token in API requests using the ``Authorization`` header::

   Authorization: Bearer <token>

Managing Tokens
---------------

Existing tokens can be viewed (name and creation date) and deleted through the admin
interface. Token values cannot be regenerated; create a new token instead.
