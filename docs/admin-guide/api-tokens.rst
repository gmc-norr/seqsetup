API Tokens
==========

API tokens let an external system authenticate to SeqSetup's read-only JSON
API without a user login. Manage them from **Admin > API Tokens**.

Creating a token
------------------

Fill in the **Create New Token** form:

- **Token Name** -- a descriptive name so you can tell tokens apart later
  (for example, which integration it belongs to).
- **Expires in (days)** -- default 90, maximum 730 (about two years). Set 0
  for a token that never expires -- discouraged, since a leaked token then
  has indefinite access.

Select **Create Token**.

.. figure:: /_static/screenshots/admin/api-tokens.png
   :alt: The Create New Token form, filled in with a name and the default 90-day expiry, with the Create Token button outlined.

   The **Create New Token** form, with **Create Token** outlined.

.. figure:: /_static/screenshots/admin/api-token-created.png
   :alt: The Token Created panel, showing a freshly generated plaintext token value that is only ever displayed at this moment.

   The **Token Created** panel, right after creating a token.

.. warning::
   The plaintext token is shown **exactly once**, in the panel above,
   immediately after you select **Create Token**. SeqSetup stores only a
   bcrypt hash of it -- if you navigate away, refresh the page, or simply
   lose the value, there is no way to recover it. The only option at that
   point is to revoke the token (below) and create a new one.

What a token can reach
--------------------------

A token can only call ``/api/*`` endpoints, with an
``Authorization: Bearer <token>`` header. That API is read-only: it can
list runs that are **Ready** or **Archived** and fetch their already
generated Sample Sheet (v2 and v1), JSON, and validation exports. Draft
runs are never exposed through it, and there is no endpoint a token can
call to create, edit, or delete anything.

Revoking a token
--------------------

Select **Revoke** on a token's row and confirm. This is immediate and
permanent -- there is no way to un-revoke a token. Any client still using it
gets an "Invalid Bearer token" error on its next request.

Expiry
---------

The token list shows each token's expiry date, or ``never``. A token within
7 days of expiring is marked **(expires soon)**; once past its expiry date
it is marked **(EXPIRED)**. An expired token is rejected the same as an
invalid one -- it must be revoked and replaced, it cannot be renewed.

Who can do this
-------------------

Every action on this page requires the **Admin** role. A revoked or expired
token itself carries no role of its own beyond what the read-only API
allows.
