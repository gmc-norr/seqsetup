Authentication
==============

All API endpoints require Bearer token authentication. Include the token in
the ``Authorization`` header of each request::

   Authorization: Bearer <token>

API tokens are created and managed through the admin interface. See
:doc:`/admin-guide/api-tokens` for details on creating and managing tokens.

Responses for unauthenticated or invalid requests return HTTP 401.
