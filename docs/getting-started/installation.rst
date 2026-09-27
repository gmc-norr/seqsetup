Installation
============

Prerequisites
-------------

- `Pixi <https://pixi.sh>`_ (for local development)
- `Docker <https://docs.docker.com/get-docker/>`_ and
  `Docker Compose <https://docs.docker.com/compose/>`_ (for containerized deployment)
- MongoDB 7+ (provided automatically by Docker Compose, or installed separately for
  local development)

Docker Compose (Recommended)
----------------------------

Docker Compose is the recommended way to run a fully functional instance.

.. code-block:: bash

   # Clone the repository
   git clone <repository-url>
   cd seqsetup

   # Start the application and MongoDB
   docker compose up --build

The application will be available at ``http://localhost:5001``.

No admin account exists yet at this point -- see
:ref:`docker-admin-bootstrap` below before you try to log in.

To run in the background:

.. code-block:: bash

   docker compose up --build -d

To stop:

.. code-block:: bash

   docker compose down

MongoDB data is persisted in a named Docker volume (``mongo_data``). To remove the
database volume as well:

.. code-block:: bash

   docker compose down -v

.. _docker-admin-bootstrap:

Creating the first admin account (Docker Compose)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The image ships with no admin account: ``config/users.yaml`` starts as
``users: {}`` and nothing seeds it at startup. ``docker-compose.yml`` mounts
your local ``./config`` directory into the container at ``/app/config``
**read-only**, so the file the running app actually reads is the one in
your checkout on the host -- and the container cannot write to it. You
create the account by editing that host file and restarting the container.

1. Generate a bcrypt password hash. The app image already has Pixi and the
   application source on it, so this can be run inside the running
   container without installing anything on the host:

   .. code-block:: bash

      docker compose exec -e PYTHONPATH=src app pixi run python -c "
      import getpass
      from seqsetup.services.auth import AuthService
      print(AuthService.hash_password(getpass.getpass('Password: ')))"

2. On the **host**, add an entry to ``./config/users.yaml`` (the file
   bind-mounted into the container) with that hash:

   .. code-block:: yaml

      users:
        admin:
          display_name: "Administrator"
          email: "admin@example.com"
          password_hash: "$2b$12$..."   # output of step 1
          role: admin

3. Restart the container so it picks up the change. ``users.yaml`` is only
   read once, at process startup, and the mount is read-only, so neither an
   in-place edit nor an in-container write takes effect on its own:

   .. code-block:: bash

      docker compose restart app

4. Log in at ``http://localhost:5001`` with that username and the password
   you chose.

This ``users.yaml`` entry is a file-based fallback account with no
password-strength check of its own -- choose the password carefully. Once
you can log in, create further accounts through
:doc:`/admin-guide/local-users`; those are stored in MongoDB and are
rejected if they are too short or match a list of common weak passwords.
See :doc:`configuration` for how to remove file-based fallback users once
LDAP/AD or MongoDB-managed users are in place.

Local Development Setup
-----------------------

1. **Install Pixi**

   Follow the instructions at `pixi.sh <https://pixi.sh>`_.

2. **Install MongoDB**

   Install and start MongoDB 7+ on your local machine. On Ubuntu/Debian:

   .. code-block:: bash

      # See https://www.mongodb.com/docs/manual/tutorial/install-mongodb-on-ubuntu/
      sudo systemctl start mongod

   By default, SeqSetup connects to ``mongodb://localhost:27017`` with database name
   ``seqsetup``. This can be changed via ``config/mongodb.yaml`` or environment
   variables (see :doc:`configuration`).

3. **Install dependencies**

   .. code-block:: bash

      pixi install

4. **Start the application**

   .. code-block:: bash

      pixi run serve

   The application starts at ``http://localhost:5001``.

5. **Log in**

   ``config/users.yaml`` ships empty (``users: {}``) -- no credentials are
   committed to the repository, so there is no default account to log in
   with. Create a bootstrap admin account before your first login:

   1. Hash a strong, unique password using the project's own hashing
      routine (this prompt does not echo or store what you type):

      .. code-block:: bash

         PYTHONPATH=src pixi run python -c "
         import getpass
         from seqsetup.services.auth import AuthService
         print(AuthService.hash_password(getpass.getpass('Password: ')))"

   2. Add an entry to ``config/users.yaml`` with that hash:

      .. code-block:: yaml

         users:
           admin:
             display_name: "Administrator"
             email: "admin@example.com"
             password_hash: "$2b$12$..."   # output of step 1
             role: admin

   3. Restart the application and log in with that username and the
      password you chose.

   This ``users.yaml`` entry is a file-based fallback account with no
   password-strength check of its own -- choose the password carefully.
   Once you can log in, create further accounts through
   :doc:`/admin-guide/local-users`; those are stored in MongoDB and are
   rejected if they are too short or match a list of common weak
   passwords. See :doc:`configuration` for how to remove file-based
   fallback users once LDAP/AD or MongoDB-managed users are in place.
