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
