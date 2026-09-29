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

``docker-compose.yml`` will not start without a ``.env`` file in the same
directory -- five settings have no default, and Compose aborts immediately
if any of them is unset.

1. Copy the template and open it in an editor:

   .. code-block:: bash

      cp .env.example .env

2. Fill in the required values:

   .. list-table::
      :header-rows: 1
      :widths: 30 70

      * - Variable
        - What it's for
      * - ``SEQSETUP_SESSION_SECRET``
        - Signs the session cookie. Must be at least 32 characters; the app
          refuses to start with a shorter value. The template's own comment
          suggests generating one with Python's ``secrets.token_hex(32)``.
      * - ``MONGO_ROOT_USER`` / ``MONGO_ROOT_PASSWORD``
        - Root credentials for the MongoDB container itself, used only for
          admin tasks. The template pre-fills the username (``root``); the
          password has no default and must be set.
      * - ``MONGO_APP_USER`` / ``MONGO_APP_PASSWORD``
        - The credentials SeqSetup itself uses to read and write its
          database, created automatically on first start by
          ``docker/mongo-init.sh``. The template pre-fills the username
          (``seqsetup_app``); the password has no default and must be set.

   .. warning::
      Choose strong, unique values for both passwords and for the session
      secret -- do not reuse a value from another system. ``.env`` is
      gitignored; never commit it.

3. Start the application and MongoDB:

   .. code-block:: bash

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

The image ships with no account at all. Make the first admin with the
``create-admin`` command, inside the running container:

.. code-block:: bash

   docker compose exec app pixi run create-admin

It asks for a username, a display name, an email address (optional) and
the password twice; the password is not shown as you type. The password
must follow the same rules as on :doc:`/admin-guide/local-users`: at least 8
characters, at most 72 bytes (letters like å, ä and ö count as 2), and not a
well-known weak password such as ``admin123``. The admin is saved in the
database, so no restart is needed.

Then log in at ``http://localhost:5001`` with that username and password,
and create further accounts through :doc:`/admin-guide/local-users`.

``create-admin`` never changes an existing account: if the name is taken,
it stops without changing anything.

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

   No account exists yet, and no credentials are committed to the
   repository. Make the first admin with:

   .. code-block:: bash

      pixi run create-admin

   It asks for a username, a display name, an email address (optional) and
   the password twice (not shown as you type), checks the password against
   the same rules as :doc:`/admin-guide/local-users`, and saves the admin in
   the database. Then log in with that username and password, and create
   further accounts through :doc:`/admin-guide/local-users`.
