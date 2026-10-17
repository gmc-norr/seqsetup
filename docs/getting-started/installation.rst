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

The two containers read two things from this checkout, each as a user of its
own rather than as you: the database container reads
``docker/mongo-init.sh``, and the application container reads ``config/``.
On a server that keeps new files from other users -- ``umask`` prints
``0007``, ``0027`` or ``0077``, as on many hardened servers -- a fresh clone
cannot be read by other users, and the first start then goes wrong: MongoDB
is set up without SeqSetup's database user, and SeqSetup loads no
instruments. Make the two readable before the first start, and again after
each update of the checkout, since a ``git pull`` writes its files the same
way. Neither holds a secret (the passwords go in ``.env`` and ``.env.db``,
below):

.. code-block:: bash

   chmod o+r docker/mongo-init.sh
   chmod -R o+rX config

``docker-compose.yml`` will not start without a ``.env`` file in the same
directory -- four settings have no default, and Compose aborts immediately
if any of them is unset -- nor without a ``.env.db`` file, which holds the
MongoDB root password. They are two files because the application container
reads the whole of ``.env``, and it never needs the root password.

1. Copy both templates and open them in an editor:

   .. code-block:: bash

      cp .env.example .env
      cp .env.db.example .env.db
      chmod 600 .env .env.db

   The two will hold passwords. ``chmod 600`` keeps them to you: on a server
   whose ``umask`` is ``0007`` or ``0027``, a copy can be read by your group
   too.

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
      * - ``MONGO_APP_USER`` / ``MONGO_APP_PASSWORD``
        - The credentials SeqSetup itself uses to read and write its
          database, created automatically on first start by
          ``docker/mongo-init.sh``. The template pre-fills the username
          (``seqsetup_app``); the password has no default and must be set.
          Generate it with ``openssl rand -hex 24``: the application's
          connection URI carries this password, and a URI cannot carry
          ``: / ? # @ [ ]`` or a space unencoded -- and reads ``%`` followed
          by two hex digits as an encoded character, so such a password would
          be sent as something else. Compose cannot encode it for you.
      * - ``MONGO_INITDB_ROOT_USERNAME`` /
          ``MONGO_INITDB_ROOT_PASSWORD`` (in ``.env.db``)
        - Root credentials for the MongoDB container itself, used only for
          admin tasks and to create the user above. The template pre-fills
          the username (``root``); the password has no default and must be
          set. Any character is safe here -- it never goes into a URI.

   .. warning::
      Choose strong, unique values for both passwords and for the session
      secret -- do not reuse a value from another system. ``.env`` and
      ``.env.db`` are both gitignored; never commit either.

3. Start the application and MongoDB:

   .. code-block:: bash

      docker compose up --build

The application will be available at ``http://localhost:5001``.

No admin account exists yet at this point -- see
:ref:`docker-admin-bootstrap` below before you try to log in.

.. note::
   If the first start stops with ``dependency failed to start: container
   ... mongodb ... is unhealthy``, and ``docker compose logs mongodb`` shows
   ``mongo-init.sh: Permission denied``, the ``chmod`` above was missed.
   MongoDB sets itself up once, on its first start, so making the file
   readable now is not enough: the database has to be set up again. On a
   first install nothing is stored in it yet, so remove it and start again:

   .. code-block:: bash

      chmod o+r docker/mongo-init.sh
      chmod -R o+rX config
      docker compose down -v
      docker compose up --build -d

   .. warning::
      ``docker compose down -v`` deletes the database and every run in it.
      Use it only on a first install.

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

   The application starts at ``http://localhost:5001``. It listens on every
   network interface of this computer, so on a shared network other machines
   can reach it too; use a firewall, or the Docker setup in
   :doc:`deployment`, which opens the port only on the server itself.

   The first run downloads Tailwind CSS, which builds the stylesheet. The
   download is checked against the SHA-256 pinned in
   ``tools/tailwind-sha256.txt``; a file that does not match is not installed,
   and the start stops.

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
