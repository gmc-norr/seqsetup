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
   cd sequencing_run_setup

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

   Default development credentials (defined in ``config/users.yaml``):

   ============ ============= ==========
   Username     Password      Role
   ============ ============= ==========
   ``admin``    ``admin123``  Admin
   ``user``     ``user123``   Standard
   ============ ============= ==========

   .. warning::

      These credentials are for development only. See :doc:`configuration` for
      instructions on disabling default credentials in production.
