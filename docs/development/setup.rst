Development Setup
=================

Environment Management
----------------------

SeqSetup uses `Pixi <https://pixi.sh>`_ for environment and dependency management.

.. code-block:: bash

   # Install dependencies
   pixi install

   # Start the development server
   pixi run serve

   # Run the test suite
   pixi run test

   # Build documentation
   pixi run docs

Dependencies
------------

Runtime dependencies are defined in ``pixi.toml``:

- **python** >= 3.12
- **python-fasthtml** -- Web framework
- **pymongo** -- MongoDB driver
- **bcrypt** -- Password hashing
- **ldap3** -- LDAP/AD integration
- **pyyaml** -- YAML configuration parsing
- **packaging** -- Version parsing (PEP 440)
- **python-multipart** -- File upload handling

Development dependencies:

- **pytest** -- Test framework
- **sphinx** -- Documentation generator
- **sphinx-rtd-theme** -- ReadTheDocs theme

Running Tests
-------------

.. code-block:: bash

   pixi run test

Tests are located in the ``tests/`` directory:

- ``tests/unit/`` -- Unit tests for models, services, and utilities
- ``tests/integration/`` -- Integration tests (require MongoDB)
- ``tests/conftest.py`` -- Shared fixtures

Building Documentation
----------------------

.. code-block:: bash

   pixi run docs

This generates HTML documentation in ``docs/_build/html/``. Open
``docs/_build/html/index.html`` in a browser to preview.

MongoDB for Development
-----------------------

A local MongoDB instance is required for development. The default connection is
``mongodb://localhost:27017`` with database ``seqsetup``.

Alternatively, use Docker Compose to start both the application and MongoDB:

.. code-block:: bash

   docker compose up --build
