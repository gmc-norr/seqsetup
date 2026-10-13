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

- **python** >= 3.14
- **fastapi** -- Web framework
- **jinja2-fragments** -- Server-side HTML templating
- **pymongo** -- MongoDB driver
- **bcrypt** -- Password hashing
- **ldap3** -- LDAP/AD integration
- **pyyaml** -- YAML configuration parsing
- **packaging** -- Version parsing (PEP 440)
- **python-multipart** -- File upload handling

Development dependencies live in the ``dev`` feature and environment, not in
the default one the Dockerfile installs (``pixi install --locked --environment
default``), so none of them is in the image that runs in the lab:

- **pytest** -- Test framework
- **pytest-playwright** -- Browser tests
- **mongomock** -- In-memory MongoDB for tests
- **httpx2** -- The test client Starlette's ``TestClient`` uses
- **sphinx** -- Documentation generator
- **furo** -- Documentation theme

``pixi install`` installs the default environment alone; ``pixi install --all``
adds the ``dev`` one, and a task that needs it (``pixi run test``,
``pixi run docs``, ``pixi run smoke-browser``) installs it on its own.

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
