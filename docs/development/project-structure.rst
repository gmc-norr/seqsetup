Project Structure
=================

Source Layout
-------------

.. code-block:: text

   seqsetup/
   ├── config/                          # Configuration files
   │   ├── instruments.yaml             # Instrument and flowcell definitions
   │   ├── mongodb.yaml                 # Database connection settings
   │   ├── users.yaml                   # Development user credentials
   │   └── profiles/                    # Application/test profile YAML files
   ├── src/seqsetup/        # Application source code
   │   ├── app.py                       # Application entry point (FastHTML)
   │   ├── components/                  # UI components
   │   ├── data/                        # Static data loaders
   │   ├── models/                      # Data models (dataclasses)
   │   ├── repositories/                # MongoDB data access layer
   │   ├── routes/                      # HTTP route handlers
   │   ├── services/                    # Business logic
   │   └── static/                      # CSS and JavaScript assets
   ├── tests/                           # Test suite
   │   ├── conftest.py                  # Shared fixtures
   │   ├── unit/                        # Unit tests
   │   └── integration/                 # Integration tests
   ├── docs/                            # Sphinx documentation
   ├── Dockerfile                       # Container build
   ├── docker-compose.yml               # Multi-container orchestration
   ├── pixi.toml                        # Project manifest
   └── pixi.lock                        # Locked dependencies

Application Layers
------------------

**Models** (``models/``)
   Python dataclasses defining the data structures. All models support ``to_dict()``
   and ``from_dict()`` for MongoDB serialization. No database or framework
   dependencies.

**Repositories** (``repositories/``)
   MongoDB data access layer. Each repository handles CRUD operations for a specific
   model type. Repositories accept a PyMongo database connection and operate on
   specific collections.

**Services** (``services/``)
   Business logic that operates on models. Services are stateless and typically
   implemented as class methods. Examples: cycle calculation, validation, export,
   authentication.

**Routes** (``routes/``)
   HTTP request handlers using FastHTML. Routes coordinate between services,
   repositories, and components to handle user requests. Each route module covers
   a functional area (samples, indexes, export, auth, admin).

**Components** (``components/``)
   FastHTML UI components that generate HTML responses. Components use HTMX for
   dynamic updates without full page reloads. The wizard component manages the
   multi-step run setup flow.

**Data** (``data/``)
   Static data loaders for configuration files (instruments, chemistry types).
   Reads YAML configuration at startup and provides accessor functions.

Technology Stack
----------------

- **Backend**: Python 3.12+ with FastHTML
- **Frontend**: Server-rendered HTML with HTMX for dynamic interactions
- **Database**: MongoDB with PyMongo driver
- **Authentication**: bcrypt password hashing, LDAP/AD via ldap3
- **Configuration**: YAML files with environment variable overrides
- **Packaging**: Pixi (conda-forge based)
- **Containerization**: Docker with Docker Compose
