Contributing Guide
==================

This guide covers everything you need to know to contribute to SeqSetup
development. Whether you're fixing bugs, adding features, or improving
documentation, this document will help you understand the codebase and
follow established patterns.

Prerequisites
-------------

Before starting development, ensure you have:

1. **Pixi** installed (https://pixi.sh) for environment management
2. **MongoDB** running locally (or Docker for containerized development)
3. **Git** for version control
4. A code editor with Python support (VS Code recommended)

Getting Started
---------------

.. code-block:: bash

   # Clone the repository
   git clone <repository-url>
   cd seqsetup

   # Install dependencies
   pixi install

   # Start MongoDB (if not using Docker)
   # Ensure MongoDB is running on localhost:27017

   # Start the development server
   pixi run serve

   # In another terminal, run tests to verify setup
   pixi run test

The application will be available at http://localhost:5001.

Development Workflow
--------------------

1. **Create a feature branch** from ``main``
2. **Make changes** following the patterns described below
3. **Write tests** for new functionality
4. **Run the test suite** to ensure nothing is broken
5. **Update documentation** if adding user-facing features
6. **Submit a pull request** with a clear description

Understanding the Architecture
------------------------------

SeqSetup follows a layered architecture. Understanding these layers is
essential for making changes in the right place.

**Request Flow**::

   Browser Request
        ↓
   Routes (routes/*.py)      ← Handle HTTP, coordinate layers
        ↓
   Services (services/*.py)  ← Business logic, calculations
        ↓
   Repositories (repositories/*.py)  ← Database access
        ↓
   Models (models/*.py)      ← Data structures
        ↓
   MongoDB

**Response Flow**::

   Routes
        ↓
   Components (components/*.py)  ← Generate HTML
        ↓
   HTMX swaps HTML into page

See :doc:`/architecture/technology-stack` for the full technology stack and
:doc:`project-structure` for directory layout.

Code Conventions
----------------

Python Style
~~~~~~~~~~~~

- Follow PEP 8 with a line length of 100 characters
- Use type hints for function signatures
- Write docstrings for public functions and classes
- Use dataclasses for model definitions

.. code-block:: python

   def calculate_override_cycles(
       run_cycles: RunCycles,
       index1_length: int,
       index2_length: int,
   ) -> str:
       """
       Calculate the override cycles string for BCL Convert.

       Args:
           run_cycles: The run cycle configuration
           index1_length: Length of the i7 index sequence
           index2_length: Length of the i5 index sequence

       Returns:
           Override cycles string (e.g., "Y151;I8N2;I8N2;Y151")
       """
       ...

Naming Conventions
~~~~~~~~~~~~~~~~~~

- **Models**: PascalCase singular (``Sample``, ``IndexKit``, ``SequencingRun``)
- **Repositories**: PascalCase with ``Repository`` suffix (``SampleRepository``)
- **Services**: PascalCase with ``Service`` suffix or descriptive name (``AuthService``, ``CycleCalculator``)
- **Routes**: snake_case functions (``get_sample``, ``update_run``)
- **Components**: PascalCase functions returning HTML (``SampleTable``, ``IndexCard``)
- **CSS classes**: kebab-case (``sample-table``, ``index-card``)

Adding New Features
-------------------

Adding a New Model
~~~~~~~~~~~~~~~~~~

Models are Python dataclasses in ``src/seqsetup/models/``.

.. code-block:: python

   # src/seqsetup/models/my_model.py
   from dataclasses import dataclass, field
   from typing import Optional
   import uuid


   @dataclass
   class MyModel:
       """Description of what this model represents."""

       id: str = field(default_factory=lambda: str(uuid.uuid4()))
       name: str = ""
       description: str = ""
       created_at: Optional[str] = None

       def to_dict(self) -> dict:
           """Convert to dictionary for MongoDB storage."""
           return {
               "id": self.id,
               "name": self.name,
               "description": self.description,
               "created_at": self.created_at,
           }

       @classmethod
       def from_dict(cls, data: dict) -> "MyModel":
           """Create from dictionary (MongoDB document)."""
           return cls(
               id=data["id"],
               name=data.get("name", ""),
               description=data.get("description", ""),
               created_at=data.get("created_at"),
           )

Key points:

- Always implement ``to_dict()`` and ``from_dict()`` for MongoDB serialization
- Use ``field(default_factory=...)`` for mutable defaults (lists, dicts)
- Generate UUIDs for ``id`` fields by default
- Handle missing fields gracefully in ``from_dict()`` with ``.get()``

Adding a New Repository
~~~~~~~~~~~~~~~~~~~~~~~

Repositories handle database operations in ``src/seqsetup/repositories/``.

.. code-block:: python

   # src/seqsetup/repositories/my_model_repo.py
   from pymongo.database import Database

   from ..models.my_model import MyModel


   class MyModelRepository:
       """Repository for MyModel documents."""

       def __init__(self, db: Database):
           self.collection = db["my_models"]

       def get_by_id(self, model_id: str) -> MyModel | None:
           """Get a model by ID."""
           doc = self.collection.find_one({"id": model_id})
           return MyModel.from_dict(doc) if doc else None

       def list_all(self) -> list[MyModel]:
           """Get all models."""
           return [MyModel.from_dict(doc) for doc in self.collection.find()]

       def save(self, model: MyModel) -> None:
           """Save or update a model."""
           self.collection.update_one(
               {"id": model.id},
               {"$set": model.to_dict()},
               upsert=True,
           )

       def delete(self, model_id: str) -> bool:
           """Delete a model by ID."""
           result = self.collection.delete_one({"id": model_id})
           return result.deleted_count > 0

Register the repository in ``src/seqsetup/app.py``:

.. code-block:: python

   # Add to _REPO_REGISTRY
   _REPO_REGISTRY = {
       ...
       "my_model": MyModelRepository,
   }

   # Add getter function
   def get_my_model_repo() -> MyModelRepository:
       return _get_repo("my_model")

Adding a New Route
~~~~~~~~~~~~~~~~~~

Routes handle HTTP requests in ``src/seqsetup/routes/``.

.. code-block:: python

   # src/seqsetup/routes/my_feature.py
   from fasthtml.common import *

   from ..context import AppContext
   from ..components.my_component import MyComponent
   from ..models.my_model import MyModel


   def register(app, rt, ctx: AppContext):
       """Register routes for this feature."""

       @rt("/my-feature")
       def get_my_feature(req):
           """Display the main feature page."""
           items = ctx.my_model_repo.list_all()
           return MyComponent(items)

       @rt("/my-feature/{item_id}")
       def get_item(req, item_id: str):
           """Get a specific item."""
           item = ctx.my_model_repo.get_by_id(item_id)
           if not item:
               return Response("Not found", status_code=404)
           return ItemDetail(item)

       @rt("/my-feature", methods=["POST"])
       def create_item(req, name: str, description: str = ""):
           """Create a new item."""
           item = MyModel(name=name, description=description)
           ctx.my_model_repo.save(item)
           # Return updated list for HTMX swap
           return MyComponent(ctx.my_model_repo.list_all())

Register the route module in ``src/seqsetup/app.py``:

.. code-block:: python

   from .routes import my_feature

   # In the route registration section:
   my_feature.register(app, rt, ctx)

Adding a New Component
~~~~~~~~~~~~~~~~~~~~~~

Components generate HTML in ``src/seqsetup/components/``.

.. code-block:: python

   # src/seqsetup/components/my_component.py
   from fasthtml.common import *

   from ..models.my_model import MyModel


   def MyComponent(items: list[MyModel]):
       """Render a list of items."""
       return Div(
           H2("My Items"),
           Div(
               *[ItemCard(item) for item in items],
               cls="item-grid",
           ) if items else P("No items yet."),
           id="my-component",
       )


   def ItemCard(item: MyModel):
       """Render a single item card."""
       return Div(
           H3(item.name),
           P(item.description) if item.description else None,
           Div(
               Button(
                   "Edit",
                   hx_get=f"/my-feature/{item.id}/edit",
                   hx_target=f"#item-{item.id}",
                   cls="btn-secondary",
               ),
               Button(
                   "Delete",
                   hx_delete=f"/my-feature/{item.id}",
                   hx_target="#my-component",
                   hx_confirm="Are you sure?",
                   cls="btn-danger",
               ),
               cls="item-actions",
           ),
           id=f"item-{item.id}",
           cls="item-card",
       )

Adding a New Service
~~~~~~~~~~~~~~~~~~~~

Services contain business logic in ``src/seqsetup/services/``.

.. code-block:: python

   # src/seqsetup/services/my_service.py
   from ..models.my_model import MyModel


   class MyService:
       """Business logic for MyModel operations."""

       @staticmethod
       def validate(model: MyModel) -> list[str]:
           """
           Validate a model.

           Returns:
               List of validation error messages (empty if valid)
           """
           errors = []
           if not model.name:
               errors.append("Name is required")
           if len(model.name) > 100:
               errors.append("Name must be 100 characters or less")
           return errors

       @staticmethod
       def process(model: MyModel) -> MyModel:
           """Process a model (example transformation)."""
           # Services are stateless - they take input and return output
           model.name = model.name.strip()
           return model

Services should be:

- **Stateless**: No instance variables, use ``@staticmethod`` or ``@classmethod``
- **Focused**: Each service handles one area of business logic
- **Testable**: Easy to unit test without database or HTTP dependencies

HTMX Patterns
-------------

SeqSetup uses HTMX for dynamic updates. Understanding these patterns is
essential for frontend work.

Basic HTMX Attributes
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   # GET request, replace target content
   Button(
       "Load More",
       hx_get="/items?page=2",
       hx_target="#item-list",
       hx_swap="beforeend",  # Append to existing content
   )

   # POST request with form data
   Form(
       Input(name="name", type="text"),
       Button("Save", type="submit"),
       hx_post="/items",
       hx_target="#item-list",
       hx_swap="outerHTML",
   )

   # DELETE with confirmation
   Button(
       "Delete",
       hx_delete=f"/items/{item_id}",
       hx_target=f"#item-{item_id}",
       hx_swap="outerHTML",
       hx_confirm="Delete this item?",
   )

Out-of-Band Swaps
~~~~~~~~~~~~~~~~~

Update multiple page elements from a single response:

.. code-block:: python

   # In route handler
   @rt("/items/{item_id}", methods=["DELETE"])
   def delete_item(req, item_id: str):
       ctx.repo.delete(item_id)
       items = ctx.repo.list_all()
       return (
           # Primary response (replaces hx-target)
           ItemList(items),
           # Out-of-band update (updates element with matching id)
           Div(f"{len(items)} items", id="item-count", hx_swap_oob="true"),
       )

Triggering Events
~~~~~~~~~~~~~~~~~

.. code-block:: python

   # Trigger HTMX request from JavaScript
   Button(
       "Apply",
       onclick="htmx.trigger('#my-form', 'submit')",
   )

   # In JavaScript (app.js)
   htmx.ajax('POST', '/endpoint', {
       target: '#target-element',
       swap: 'outerHTML',
       values: { key: 'value' }
   });

Writing Tests
-------------

Tests are in the ``tests/`` directory, organized by type.

Unit Tests
~~~~~~~~~~

Test models, services, and utilities without database dependencies:

.. code-block:: python

   # tests/unit/test_my_service.py
   import pytest
   from seqsetup.models.my_model import MyModel
   from seqsetup.services.my_service import MyService


   class TestMyService:
       def test_validate_empty_name(self):
           model = MyModel(name="")
           errors = MyService.validate(model)
           assert "Name is required" in errors

       def test_validate_valid_model(self):
           model = MyModel(name="Valid Name")
           errors = MyService.validate(model)
           assert errors == []

       def test_process_strips_whitespace(self):
           model = MyModel(name="  test  ")
           result = MyService.process(model)
           assert result.name == "test"

Integration Tests
~~~~~~~~~~~~~~~~~

Test repository operations with a real MongoDB connection:

.. code-block:: python

   # tests/integration/test_my_model_repo.py
   import pytest
   from seqsetup.models.my_model import MyModel
   from seqsetup.repositories.my_model_repo import MyModelRepository


   @pytest.fixture
   def repo(test_db):
       """Create a repository with test database."""
       return MyModelRepository(test_db)


   class TestMyModelRepository:
       def test_save_and_retrieve(self, repo):
           model = MyModel(name="Test")
           repo.save(model)

           retrieved = repo.get_by_id(model.id)
           assert retrieved is not None
           assert retrieved.name == "Test"

       def test_delete(self, repo):
           model = MyModel(name="To Delete")
           repo.save(model)

           assert repo.delete(model.id) is True
           assert repo.get_by_id(model.id) is None

Running Tests
~~~~~~~~~~~~~

.. code-block:: bash

   # Run all tests
   pixi run test

   # Run specific test file
   pixi run test tests/unit/test_my_service.py

   # Run with verbose output
   pixi run test -v

   # Run tests matching a pattern
   pixi run test -k "test_validate"

Documentation
-------------

Documentation is written in reStructuredText and built with Sphinx.

Adding Documentation
~~~~~~~~~~~~~~~~~~~~

1. Create a new ``.rst`` file in the appropriate ``docs/`` subdirectory
2. Add it to the relevant ``index.rst`` toctree
3. Build and preview locally

.. code-block:: bash

   # Build documentation
   pixi run docs

   # Open in browser
   open docs/_build/html/index.html

Documentation Structure
~~~~~~~~~~~~~~~~~~~~~~~

- ``docs/getting-started/`` -- Installation and configuration
- ``docs/user-guide/`` -- End-user documentation
- ``docs/admin-guide/`` -- Administrator documentation
- ``docs/api-reference/`` -- API endpoint documentation
- ``docs/architecture/`` -- Technical architecture
- ``docs/development/`` -- Developer documentation

Common Tasks
------------

Adding a New Admin Page
~~~~~~~~~~~~~~~~~~~~~~~

1. Create route in ``src/seqsetup/routes/admin.py`` or new file
2. Create component in ``src/seqsetup/components/``
3. Add navigation link in ``src/seqsetup/components/layout.py``
4. Add documentation in ``docs/admin-guide/``

Adding a New API Endpoint
~~~~~~~~~~~~~~~~~~~~~~~~~

1. Add route in ``src/seqsetup/routes/api.py``
2. Implement Bearer token authentication check
3. Return JSON responses using ``JSONResponse``
4. Document in ``docs/api-reference/runs.rst`` or appropriate file
5. Add to OpenAPI spec if applicable

Adding CSS Styles
~~~~~~~~~~~~~~~~~

Add styles to ``src/seqsetup/static/css/app.css``. Follow existing patterns:

- Use semantic class names (``sample-table``, not ``table1``)
- Group related styles together
- Add comments for complex sections
- Use CSS custom properties for colors/spacing where appropriate

Adding JavaScript
~~~~~~~~~~~~~~~~~

Add to ``src/seqsetup/static/js/app.js``. Keep JavaScript minimal:

- Only use JS for interactions that can't be done with HTMX
- Document functions with comments
- Use vanilla JavaScript (no frameworks)

Debugging Tips
--------------

Server Logs
~~~~~~~~~~~

The development server prints requests and errors to the console. Watch for:

- HTTP 500 errors with stack traces
- Database connection issues
- Authentication failures

Browser Developer Tools
~~~~~~~~~~~~~~~~~~~~~~~

- **Network tab**: Inspect HTMX requests and responses
- **Console**: Check for JavaScript errors
- **Elements**: Verify HTML structure after HTMX swaps

MongoDB Queries
~~~~~~~~~~~~~~~

Use MongoDB Compass or ``mongosh`` to inspect data:

.. code-block:: bash

   mongosh seqsetup
   db.runs.find().pretty()
   db.index_kits.find({ name: /IDT/ })

Common Issues
~~~~~~~~~~~~~

**HTMX not updating**: Check that the target element ID matches and exists
in the DOM.

**Form data not received**: Ensure form inputs have ``name`` attributes and
the form has the correct ``hx-post`` or method.

**Authentication redirect loop**: Check that the route is not in
``PUBLIC_ROUTES`` if it should require login.

**MongoDB connection error**: Verify MongoDB is running and the connection
URI in ``config/mongodb.yaml`` or ``MONGODB_URI`` environment variable is
correct.

Questions?
----------

If you have questions about contributing:

1. Check existing code for similar patterns
2. Read the architecture documentation
3. Look at recent commits for examples
4. Open an issue for discussion
