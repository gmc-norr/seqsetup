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
   Templates (templates/*.html)  ← Jinja2 renders HTML via render()
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
- **Templates**: snake_case files, one page per file, page-local partials prefixed
  with ``_`` (``runs/edit.html``, ``runs/_paste_preview.html``)
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

Register the repository in ``src/seqsetup/startup.py``:

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

Routes handle HTTP requests in ``src/seqsetup/routes/`` using FastAPI's
``APIRouter``. See ``src/seqsetup/routes/profiles.py`` for a minimal
reference implementation.

.. code-block:: python

   # src/seqsetup/routes/my_feature.py
   from typing import Annotated

   from fastapi import APIRouter, Depends, Form, Request
   from pydantic import BaseModel
   from starlette.responses import HTMLResponse, Response

   from ..context import AppContext
   from ..models.my_model import MyModel
   from ..templating import render
   from .dependencies import get_ctx

   router = APIRouter(tags=["my-feature"])


   class CreateMyModelForm(BaseModel):
       name: str
       description: str = ""


   @router.get("/my-feature", response_class=HTMLResponse)
   def my_feature_page(request: Request, ctx: AppContext = Depends(get_ctx)):
       """Display the main feature page."""
       return render(request, "my_feature.html", {"items": ctx.my_model_repo.list_all()})


   @router.get("/my-feature/{item_id}", response_class=HTMLResponse)
   def get_item(request: Request, item_id: str, ctx: AppContext = Depends(get_ctx)):
       """Get a specific item."""
       item = ctx.my_model_repo.get_by_id(item_id)
       if not item:
           return Response("Not found", status_code=404)
       return render(request, "my_feature.html", {"item": item}, block_name="item_detail")


   @router.post("/my-feature", response_class=HTMLResponse)
   def create_item(
       request: Request,
       form: Annotated[CreateMyModelForm, Form()],
       ctx: AppContext = Depends(get_ctx),
   ):
       """Create a new item and return the updated list for the HTMX swap."""
       item = MyModel(name=form.name, description=form.description)
       ctx.my_model_repo.save(item)
       return render(
           request, "my_feature.html",
           {"items": ctx.my_model_repo.list_all()}, block_name="item_list",
       )

Register the router in ``src/seqsetup/app.py``:

.. code-block:: python

   from .routes import my_feature

   app.include_router(my_feature.router)

Adding a New Template
~~~~~~~~~~~~~~~~~~~~~~

Pages and fragments are Jinja2 templates in ``src/seqsetup/templates/``. A
page extends the app shell and exposes its HTMX swap target as a
``{% block %}``; the route renders either the full page or just that block
(via ``render(request, template, context, block_name="...")``).

.. code-block:: jinja

   {# src/seqsetup/templates/my_feature.html #}
   {% extends "_app_shell.html" %}
   {% set page_title = "My Feature" %}

   {% block content %}
   <div id="my-feature-page">
     {% block item_list %}
     <div id="item-grid">
       {% if items %}
         {% for item in items %}
           {% include "_item_card.html" %}
         {% endfor %}
       {% else %}
         <p>No items yet.</p>
       {% endif %}
     </div>
     {% endblock %}
   </div>
   {% endblock %}

.. code-block:: jinja

   {# src/seqsetup/templates/_item_card.html #}
   <div id="item-{{ item.id }}" class="item-card">
     <h3>{{ item.name }}</h3>
     {% if item.description %}<p>{{ item.description }}</p>{% endif %}
     <div class="item-actions">
       <button class="btn-secondary"
               hx-get="/my-feature/{{ item.id }}/edit"
               hx-target="#item-{{ item.id }}">Edit</button>
       <button class="btn-danger"
               hx-delete="/my-feature/{{ item.id }}"
               hx-target="#item-grid"
               hx-confirm="Are you sure?">Delete</button>
     </div>
   </div>

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
essential for frontend work. HTMX attributes are hyphenated (``hx-post``,
not ``hx_post``) since they are written directly in Jinja2 templates.

Basic HTMX Attributes
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: html

   <!-- GET request, replace target content -->
   <button hx-get="/items?page=2"
           hx-target="#item-list"
           hx-swap="beforeend">Load More</button>

   <!-- POST request with form data -->
   <form hx-post="/items" hx-target="#item-list" hx-swap="outerHTML">
     <input name="name" type="text">
     <button type="submit">Save</button>
   </form>

   <!-- DELETE with confirmation -->
   <button hx-delete="/items/{{ item.id }}"
           hx-target="#item-{{ item.id }}"
           hx-swap="outerHTML"
           hx-confirm="Delete this item?">Delete</button>

Out-of-Band Swaps
~~~~~~~~~~~~~~~~~

Update multiple page elements from a single response by rendering a
fragment that includes an out-of-band element alongside the primary swap:

.. code-block:: jinja

   {# Primary response (replaces hx-target) #}
   {% block item_list %}...{% endblock %}

   {# Out-of-band update (updates element with matching id) #}
   <div id="item-count" hx-swap-oob="true">{{ items | length }} items</div>

Triggering Events
~~~~~~~~~~~~~~~~~

.. code-block:: html

   <!-- Trigger HTMX request from JavaScript -->
   <button onclick="htmx.trigger('#my-form', 'submit')">Apply</button>

.. code-block:: javascript

   // In JavaScript (static/js/app.js or a component under static/js/components/)
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

Test repository operations against a mongomock-backed database (no real
MongoDB connection required):

.. code-block:: python

   # tests/integration/test_my_model_repo.py
   import pytest
   from seqsetup.models.my_model import MyModel
   from seqsetup.repositories.my_model_repo import MyModelRepository


   @pytest.fixture
   def repo(isolated_mongo):
       """Create a repository against the isolated mongomock database."""
       return MyModelRepository(isolated_mongo)


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

1. Create a route module in ``src/seqsetup/routes/admin/`` (router-level
   ``dependencies=[Depends(require_admin_dep)]``)
2. Create a template in ``src/seqsetup/templates/admin/``
3. Add a navigation link in ``src/seqsetup/templates/_app_shell.html``
4. Add documentation in ``docs/admin-guide/``

Adding a New API Endpoint
~~~~~~~~~~~~~~~~~~~~~~~~~

The JSON API lives in ``src/seqsetup/api/`` (FastAPI sub-app mounted at
``/api`` by ``seqsetup.app``). The OpenAPI schema is auto-generated from
the route signatures and Pydantic response models — there's no separate
spec file to maintain.

1. Define a Pydantic response model in ``src/seqsetup/api/schemas.py`` if
   the endpoint returns a JSON shape (skip for CSV/PDF/raw responses).
2. Add the route to ``src/seqsetup/api/app.py``. Declare ``response_model``
   so it shows up in the auto-OpenAPI; include ``responses={...}`` for
   non-200 statuses (at least 401, 403, 404, 429 as appropriate).
3. Add ``token: AuthToken`` to the handler signature — this requires
   Bearer auth and applies the per-IP rate limit before bcrypt.
4. Convert domain dataclasses to the Pydantic response model at the
   boundary (see ``_run_summary`` for the pattern). Do not let Pydantic
   models leak into ``seqsetup.models``.
5. Emit an audit event via ``audit("api.run.read", actor=api_actor(token),
   target=run_id, resource="...")`` so the access is in the log.
6. Document in ``docs/api-reference/runs.rst``. The auto-generated Swagger
   UI at ``/api/docs`` is the runtime source of truth, but the Sphinx
   reference is still what readers find via search.

Adding CSS Styles
~~~~~~~~~~~~~~~~~

``src/seqsetup/static/css/app.css`` is a generated build artifact (from
``pixi run css``) -- never edit it directly or commit it. Add Tailwind
utility classes inline in templates, or shared component-level styles to
``src/seqsetup/static/css/components.css`` (imported, alongside Tailwind
itself, by ``static/css/input.css``). Follow existing patterns:

- Use semantic class names (``sample-table``, not ``table1``)
- Group related styles together
- Add comments for complex sections
- Use CSS custom properties for colors/spacing where appropriate

Adding JavaScript
~~~~~~~~~~~~~~~~~

Add to ``src/seqsetup/static/js/app.js``, or a new self-contained component
module under ``src/seqsetup/static/js/components/`` for an Alpine component
(registered via ``Alpine.data(...)`` on ``alpine:init``). Keep JavaScript
minimal:

- Only use JS for interactions that can't be done with HTMX
- Use Alpine for UI-only state (selection, drag-over highlights, modal
  open/closed); the server stays the source of truth for domain data
- Document functions with comments
- HTMX and Alpine are vendored in ``static/js/vendor/``, not installed via
  a package manager

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
