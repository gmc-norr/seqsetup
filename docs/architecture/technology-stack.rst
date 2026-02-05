Technology Stack
================

SeqSetup is built using a hypermedia-driven architecture where the server
renders HTML and dynamic updates are handled via HTML fragments rather than
client-side JavaScript frameworks.

Backend
-------

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Framework
     - Purpose
   * - **FastHTML**
     - Main web framework for server-side HTML generation
   * - **FastAPI**
     - REST API endpoints for programmatic access
   * - **Starlette**
     - Underlying ASGI framework (used by both FastHTML and FastAPI)
   * - **Uvicorn**
     - ASGI server for running the application
   * - **PyMongo**
     - MongoDB driver for database operations
   * - **ldap3**
     - LDAP and Active Directory authentication
   * - **bcrypt**
     - Secure password hashing
   * - **ReportLab**
     - PDF generation for validation reports
   * - **Matplotlib**
     - Charts and plotting for reports
   * - **Sphinx + Furo**
     - Documentation generation

Frontend
--------

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Framework
     - Purpose
   * - **HTMX**
     - Dynamic HTML updates without full page reloads (bundled with FastHTML)
   * - **Vanilla JavaScript**
     - Custom UI interactions (drag-drop, multi-select, bulk operations)

Architecture Approach
---------------------

SeqSetup follows a **hypermedia-driven** approach:

1. **Server-rendered HTML**: FastHTML generates complete HTML on the server,
   eliminating the need for client-side templating or state management.

2. **HTMX for interactivity**: Dynamic updates are handled by HTMX, which
   requests HTML fragments from the server and swaps them into the page.
   This provides a responsive user experience without the complexity of
   a JavaScript framework.

3. **Minimal custom JavaScript**: Client-side JavaScript is used only for
   interactions that genuinely require it, such as:

   - Drag-and-drop index assignment
   - Multi-select with Ctrl/Shift+click
   - Bulk operations on selected samples
   - Client-side filtering of index lists

This architecture offers several benefits:

- **Simplified development**: No separate frontend build process or API design
- **Reduced complexity**: Server maintains all state; no client-side state sync
- **Progressive enhancement**: Core functionality works without JavaScript
- **Smaller payload**: No large JavaScript bundles to download

Database
--------

**MongoDB** is used for all persistent storage:

- Sequencing runs and samples
- Index kit definitions
- User accounts and API tokens
- Application and test profiles
- Authentication configuration

See :doc:`data-models` for details on the data structures.
