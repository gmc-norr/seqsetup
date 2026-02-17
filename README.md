# SeqSetup

A web application for configuring Illumina DNA sequencing runs. SeqSetup manages sample information, index assignment, and validation, and generates Illumina Sample Sheet v2 files and associated metadata for instruments including NovaSeq X, MiSeq i100, NextSeq 1000/2000, and others.

## Prerequisites

- [Pixi](https://pixi.sh) (for local development)
- [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/) (for containerized deployment)
- MongoDB 7+ (provided automatically by Docker Compose, or installed separately for local development)

## Quick Start with Docker Compose

This is the recommended way to run a fully functional instance.

```bash
# Clone the repository
git clone <repository-url>
cd seqsetup

# Start the application and MongoDB
docker compose up --build
```

The application will be available at `http://localhost:5001`.

To run in the background:

```bash
docker compose up --build -d
```

To stop:

```bash
docker compose down
```

MongoDB data is persisted in a named Docker volume (`mongo_data`). To remove the database volume as well:

```bash
docker compose down -v
```

## Local Development Setup

### 1. Install Pixi

Follow the instructions at [pixi.sh](https://pixi.sh) to install the Pixi package manager.

### 2. Install MongoDB

Install and start MongoDB 7+ on your local machine. On Ubuntu/Debian:

```bash
# See https://www.mongodb.com/docs/manual/tutorial/install-mongodb-on-ubuntu/
sudo systemctl start mongod
```

By default, SeqSetup connects to `mongodb://localhost:27017` with database name `seqsetup`. This can be changed via `config/mongodb.yaml` or environment variables (see [Configuration](#configuration)).

### 3. Install dependencies

```bash
pixi install
```

### 4. Start the application

```bash
pixi run serve
```

The application starts at `http://localhost:5001`.

### 5. Log in

Default development credentials (defined in `config/users.yaml`):

| Username | Password  | Role     |
|----------|-----------|----------|
| `admin`  | `admin123`| Admin    |
| `user`   | `user123` | Standard |

**These credentials are for development only.** See [Disabling Default Credentials](#disabling-default-credentials) for production deployments.

## Running Tests

```bash
pixi run test
```

The test suite contains 607 unit tests covering models, services, exporters, validators, and route utilities. Tests run without a database connection.

## Configuration

### Environment Variables

| Variable                    | Description                     | Default                     |
|-----------------------------|---------------------------------|-----------------------------|
| `MONGODB_URI`               | MongoDB connection URI          | `mongodb://localhost:27017` |
| `MONGODB_DATABASE`          | Database name                   | `seqsetup`                  |
| `SEQSETUP_SESSION_SECRET`   | Session encryption key          | Auto-generated in `.sesskey`|
| `INSTRUMENTS_CONFIG`        | Path to instruments YAML config | `config/instruments.yaml`   |

Environment variables take precedence over configuration files.

### Configuration Files

All configuration files are in the `config/` directory:

- **`mongodb.yaml`** -- MongoDB connection settings (URI and database name).
- **`users.yaml`** -- Local user credentials (bcrypt-hashed passwords). Used during development; production deployments should use LDAP/AD.
- **`instruments.yaml`** -- Supported sequencing instruments, flowcell types, reagent kits, SBS chemistry definitions, and default cycle configurations.
- **`profiles/`** -- Application and test profile definitions (can be synced from GitHub).
- **`indexes/`** -- Bundled index kit definitions in CSV and YAML formats.

### Session Key

A session secret key is stored in `.sesskey` at the project root. It is auto-generated on first startup if it does not exist. Keep this file out of version control. For production, set `SEQSETUP_SESSION_SECRET` instead.

### Disabling Default Credentials

The default development users in `config/users.yaml` should not be available in production. The authentication system checks credentials in this order:

1. **LDAP/AD** (if configured and enabled)
2. **Local users in MongoDB** (managed through the admin interface)
3. **`config/users.yaml`** (file-based fallback)

To disable the default credentials, use one or more of the following approaches:

**Remove the YAML users.** Replace the contents of `config/users.yaml` with an empty user list:

```yaml
users: {}
```

This disables all file-based logins while keeping the file in place. MongoDB local users and LDAP authentication continue to work.

**Configure LDAP without local fallback.** Set up LDAP/AD authentication through the admin interface and set `allow_local_fallback` to `false`. This prevents the local authentication path from being reached entirely, meaning neither MongoDB local users nor `users.yaml` will be consulted.

**Restrict the config mount in Docker.** By default, `docker-compose.yml` bind-mounts the entire `config/` directory. You can mount only the files you need and omit `users.yaml`, which causes file-based authentication to fail with no matching users.

## User Authentication and Authorization

### Authentication Methods

Authentication is configured through the admin interface. Supported methods:

1. **Local** -- Users stored in MongoDB or `config/users.yaml`
2. **LDAP** -- LDAP directory server
3. **Active Directory** -- Microsoft AD with LDAP protocol

### User Roles

- **Administrator** -- Full access including index kit management, application/test profiles, local users, API tokens, LDAP configuration, and config sync.
- **Standard User** -- Run setup, sample management, index assignment, validation, and export functions.

## Functional Overview

### Run Workflow

The core workflow is wizard-based:

1. **Create a new run** -- Select instrument platform, flowcell type, reagent kit, and configure cycle counts.
2. **Add samples** -- Paste sample data, upload a file, or import from an external LIMS API (iGene).
3. **Assign indexes** -- Drag-and-drop indexes from uploaded index kits onto samples. Supports unique dual, combinatorial, and single-index modes.
4. **Validate** -- Check for index collisions, color balance issues, and dark cycles. Approve validation.
5. **Mark Ready** -- Locks the run and pre-generates all export files.
6. **Export** -- Download Sample Sheet v2, Sample Sheet v1 (MiSeq), JSON metadata, or validation reports (JSON/PDF).

### Run Status State Machine

Runs follow a strict state machine: **Draft** → **Ready** → **Archived**

| Status   | Editable | API Access | Exports Available |
|----------|----------|------------|-------------------|
| Draft    | Yes      | No         | No                |
| Ready    | No       | Yes        | Yes (pre-generated) |
| Archived | No       | Yes        | Yes (pre-generated) |

- **Draft → Ready** requires validation to be approved (no errors, all samples have indexes). Triggers pre-generation of all export files.
- **Ready → Draft** returns the run to editable state (clears pre-generated exports).
- **Ready → Archived** marks the run as a historical record.
- **Archived** is a terminal state -- no transitions out.

### Export Formats

| Format | Description |
|--------|-------------|
| Sample Sheet v2 | Illumina CSV for NovaSeq X, MiSeq i100, NextSeq 1000/2000. Includes BCLConvert and DRAGEN sections based on application profiles. |
| Sample Sheet v1 | Legacy CSV format for instruments that require it (MiSeq). |
| JSON Metadata | Complete run and sample data including test IDs, indexes, override cycles, and all configuration. |
| Validation Report (JSON) | Machine-readable validation results with error details, distance matrices, and color balance analysis. |
| Validation Report (PDF) | Human-readable validation summary with heatmaps and color balance charts. |

### JSON API

The API provides programmatic access to finalized runs using Bearer token authentication.

**Security**: Only `ready` and `archived` runs are accessible. Draft runs cannot be accessed via API.

| Endpoint | Description |
|----------|-------------|
| `GET /api/runs` | List runs (status=ready\|archived) |
| `GET /api/runs/{id}/samplesheet-v2` | Download Sample Sheet v2 |
| `GET /api/runs/{id}/samplesheet-v1` | Download Sample Sheet v1 |
| `GET /api/runs/{id}/json` | Download JSON metadata |
| `GET /api/runs/{id}/validation-report` | Download validation JSON |
| `GET /api/runs/{id}/validation-pdf` | Download validation PDF |

API documentation is available at `/api/docs` (Swagger UI) and `/api/openapi.json`.

## Development

### Technology Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.14+, [FastHTML](https://fastht.ml) framework |
| Database | MongoDB 7+ via PyMongo |
| Frontend | Server-rendered HTML with [HTMX](https://htmx.org) for dynamic updates |
| Authentication | Session-based (web UI), Bearer token (API). LDAP/AD via ldap3. |
| Environment | [Pixi](https://pixi.sh) for dependency management |
| PDF Generation | ReportLab + Matplotlib (for heatmap charts) |
| Testing | pytest (607 unit tests, no database required) |

### Architecture

SeqSetup follows a layered architecture with clear separation of concerns:

```
┌─────────────────────────────────────────────────┐
│  Browser (HTMX)                                 │
├─────────────────────────────────────────────────┤
│  FastHTML App (app.py)                          │
│  ├── Middleware (middleware.py) — auth          │
│  ├── Startup (startup.py) — init & DI           │
│  └── Context (context.py) — shared state        │
├─────────────────────────────────────────────────┤
│  Routes (routes/)         │ Components          │
│  Request handling,        │ (components/)       │
│  input validation,        │ Server-rendered     │
│  orchestration            │ HTML via FastHTML   │
├─────────────────────────────────────────────────┤
│  Services (services/)                           │
│  Business logic: validation, export, auth,      │
│  LIMS API client, GitHub sync, parsing          │
├─────────────────────────────────────────────────┤
│  Repositories (repositories/)                   │
│  Thin MongoDB data access layer                 │
├─────────────────────────────────────────────────┤
│  Models (models/)                               │
│  Python dataclasses with to_dict/from_dict      │
├─────────────────────────────────────────────────┤
│  MongoDB                                        │
└─────────────────────────────────────────────────┘
```

**Data flows top-down**: routes receive HTTP requests, call services for business logic, and use repositories for persistence. Components render the UI from model data. Services never import from routes; repositories never import from services.

### Project Structure

```
seqsetup/
├── config/                          # Configuration files
│   ├── instruments.yaml             # Instrument and flowcell definitions
│   ├── mongodb.yaml                 # Database connection settings
│   ├── users.yaml                   # Development user credentials
│   ├── indexes/                     # Bundled index kit definitions
│   └── profiles/                    # Application/test profiles
│       ├── application_profiles/
│       └── test_profiles/
├── src/seqsetup/                    # Application source (~18k lines)
│   ├── app.py                       # FastHTML app creation & route registration
│   ├── startup.py                   # Repo initialization, service factories, DI setup
│   ├── middleware.py                # Auth beforeware (session + Bearer token)
│   ├── context.py                   # AppContext dataclass for dependency injection
│   ├── openapi.py                   # OpenAPI 3.0 spec for the JSON API
│   ├── components/                  # UI components (server-rendered FastHTML)
│   │   ├── wizard/                  # Run creation wizard (steps, sample table, indexes)
│   │   ├── admin/                   # Admin pages (auth, instruments, sync, API config)
│   │   ├── validation/              # Validation page (issues, heatmaps, color balance)
│   │   ├── layout.py                # App shell, navigation, page wrapper
│   │   ├── edit_run.py              # Run overview/editing page components
│   │   ├── sample_table.py          # Sample table for run overview
│   │   ├── index_panel.py           # Index kit display and management
│   │   ├── dashboard.py             # Dashboard / run list
│   │   ├── login.py                 # Login form
│   │   ├── profiles.py              # Application/test profile management
│   │   ├── local_users.py           # Local user management
│   │   ├── api_tokens.py            # API token management
│   │   ├── export_panel.py          # Export buttons and download panel
│   │   └── run_config.py            # Run configuration display
│   ├── models/                      # Data models (Python dataclasses)
│   │   ├── sequencing_run.py        # SequencingRun, RunStatus, RunCycles, InstrumentPlatform
│   │   ├── sample.py                # Sample (with index assignment)
│   │   ├── index.py                 # IndexKit, IndexPair, Index, IndexMode
│   │   ├── analysis.py              # Analysis, AnalysisType, DRAGENPipeline
│   │   ├── validation.py            # ValidationResult, ValidationError models
│   │   ├── auth_config.py           # AuthConfig, AuthMethod, LDAPConfig
│   │   ├── user.py                  # User, UserRole
│   │   ├── api_token.py             # ApiToken (bcrypt-hashed)
│   │   ├── local_user.py            # LocalUser (bcrypt-hashed)
│   │   ├── application_profile.py   # ApplicationProfile (SampleSheet sections)
│   │   ├── test_profile.py          # TestProfile (maps test types to app profiles)
│   │   ├── instrument_config.py     # InstrumentConfig
│   │   ├── instrument_definition.py # InstrumentDefinition (synced from GitHub)
│   │   ├── sample_api_config.py     # SampleApiConfig (external LIMS API settings)
│   │   └── profile_sync_config.py   # ProfileSyncConfig (GitHub sync settings)
│   ├── repositories/                # MongoDB data access
│   │   ├── base.py                  # BaseRepository[T], SingletonConfigRepository[C]
│   │   ├── run_repo.py              # SequencingRun CRUD
│   │   ├── index_kit_repo.py        # IndexKit CRUD + index lookup
│   │   ├── test_repo.py             # Legacy test CRUD
│   │   ├── api_token_repo.py        # API token CRUD + verification
│   │   ├── local_user_repo.py       # Local user CRUD + authentication
│   │   ├── application_profile_repo.py
│   │   ├── test_profile_repo.py
│   │   ├── auth_config_repo.py      # Singleton: auth config
│   │   ├── instrument_config_repo.py # Singleton: instrument config
│   │   ├── sample_api_config_repo.py # Singleton: LIMS API config
│   │   ├── instrument_definition_repo.py
│   │   └── profile_sync_config_repo.py
│   ├── routes/                      # HTTP route handlers
│   │   ├── utils.py                 # Shared guards and helpers
│   │   ├── main.py                  # Run detail page (catch-all /runs/{id})
│   │   ├── dashboard.py             # Dashboard / run list
│   │   ├── wizard.py                # New run wizard + add-samples wizard
│   │   ├── runs.py                  # Run configuration updates (instrument, cycles, status)
│   │   ├── samples.py               # Sample CRUD, bulk operations, LIMS import
│   │   ├── indexes.py               # Index kit upload, management, download
│   │   ├── validation.py            # Validation page, approve/unapprove
│   │   ├── export.py                # SampleSheet, JSON, and report downloads
│   │   ├── api.py                   # JSON API for external integrations
│   │   ├── swagger.py               # Swagger UI at /api/docs
│   │   ├── auth.py                  # Login/logout
│   │   ├── admin.py                 # Admin pages (auth, instruments, sync, API config)
│   │   ├── api_tokens.py            # API token management
│   │   ├── local_users.py           # Local user management
│   │   └── profiles.py              # Application/test profile management
│   ├── services/                    # Business logic
│   │   ├── validation.py            # ValidationService orchestrator (read-only)
│   │   ├── index_collision_validator.py # Index collision detection + distance matrices
│   │   ├── color_analysis_validator.py  # Dark cycle + color balance checks
│   │   ├── application_profile_validator.py # Profile compatibility checks
│   │   ├── samplesheet_v2_exporter.py # Sample Sheet v2 CSV generator
│   │   ├── samplesheet_v1_exporter.py # Sample Sheet v1 CSV generator
│   │   ├── json_exporter.py         # JSON metadata exporter
│   │   ├── validation_report.py     # Validation JSON + PDF report generators
│   │   ├── cycle_calculator.py      # Override cycles computation
│   │   ├── index_parser.py          # Index kit file parser (CSV/TSV)
│   │   ├── index_validator.py       # Index kit validation
│   │   ├── index_kit_yaml_exporter.py # Index kit YAML export
│   │   ├── sample_parser.py         # Pasted/uploaded sample data parser
│   │   ├── sample_api.py            # External LIMS API client (iGene)
│   │   ├── auth.py                  # AuthService (YAML + MongoDB + LDAP)
│   │   ├── ldap.py                  # LDAP/AD authentication
│   │   ├── database.py              # MongoDB connection management
│   │   ├── github_sync.py           # Profile/instrument sync from GitHub
│   │   ├── scheduler.py             # Background sync scheduler
│   │   ├── log_capture.py           # In-memory log capture for admin UI
│   │   └── version_resolver.py      # Semantic version resolution for profiles
│   ├── data/
│   │   └── instruments.py           # Instrument definitions loader (YAML + DB)
│   ├── utils/
│   │   └── html.py                  # XSS protection: escape_js_string, escape_html_attr
│   └── static/                      # CSS, JS, images
│       ├── css/app.css
│       ├── js/app.js
│       └── img/
├── tests/
│   ├── unit/                        # 607 unit tests (no database needed)
│   ├── integration/                 # Integration tests
│   ├── fixtures/                    # Test data files
│   └── conftest.py
├── tools/
│   └── mock_igene_api.py            # Mock iGene LIMS API server (FastAPI)
├── Dockerfile
├── docker-compose.yml
├── pixi.toml                        # Pixi project manifest (dependencies, tasks)
└── pixi.lock                        # Locked dependency versions
```

### Key Architectural Concepts

#### Dependency Injection via AppContext

All route modules receive a single `AppContext` dataclass that holds references to every repository and service factory. This replaces scattered getter functions and makes dependencies explicit:

```python
# In startup.py
ctx = get_app_context()  # Creates AppContext with all repos

# In app.py
runs.register(app, rt, ctx)
samples.register(app, rt, ctx)

# In a route handler
run = ctx.run_repo.get_by_id(run_id)
```

`AppContext` is created once at startup and shared across all route modules.

#### Repository Pattern

Repositories are thin data access wrappers around MongoDB collections. Two base classes eliminate boilerplate:

- **`BaseRepository[T]`** -- For collection-backed entities (runs, index kits, profiles, etc.). Provides `list_all()`, `get_by_id()`, `save()`, `delete()`.
- **`SingletonConfigRepository[C]`** -- For singleton configuration documents (auth config, instrument config, LIMS API config). Stores config in a shared `settings` collection keyed by `CONFIG_ID`.

Repositories contain no business logic. They serialize models via `to_dict()` / `from_dict()`.

#### Models

All domain objects are Python `@dataclass` classes with:

- **`to_dict()`** -- Serialize to a dict for MongoDB storage.
- **`from_dict(cls, data)`** -- Deserialize from a MongoDB document.
- **`__post_init__`** -- Input validation and normalization (clamping, type coercion).

Models are self-contained and do not import from other layers.

#### Server-Rendered UI with HTMX

The frontend is entirely server-rendered using FastHTML (a Python framework that generates HTML). Dynamic updates use HTMX attributes (`hx-post`, `hx-get`, `hx-swap`, `hx-swap-oob`) to replace page fragments without full reloads.

Components are Python functions that return FastHTML element trees:

```python
def SampleRow(sample, run_id, ...):
    return Tr(
        Td(sample.sample_id),
        Td(sample.index1_sequence or ""),
        ...,
    )
```

Large component files are split into packages (e.g., `components/wizard/`, `components/admin/`, `components/validation/`) with `__init__.py` re-exporting all public symbols to preserve import paths.

#### Validation Architecture

Validation is read-only and never mutates run state. The `ValidationService` orchestrates three specialized validators:

1. **`IndexCollisionValidator`** -- Detects index collisions within lanes, computes Hamming distance matrices.
2. **`ColorAnalysisValidator`** -- Checks for dark cycles and color balance issues based on instrument chemistry (two-color vs four-color SBS).
3. **`ApplicationProfileValidator`** -- Validates that samples have compatible application profile configurations.

Results are returned as a `ValidationResult` dataclass containing errors, warnings, and distance matrices.

#### Export Pipeline

When a run transitions from Draft to Ready:

1. All exports are pre-generated and stored in the `SequencingRun` model (`generated_samplesheet_v2`, `generated_json`, etc.).
2. The API and export routes serve this pre-generated content, not live exports.
3. Validation PDF is generated lazily on first download (to keep the "Mark Ready" transition fast).

This ensures the exported content is a frozen snapshot of the run at the time it was finalized.

#### Application and Test Profiles

Profiles define how the Sample Sheet v2 is structured for different assay types:

- **TestProfile** maps a `test_id` (e.g., "WES", "WGS") to one or more ApplicationProfile references.
- **ApplicationProfile** defines a Sample Sheet section: settings key-value pairs, data fields, and field translations.

This allows the Sample Sheet structure to be configured externally (and synced from GitHub) rather than hardcoded.

#### External LIMS Integration

SeqSetup can import samples from an external LIMS API (iGene). Configuration is stored in `SampleApiConfig` with:

- Base URL and API key
- Field mappings to translate LIMS field names to SeqSetup field names
- The mock server (`tools/mock_igene_api.py`) implements the iGene API spec for testing

#### Config Sync from GitHub

Application profiles, test profiles, instrument definitions, and index kits can be synchronized from a GitHub repository. The `ProfileSyncScheduler` runs in a background thread and periodically checks for updates based on a configurable interval.

### Navigating the Code

**Starting points for common tasks:**

| Task | Start here |
|------|-----------|
| Understand how a request is handled | `middleware.py` → `routes/{module}.py` → `services/` → `repositories/` |
| Add a new route | Look at an existing route module (e.g., `routes/runs.py`), follow the handler pattern |
| Modify the Sample Sheet output | `services/samplesheet_v2_exporter.py` (v2) or `services/samplesheet_v1_exporter.py` (v1) |
| Add a validation check | `services/validation.py` (orchestrator) and the appropriate sub-validator |
| Change the UI for a page | Find the component in `components/`, then the route that renders it in `routes/` |
| Add a new model field | `models/{model}.py` -- update the dataclass, `to_dict()`, and `from_dict()` |
| Add a new admin page | `routes/admin.py` + `components/admin/{page}.py` |
| Modify instrument configuration | `config/instruments.yaml` + `data/instruments.py` |
| Debug authentication | `middleware.py` → `services/auth.py` → `services/ldap.py` |
| Understand dependency wiring | `startup.py` (init_repos, get_app_context) → `context.py` (AppContext) → `app.py` (route registration) |

**Route registration order matters** in `app.py` because FastHTML matches routes in registration order. More specific routes (e.g., `/runs/new/*`) must be registered before catch-all patterns (e.g., `/runs/{run_id}`).

### Development Commands

```bash
pixi install                # Install all dependencies
pixi run serve              # Start the application (localhost:5001)
pixi run test               # Run all tests
pixi run mock-api           # Start the mock iGene API server (localhost:8100)
pixi run docs               # Build Sphinx documentation
pixi add <pkg>              # Add a runtime dependency
pixi add --feature dev <pkg>  # Add a development dependency
```

### Mock LIMS API Server

A FastAPI-based mock server (`tools/mock_igene_api.py`) implements the iGene LIMS API for testing the LIMS integration without a real LIMS system. It serves test data for worksheets, samples, and gene panels.

```bash
pixi run mock-api
# Or directly: uvicorn tools.mock_igene_api:app --port 8100
# API key for testing: test-api-key-12345
```

The mock server implements the OpenAPI spec defined in `igene_openapi.json`.

## Author

Pär Larsson <par.g.larsson@regionvasterbotten.se>
