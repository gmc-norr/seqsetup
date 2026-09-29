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

No account exists yet, and no default passwords are committed. Make the first admin with:

```bash
pixi run create-admin
```

It asks for a username, display name, email (optional) and the password twice, with the same password rules as **Admin > Users**. With Docker: `docker compose exec app pixi run create-admin`.

## Running Tests

```bash
pixi run test
```

This runs the unit and integration tests. They use an in-memory stand-in for MongoDB (mongomock), so no database is needed.

The browser tests drive the real app in Chromium:

```bash
pixi run playwright-install   # once
pixi run smoke-browser
```

## Configuration

### Environment Variables

| Variable                    | Description                     | Default                     |
|-----------------------------|---------------------------------|-----------------------------|
| `MONGODB_URI`               | MongoDB connection URI          | `mongodb://localhost:27017` |
| `MONGODB_DATABASE`          | Database name                   | `seqsetup`                  |
| `SEQSETUP_SESSION_SECRET`   | Signs the session cookie        | Auto-generated in `.sesskey`|
| `SEQSETUP_SESSION_IDLE_SECONDS` | A login unused this long ends | `1800` (30 minutes)       |
| `SEQSETUP_SESSION_MAX_AGE_SECONDS` | Every login ends this long after sign-in | `28800` (8 hours) |
| `INSTRUMENTS_CONFIG`        | Path to instruments YAML config | `config/instruments.yaml`   |

Environment variables take precedence over configuration files.

### Configuration Files

All configuration files are in the `config/` directory:

- **`mongodb.yaml`** -- MongoDB connection settings (URI and database name).
- **`instruments.yaml`** -- Supported sequencing instruments, flowcell types, reagent kits, SBS chemistry definitions, and default cycle configurations.
- **`profiles/`** -- Application and test profile definitions (can be synced from GitHub).
- **`indexes/`** -- Bundled index kit definitions in CSV and YAML formats.

### Session Key

A session secret key is stored in `.sesskey` at the project root. It is auto-generated on first startup if it does not exist. Keep this file out of version control. For production, set `SEQSETUP_SESSION_SECRET` instead.

### Local Accounts

Local accounts live only in MongoDB. The first admin is made with `pixi run create-admin`; the others on **Admin > Users**. `config/users.yaml` is no longer read. If LDAP/AD sign-in ever locks everyone out, `pixi run use-local-sign-in` switches sign-in back to local accounts.

## User Authentication and Authorization

### Authentication Methods

Authentication is configured through the admin interface. Supported methods:

1. **Local** -- Users stored in MongoDB (Admin > Users; the first admin via `pixi run create-admin`)
2. **LDAP** -- LDAP directory server
3. **Active Directory** -- Microsoft AD with LDAP protocol

### User Roles

- **Administrator** -- Full access including index kit management, application/test profiles, local users, API tokens, LDAP configuration, config sync, and the audit trail.
- **Standard User** -- Run setup, sample management, index assignment, validation, and export functions.

### Logins

Logins are kept on the server. A login ends after 30 minutes unused, 8 hours after sign-in, on sign-out, or when an administrator deletes the user or changes their role or password. Sign-ins, user and token changes, run status and sample changes, exports and configuration changes are recorded on the **Audit trail** admin page, which is kept permanently. Changes to a run's setup (name, instrument, cycles) are in that run's own change history.

## Functional Overview

### Run Workflow

The core workflow is wizard-based:

1. **Create a new run** -- Select instrument platform, flowcell type, reagent kit, and configure cycle counts.
2. **Add samples** -- Paste sample data, upload a file, or import from an external LIMS API (iGene).
3. **Assign indexes** -- Drag-and-drop indexes from uploaded index kits onto samples. Supports unique dual, combinatorial, and single-index modes.
4. **Check** -- The run's Check panel and validation page show index collisions, color balance, dark cycles, missing tests and other problems, updated after every change.
5. **Mark Ready** -- Runs every check again and refuses if there is any error; otherwise locks the run and pre-generates all export files.
6. **Export** -- Download Sample Sheet v2, Sample Sheet v1 (MiSeq), JSON metadata, or validation reports (JSON/PDF).

### Run Status State Machine

Runs follow a strict state machine: **Draft** → **Ready** → **Archived**

| Status   | Editable | API Access | Exports Available |
|----------|----------|------------|-------------------|
| Draft    | Yes      | No         | No                |
| Ready    | No       | Yes        | Yes (pre-generated) |
| Archived | No       | Yes        | Yes (pre-generated) |

- **Draft → Ready** runs validation at that moment and is refused if there are any errors (for example, a sample with no index). Triggers pre-generation of all export files.
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
| Backend | Python 3.14+, [FastAPI](https://fastapi.tiangolo.com) (Starlette), Pydantic v2 |
| Pages | Server-rendered [Jinja2](https://jinja.palletsprojects.com) templates, with [jinja2-fragments](https://github.com/sponsfreixes/jinja2-fragments) for partial updates |
| In-page behaviour | [HTMX](https://htmx.org) 2 and [Alpine.js](https://alpinejs.dev) 3, vendored in `static/js/vendor/` |
| Styling | [Tailwind CSS](https://tailwindcss.com) v4 |
| Database | MongoDB 7+ via PyMongo |
| Authentication | Server-side logins (web UI), Bearer tokens (API), LDAP/AD via ldap3 |
| PDF reports | ReportLab + Matplotlib |
| Environment | [Pixi](https://pixi.sh) |
| Testing | pytest with mongomock; Playwright for browser tests |

### Where to read more

- **`ARCHITECTURE.md`** -- how the code is organised, the conventions for routes, forms, templates and HTMX, and the reference implementations to copy.
- **`CLAUDE.md`** -- the project's hard rules for clinical safety (input bounds, run state, exports, authentication).
- **The Sphinx docs in `docs/`** -- user guide, admin guide, API reference, architecture and development pages, with screenshots. Build them with `pixi run docs`; the result is in `docs/_build/html/`.

### Project Layout

```
seqsetup/
├── config/          # instruments.yaml, mongodb.yaml, bundled index kits, profiles
├── src/seqsetup/
│   ├── app.py       # FastAPI app, middleware, route registration
│   ├── startup.py   # repositories, services, AppContext
│   ├── middleware.py, csrf.py, security_headers.py, rate_limit.py
│   ├── api/         # the Bearer-token JSON API (mounted at /api)
│   ├── routes/      # page and HTMX request handlers
│   ├── forms/       # Pydantic form models
│   ├── templates/   # Jinja2 templates
│   ├── models/      # dataclasses, self-validating
│   ├── repositories/ # thin MongoDB access
│   ├── services/    # validation, exports, auth, LIMS client, config sync
│   ├── data/        # instrument definitions loader
│   ├── utils/       # HTML/JS escaping helpers
│   └── static/      # CSS, JS, images
├── tests/           # unit/, integration/, browser/
├── tools/           # mock LIMS API and maintenance scripts
└── docs/            # Sphinx documentation
```

### Development Commands

```bash
pixi install                # Install all dependencies
pixi run serve              # Start the application (localhost:5001)
pixi run test               # Run the unit and integration tests
pixi run smoke-browser      # Run the browser tests
pixi run mock-api           # Start the mock iGene API server (localhost:8100)
pixi run docs               # Build the Sphinx documentation (warnings are errors)
pixi run docs-screenshots   # Retake the documentation screenshots
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
