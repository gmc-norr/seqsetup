# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SeqSetup is a web-based application for configuring and managing sample information for Illumina DNA sequencing workflows. It generates Illumina Sample Sheet v2 files and associated metadata.

### Technology Stack

- **Backend**: Python with FastHTML framework
- **Database**: MongoDB
- **Frontend**: Server-rendered HTML with HTMX for dynamic updates
- **Authentication**: Local users, LDAP, or Active Directory

## User Authentication and Authorization

### Authentication Methods

Authentication is configured through the admin interface. Supported methods:

1. **Local** - Users stored in MongoDB or `config/users.yaml`
2. **LDAP** - LDAP directory server
3. **Active Directory** - Microsoft AD with LDAP protocol

### User Roles

- **Administrator** - Full access including index kit management, profiles, local users, API tokens
- **Standard User** - Run setup, sample management, and export functions

### Security Configuration

- Session secret: Set `SEQSETUP_SESSION_SECRET` environment variable in production
- LDAP SSL: Enable `verify_ssl_cert` in production to prevent MITM attacks
- API access: Only `ready` and `archived` runs are accessible via API

## Functional Capabilities

After authentication, users can:

- Create and manage sequencing runs (wizard-based workflow)
- Import samples via paste or external Sample API
- Assign indexes using drag-and-drop interface
- Configure lanes, barcode mismatches, and override cycles
- Validate runs (index collisions, color balance, dark cycles)
- Export Sample Sheet v2, Sample Sheet v1 (MiSeq), JSON metadata, validation reports

### Run Status Workflow

Runs follow a state machine: **Draft** → **Ready** → **Archived**

- **Draft**: Editable, validation not required
- **Ready**: Locked, validation approved, exports generated
- **Archived**: Archived for historical reference

## Export Functions

### Sample Sheet v2
Illumina Sample Sheet v2 CSV for NovaSeq X, MiSeq i100, and other supported instruments.

### Sample Sheet v1
Legacy CSV format for instruments that require it (MiSeq).

### JSON Metadata
Complete run and sample data including test IDs, user info, and all configuration.

### Validation Reports
JSON and PDF reports showing validation status, index collisions, and color balance analysis.

## API

The JSON API provides programmatic access using Bearer token authentication.

**Security**: Only `ready` and `archived` runs are accessible. Draft runs cannot be accessed via API.

Endpoints:
- `GET /api/runs` - List runs (status=ready|archived)
- `GET /api/runs/{id}/samplesheet-v2` - Download Sample Sheet v2
- `GET /api/runs/{id}/samplesheet-v1` - Download Sample Sheet v1
- `GET /api/runs/{id}/json` - Download JSON metadata
- `GET /api/runs/{id}/validation-report` - Download validation JSON
- `GET /api/runs/{id}/validation-pdf` - Download validation PDF

## Development Environment

This project uses **Pixi** for environment and dependency management.

### Common Commands

```bash
# Install dependencies and activate environment
pixi install

# Run the application
pixi run dev

# Run tests
pixi run test

# Add a dependency
pixi add <package-name>

# Add a development dependency
pixi add --feature dev <package-name>
```

### Project Configuration

- **pixi.toml** - Project manifest (dependencies, tasks, metadata)
- **pixi.lock** - Lock file (auto-generated, do not edit manually)

## Project Structure

```
src/seqsetup/
├── app.py              # Main FastHTML application, auth middleware
├── context.py          # AppContext for dependency injection
├── components/         # UI components (FastHTML)
│   ├── edit_run.py     # Run editing components
│   ├── index_panel.py  # Index kit display components
│   ├── layout.py       # App shell, navigation
│   ├── wizard.py       # Sample table, wizard steps
│   └── ...
├── models/             # Data models (dataclasses)
│   ├── sequencing_run.py
│   ├── index.py
│   ├── auth_config.py
│   └── ...
├── repositories/       # MongoDB data access
├── routes/             # Route handlers
│   ├── api.py          # JSON API endpoints
│   ├── export.py       # File download routes
│   ├── runs.py         # Run management
│   ├── samples.py      # Sample management
│   ├── validation.py   # Validation page
│   └── ...
├── services/           # Business logic
│   ├── validation.py   # Run validation
│   ├── samplesheet_v2_exporter.py
│   ├── ldap.py         # LDAP authentication
│   └── ...
├── utils/              # Shared utilities
│   └── html.py         # XSS protection helpers
└── static/             # CSS, JS, images
```

## Configuration Files

- `config/mongodb.yaml` - Database connection
- `config/users.yaml` - Development user credentials
- `config/instruments.yaml` - Instrument definitions
- `.sesskey` - Session secret (auto-generated, keep out of version control)

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MONGODB_URI` | MongoDB connection URI | `mongodb://localhost:27017` |
| `MONGODB_DATABASE` | Database name | `seqsetup` |
| `SEQSETUP_SESSION_SECRET` | Session encryption key | Auto-generated in `.sesskey` |
| `INSTRUMENTS_CONFIG` | Path to instruments config | `config/instruments.yaml` |
