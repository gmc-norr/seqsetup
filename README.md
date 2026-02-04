# SeqSetup

> **Note:** This project is under active development and is not ready for production use. APIs, data models, and features may change without notice.

A web-based application for configuring and managing sample information for Illumina DNA sequencing workflows. SeqSetup generates Illumina Sample Sheet v2 files and associated metadata for instruments including NovaSeq X, MiSeq i100, and others.

**Documentation:** [seqsetup.readthedocs.io](https://seqsetup.readthedocs.io)

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

## Configuration

### Environment Variables

| Variable              | Description                          | Default                          |
|-----------------------|--------------------------------------|----------------------------------|
| `MONGODB_URI`         | MongoDB connection URI               | `mongodb://localhost:27017`      |
| `MONGODB_DATABASE`    | Database name                        | `seqsetup`                       |
| `INSTRUMENTS_CONFIG`  | Path to instruments YAML config      | `config/instruments.yaml`        |

Environment variables take precedence over configuration files.

### Configuration Files

All configuration files are in the `config/` directory:

- **`mongodb.yaml`** -- MongoDB connection settings (URI and database name).
- **`users.yaml`** -- Local user credentials (bcrypt-hashed passwords). Used during development; production deployments should use LDAP/AD.
- **`instruments.yaml`** -- Supported sequencing instruments, flowcell types, reagent kits, SBS chemistry definitions, and default cycle configurations.
- **`profiles/`** -- Application and test profile definitions.

### Session Key

A session secret key is stored in `.sesskey` at the project root. It is auto-generated on first startup if it does not exist. Keep this file out of version control.

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

## Running Tests

```bash
pixi run test
```

## Project Structure

```
seqsetup/
├── config/                          # Configuration files
│   ├── instruments.yaml             # Instrument and flowcell definitions
│   ├── mongodb.yaml                 # Database connection settings
│   ├── users.yaml                   # Development user credentials
│   └── profiles/                    # Application/test profiles
├── src/seqsetup/        # Application source code
│   ├── app.py                       # Application entry point
│   ├── components/                  # UI components (FastHTML)
│   ├── data/                        # Static data loaders
│   ├── models/                      # Data models
│   ├── repositories/                # MongoDB data access layer
│   ├── routes/                      # HTTP route handlers
│   ├── services/                    # Business logic services
│   └── static/                      # CSS and JavaScript assets
├── tests/                           # Test suite
├── Dockerfile                       # Container build definition
├── docker-compose.yml               # Multi-container orchestration
├── pixi.toml                        # Pixi project manifest
└── pixi.lock                        # Locked dependency versions
```

## Author

Pär Larsson <par.larsson@umu.se>
