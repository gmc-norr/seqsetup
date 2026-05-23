#!/usr/bin/env bash
# Mongo init — runs once on first container start.
#
# Creates the least-privileged application user against the `seqsetup`
# database. The root admin user is created by Mongo itself from
# MONGO_INITDB_ROOT_USERNAME / MONGO_INITDB_ROOT_PASSWORD; we add the
# scoped app user (MONGO_APP_USER / MONGO_APP_PASSWORD) here.
#
# Audit findings C2 / H1: this replaces the previous unauthenticated,
# host-port-exposed setup. Mongo now requires auth and is only reachable
# from the internal Compose network.
#
# NOTE: this MUST be a .sh file, not .js. The MongoDB Docker image runs
# .sh scripts via /bin/bash where ${VAR} substitution works; .js scripts
# run inside mongosh which has no process.env.
set -euo pipefail

if [[ -z "${MONGO_APP_USER:-}" || -z "${MONGO_APP_PASSWORD:-}" ]]; then
    echo "mongo-init: MONGO_APP_USER / MONGO_APP_PASSWORD unset — skipping app-user creation" >&2
    exit 0
fi

# Authenticate against admin as root (MONGO_INITDB_ROOT_USERNAME/PASSWORD),
# then create the scoped readWrite user against the seqsetup database.
mongosh --quiet \
    --host localhost \
    --username "${MONGO_INITDB_ROOT_USERNAME}" \
    --password "${MONGO_INITDB_ROOT_PASSWORD}" \
    --authenticationDatabase admin \
    --eval "
db = db.getSiblingDB('seqsetup');
db.createUser({
    user: '${MONGO_APP_USER}',
    pwd: '${MONGO_APP_PASSWORD}',
    roles: [{ role: 'readWrite', db: 'seqsetup' }]
});
print('mongo-init: created app user ${MONGO_APP_USER} (readWrite on seqsetup)');
"
