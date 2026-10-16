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
# NOTE: this MUST be a .sh file, not .js: the MongoDB Docker image runs .sh
# scripts via /bin/bash, and only a .sh file can pass the root credential to
# mongosh as arguments. The app credentials are NOT substituted into the
# mongosh program -- the program reads them from process.env, which mongosh
# does have (measured: mongosh 2.6.0 and 2.12.0 both read it, with every
# character intact). Pasting them in meant a ' made mongod exit on first
# start -- and the init script is skipped on every later start, so the app
# user never existed until `down -v` -- while a \ silently created the user
# with a different password (review F13).
set -euo pipefail

if [[ -z "${MONGO_APP_USER:-}" || -z "${MONGO_APP_PASSWORD:-}" ]]; then
    echo "mongo-init: MONGO_APP_USER / MONGO_APP_PASSWORD unset — skipping app-user creation" >&2
    exit 0
fi

# Authenticate against admin as root (MONGO_INITDB_ROOT_USERNAME/PASSWORD),
# then create the scoped readWrite user against the seqsetup database.
# The program is in single quotes: bash substitutes nothing into it.
mongosh --quiet \
    --host localhost \
    --username "${MONGO_INITDB_ROOT_USERNAME}" \
    --password "${MONGO_INITDB_ROOT_PASSWORD}" \
    --authenticationDatabase admin \
    --eval '
const appUser = process.env.MONGO_APP_USER;
const appPassword = process.env.MONGO_APP_PASSWORD;
db = db.getSiblingDB("seqsetup");
db.createUser({
    user: appUser,
    pwd: appPassword,
    roles: [{ role: "readWrite", db: "seqsetup" }]
});
print("mongo-init: created app user " + appUser + " (readWrite on seqsetup)");
'
