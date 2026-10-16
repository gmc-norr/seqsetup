"""The shipped deployment files hand MongoDB the right credentials, to the
right place, without mangling them (outside review of f490536: F4, F12,
F13, F16). Docker is not needed -- these read the files as shipped, and the
init script's program is run against a stand-in that records what it would
create.
"""

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml
from pymongo import uri_parser

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "docker-compose.yml"
INIT = ROOT / "docker" / "mongo-init.sh"
DEPLOYMENT = ROOT / "docs" / "getting-started" / "deployment.rst"

# What a password manager hands out. Each must survive the init script
# unchanged, or be refused -- never stored as something else.
AWKWARD_PASSWORDS = [
    "SynthPw1", "Synth@Pw1", "Synth:Pw1", "Synth/Pw1", "Synth%Pw1", "Synth?Pw1",
    "Synth'Pw1", "Synth\\Pw1", 'Synth"Pw1', "Synth$Pw1", "Synth`Pw1", "Synth\nPw1",
]


def _compose():
    return yaml.safe_load(COMPOSE.read_text())


def _env(service) -> dict:
    env = _compose()["services"][service].get("environment", [])
    if isinstance(env, dict):
        return dict(env)
    return dict(entry.split("=", 1) for entry in env)


def _interpolate(template: str, values: dict) -> str:
    """Compose's ${VAR}, ${VAR:?msg} and ${VAR:-default}."""
    def sub(found):
        name, op, rest = found.group(1), found.group(2), found.group(3)
        if values.get(name):
            return values[name]
        if op == ":-":
            return rest
        raise KeyError(f"{name} has no value and no default")
    return re.sub(r"\$\{([A-Za-z0-9_]+)(?:(:\?|:-)([^}]*))?\}", sub, template)


def _app_uri(password="0f2a9c4e7b1d") -> str:
    return _interpolate(_env("app")["MONGODB_URI"],
                        {"MONGO_APP_USER": "seqsetup_app", "MONGO_APP_PASSWORD": password})


def _init_database() -> str:
    found = re.search(r"""getSiblingDB\((['"])([^'"]+)\1\)""", INIT.read_text())
    assert found, "mongo-init.sh no longer names a database with getSiblingDB"
    return found.group(2)


def _env_file_keys(name) -> set:
    path = ROOT / name
    if not path.exists():
        return set()
    return {line.split("=", 1)[0] for line in path.read_text().splitlines()
            if re.match(r"^[A-Za-z0-9_]+=", line)}


class TestF4TheAppAuthenticatesWhereItsUserExists:
    def test_the_uri_names_the_database_the_init_script_creates_the_user_in(self):
        parsed = uri_parser.parse_uri(_app_uri())
        options = {k.lower(): v for k, v in parsed["options"].items()}
        auth_source = options.get("authsource") or parsed["database"]
        assert auth_source == _init_database(), (
            f"docker-compose.yml authenticates against {auth_source!r} but "
            f"docker/mongo-init.sh creates the app user in {_init_database()!r}: "
            "the app cannot sign in at all")


class TestF12TheAppNeverSeesTheRootCredential:
    def test_no_root_credential_reaches_the_app_container(self):
        app = _compose()["services"]["app"]
        keys = set(_env("app"))
        for name in (app.get("env_file") or []):
            # .env is a filled-in copy of .env.example: every key in it is
            # injected into the app container.
            keys |= _env_file_keys(f"{name}.example") | _env_file_keys(name)
        leaked = sorted(k for k in keys
                        if k.startswith("MONGO_ROOT") or k.startswith("MONGO_INITDB_ROOT"))
        assert leaked == [], f"the app container's environment carries {leaked}"

    def test_the_database_container_gets_the_root_credential(self):
        mongo = _compose()["services"]["mongodb"]
        keys = set(_env("mongodb"))
        for name in (mongo.get("env_file") or []):
            keys |= _env_file_keys(f"{name}.example") | _env_file_keys(name)
        assert {"MONGO_INITDB_ROOT_USERNAME", "MONGO_INITDB_ROOT_PASSWORD"} <= keys, (
            f"mongod would start with no root user; it has {sorted(keys)}")

    def test_the_example_for_that_file_is_shipped(self):
        mongo = _compose()["services"]["mongodb"]
        for name in (mongo.get("env_file") or []):
            if name == ".env":
                continue
            assert (ROOT / f"{name}.example").exists(), (
                f"docker-compose.yml reads {name}, but there is no {name}.example to copy")


class TestF13ThePasswordSurvivesTheInitScript:
    """The init script used to paste the password into a JavaScript string
    literal: a ' made mongod exit on first start (and the init script is
    skipped on every later start, so the app user never existed until
    `down -v`), and a \\ silently created the user with a different
    password. It must read the value, not quote it."""

    def test_the_password_is_not_pasted_into_the_program(self):
        text = INIT.read_text()
        program = text.split("--eval", 1)[1] if "--eval" in text else text
        for name in ("MONGO_APP_PASSWORD", "MONGO_APP_USER"):
            assert f"${{{name}}}" not in program, (
                f"mongo-init.sh pastes ${name} into the mongosh program, so a quote "
                "or a backslash in it changes what is created")

    @pytest.mark.parametrize("password", AWKWARD_PASSWORDS)
    def test_the_user_is_created_with_exactly_that_password(self, password, tmp_path):
        node = shutil.which("node") or "/home/parlar_ai/.nvm/versions/node/v22.22.3/bin/node"
        if not Path(node).exists():
            pytest.skip("node is needed to run the init script's JavaScript")
        # A stand-in mongosh that saves the --eval program instead of running it.
        stub = tmp_path / "bin" / "mongosh"
        stub.parent.mkdir()
        stub.write_text('#!/usr/bin/env bash\nwhile [ $# -gt 0 ]; do [ "$1" = --eval ] && '
                        'printf "%s" "$2" > "$EVAL_OUT"; shift; done\n')
        stub.chmod(0o755)
        program = tmp_path / "eval.js"
        env = {"PATH": f"{stub.parent}:/usr/bin:/bin", "EVAL_OUT": str(program),
               "MONGO_INITDB_ROOT_USERNAME": "root",
               "MONGO_INITDB_ROOT_PASSWORD": "SyntheticRootPw1",
               "MONGO_APP_USER": "seqsetup_app", "MONGO_APP_PASSWORD": password}
        subprocess.run(["bash", str(INIT)], env=env, check=True)
        # mongosh's own environment reaches the program through process.env.
        harness = (
            "let created; var db = {getSiblingDB: () => db, createUser: (u) => { created = u; }};"
            "var print = () => {}; const fs = require('fs');"
            "eval(fs.readFileSync(process.argv[1], 'utf8'));"
            "process.stdout.write(JSON.stringify([created.user, created.pwd]));")
        ran = subprocess.run([node, "-e", harness, str(program)],
                             capture_output=True, text=True, env={**os.environ, **env})
        assert ran.returncode == 0, f"mongosh would reject the program: {ran.stderr[-400:]}"
        assert json.loads(ran.stdout) == ["seqsetup_app", password], (
            f"the app user would be created with {ran.stdout}")


class TestF13TheUriCarriesTheDocumentedPassword:
    """The URI can only carry what a URI can carry, and compose cannot
    percent-encode, so .env.example must say how to make a safe one."""

    def test_a_hex_password_survives_the_uri(self):
        parsed = uri_parser.parse_uri(_app_uri("4f1b9c2e7a0d8356"))
        assert parsed["password"] == "4f1b9c2e7a0d8356"

    def test_the_example_says_how_to_generate_one(self):
        text = (ROOT / ".env.example").read_text()
        block = text.split("MONGO_APP_PASSWORD=", 1)[0]
        comment = block[block.rindex("# Mongo application credentials"):]
        assert "openssl rand -hex" in comment, (
            ".env.example does not tell the admin how to generate a password the URI "
            f"can carry; it says:\n{comment}")


def _yaml_blocks(text) -> list:
    blocks = []
    for chunk in text.split(".. code-block:: yaml")[1:]:
        lines = []
        for line in chunk.splitlines()[1:]:
            if line and not line.startswith("   "):
                break
            lines.append(line[3:])
        parsed = yaml.safe_load("\n".join(lines))
        if isinstance(parsed, dict):
            blocks.append(parsed)
    return blocks


class TestF16TheDocsShipNoSecondComposeFile:
    """deployment.rst offered a docker-compose.prod.yml that ran mongod with
    no --auth and no root user, and connected the app anonymously. An
    unpublished container port is still reachable from the Docker host, so
    any local account on the server could read the database or change a
    Ready run's stored sample sheet with no password."""

    def test_no_second_compose_file_is_offered(self):
        text = DEPLOYMENT.read_text()
        assert "docker-compose.prod.yml" not in text, (
            "deployment.rst still offers a second compose file; the shipped "
            "docker-compose.yml is the one that carries the protections")

    def test_no_code_block_defines_a_database_service(self):
        defining = [b for b in _yaml_blocks(DEPLOYMENT.read_text())
                    if "mongodb" in (b.get("services") or {})]
        assert defining == [], (
            f"deployment.rst defines a mongodb service in {len(defining)} yaml block(s)")

    def test_it_points_at_the_shipped_compose_file(self):
        assert "docker-compose.override.yml" in DEPLOYMENT.read_text(), (
            "deployment.rst should say where site-specific changes go instead")


class TestF12EveryInstallPathCopiesBothFiles:
    """The root credential moved to its own file, so every place that tells
    an admin to copy .env.example must tell them to copy .env.db.example
    too, or mongod starts with no root user."""

    PATHS = ["README.md", "docs/getting-started/installation.rst",
             "docs/getting-started/deployment.rst"]

    @pytest.mark.parametrize("path", PATHS)
    def test_it_names_the_database_env_file(self, path):
        text = (ROOT / path).read_text()
        assert ".env.example" in text, f"{path} no longer mentions .env.example"
        assert ".env.db.example" in text, (
            f"{path} tells the admin to copy .env.example but not .env.db.example")

    @pytest.mark.parametrize("path", PATHS)
    def test_it_does_not_still_name_the_moved_variables(self, path):
        text = (ROOT / path).read_text()
        gone = [name for name in ("MONGO_ROOT_USER", "MONGO_ROOT_PASSWORD") if name in text]
        assert gone == [], f"{path} still names {gone}, which no longer exist"
