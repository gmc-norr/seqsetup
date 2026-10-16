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
        """A key the app's own environment: names EMPTY is not a leak -- that
        is how an .env written before the split is neutralised, since
        environment: wins over env_file: (measured with `docker compose
        config`). A key that only .env carries is."""
        app = _compose()["services"]["app"]
        app_env = _env("app")
        blanked = {k for k, v in app_env.items() if v == ""}
        keys = {k for k, v in app_env.items() if v != ""}
        for name in (app.get("env_file") or []):
            # .env is a filled-in copy of .env.example: every key in it is
            # injected into the app container unless environment: blanks it.
            keys |= (_env_file_keys(f"{name}.example") | _env_file_keys(name)) - blanked
        leaked = sorted(k for k in keys
                        if k.startswith("MONGO_ROOT") or k.startswith("MONGO_INITDB_ROOT"))
        assert leaked == [], f"the app container's environment carries {leaked}"

    def test_the_application_example_asks_for_no_root_credential(self):
        """Blanking the two old names covers an .env that already exists; the
        template must not ask for a root credential at all, under any name."""
        asked = sorted(k for k in _env_file_keys(".env.example")
                       if k.startswith("MONGO_ROOT") or k.startswith("MONGO_INITDB_ROOT"))
        assert asked == [], f".env.example still asks for {asked}"

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
        node = shutil.which("node")
        if not node:
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
    def test_it_does_not_still_ask_for_the_moved_variables(self, path):
        """The upgrade section names them on purpose -- to say delete them.
        Everywhere else they no longer exist."""
        text = (ROOT / path).read_text()
        if "Upgrading an existing deployment" in text:
            start = text.index("Upgrading an existing deployment")
            text = text[:start] + text[start:].split("\nProduction Checklist", 1)[-1]
        gone = [name for name in ("MONGO_ROOT_USER", "MONGO_ROOT_PASSWORD") if name in text]
        assert gone == [], f"{path} still names {gone} outside the upgrade section"


class TestAFailedFirstStartIsLoud:
    """A fresh review proved a second, silent way into the state F13 exists
    to prevent: the mongo entrypoint SOURCES the init script as uid 999, so a
    checkout whose umask strips other-read (027, 077, 007 -- this repository's
    own checkout is mode 770) makes it unreadable. The entrypoint does not
    abort: the container exits 0, restarts, the volume is now initialised so
    the script never runs again, and mongod reports *healthy* while the app
    says "Authentication failed" for ever. Any other failure of the script
    lands in the same place. The healthcheck must therefore prove the app user
    exists, not just that mongod answers a ping."""

    def test_the_healthcheck_signs_in_as_the_app_user(self):
        test = _compose()["services"]["mongodb"]["healthcheck"]["test"]
        command = " ".join(test)
        assert "MONGO_APP_USER" in command and "MONGO_APP_PASSWORD" in command, (
            f"the healthcheck does not sign in as the app user: {command}")
        assert _init_database() in command, (
            f"the healthcheck does not name the app user's database: {command}")

    def test_the_app_waits_for_that_healthcheck(self):
        depends = _compose()["services"]["app"]["depends_on"]
        assert depends["mongodb"]["condition"] == "service_healthy"


class TestAStaleEnvCannotLeakTheRootCredential:
    """Moving the root credential out of .env.example does nothing to an .env
    that already exists: an upgrading site's file still carries
    MONGO_ROOT_USER / MONGO_ROOT_PASSWORD, and app's env_file hands them
    straight to the app container. Compose's environment: overrides env_file:,
    so naming them empty there neutralises the old keys whatever .env says
    (measured with `docker compose config`)."""

    def test_the_app_names_the_old_root_keys_empty(self):
        app_env = _env("app")
        for name in ("MONGO_ROOT_USER", "MONGO_ROOT_PASSWORD"):
            assert app_env.get(name) == "", (
                f"docker-compose.yml does not blank {name} on the app service, so an "
                f"upgrading site's .env still hands it over; it has {app_env.get(name)!r}")


class TestTheExamplesDoNotPromiseMoreThanComposeDelivers:
    """Compose's env-file parser is not a safe place for arbitrary text: it
    expands $VAR from the HOST environment, collapses $$ to $, strips a
    wrapping quote, and cuts a value at ` #`. Measured in-container: a root
    password typed as R00t$HOME-x reaches mongod as R00t/home/<user>-x, and
    `pw with space # x` as `pw with space`. Both examples said any character
    was safe."""

    def test_the_database_example_does_not_claim_any_character_is_safe(self):
        text = (ROOT / ".env.db.example").read_text()
        assert "Any character is safe" not in text
        assert "openssl rand -hex" in text, (
            ".env.db.example does not require a password the env-file parser leaves alone")

    def test_the_application_example_does_not_claim_it_either(self):
        text = (ROOT / ".env.example").read_text()
        assert "takes any character" not in text

    @pytest.mark.parametrize("example", [".env.example", ".env.db.example"])
    def test_the_example_names_what_the_parser_changes(self, example):
        text = (ROOT / example).read_text()
        assert "$" in text and "#" in text, f"{example} names nothing the parser changes"
        assert "env-file" in text or "env file" in text, (
            f"{example} does not say that Compose's env-file parser changes some values")


class TestUpgradingAnExistingDeploymentIsDocumented:
    """Three states an upgrading site lands in, all measured by the reviewer:
    their old .env still leaks the root credential to the app; a freshly
    generated MONGO_INITDB_ROOT_PASSWORD is silently ignored because initdb
    does not re-run, so their .env.db records a password the database does not
    have; and .env.db written with the OLD key names gives a healthy mongod
    with no users at all."""

    def test_the_docs_have_an_upgrade_section(self):
        text = DEPLOYMENT.read_text()
        assert "Upgrading an existing deployment" in text

    def test_it_says_to_delete_the_old_keys_from_env(self):
        text = DEPLOYMENT.read_text()
        section = text[text.index("Upgrading an existing deployment"):]
        section = section.split("\n----")[0]
        assert "MONGO_ROOT_USER" in section and "delete" in section.lower(), (
            "the upgrade section does not tell them to delete the old keys from .env")

    def test_it_says_to_keep_the_root_password_they_already_have(self):
        text = DEPLOYMENT.read_text()
        section = text[text.index("Upgrading an existing deployment"):].split("\n----")[0]
        assert "first start" in section.lower() or "initdb" in section.lower(), (
            "the upgrade section does not say that MONGO_INITDB_ROOT_* only applies on "
            "the first start, so a new password there is silently ignored")

    def test_the_quick_start_marks_the_root_password_as_a_new_install_step(self):
        text = DEPLOYMENT.read_text()
        start = text.index("Fill in the two environment files")
        block = text[start:start + 1400]
        assert "MONGO_INITDB_ROOT_PASSWORD" in block
        assert "first" in block.lower() or "new install" in block.lower(), (
            "the quick start tells every reader to generate a root password, which does "
            "nothing on a database that already exists")


class TestTheReadmeDoesNotOverstateTheGuard:
    """Compose's ${VAR:?} guards only the four values it interpolates from
    .env. .env.db arrives through env_file: a missing FILE is refused, but an
    empty password in it is not -- mongod restart-loops instead."""

    def test_it_scopes_the_refusal_to_the_application_file(self):
        text = (ROOT / "README.md").read_text()
        start = text.index("cp .env.example .env")
        block = text[max(0, start - 600):start]
        assert "refuses to start" in block, "README no longer mentions the guard at all"
        assert "restart-loop" in block or "not refused" in block, (
            "README mentions the compose refusal without saying that .env.db is not "
            "covered by it: that guard is only compose's ${VAR:?} on the four values "
            f"it interpolates from .env. It says:\n{block}")
