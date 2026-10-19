"""No test may reach the MongoDB a lab actually runs.

``pixi run test`` sets no environment, there was no ``tests/unit/conftest.py``,
and ``_load_config`` with no ``MONGODB_URI`` reads the shipped
``config/mongodb.yaml``, which says ``mongodb://localhost:27017`` -- the
address of the real database on a deployment host. So any test that reached
``init_db`` unguarded would ping it. ``tests/conftest.py`` now holds a
session-wide guard; these tests hold the guard itself
(docs/design/2026-10-18-input-rules-design.md, step 4, "No test reaches a
real database").
"""

import ast
import os
from pathlib import Path

import pytest

from seqsetup.services import database

SRC = Path(__file__).resolve().parents[2] / "src"


class TestTheGuardIsOn:

    def test_the_whole_suite_runs_against_an_address_nothing_listens_on(self):
        assert os.environ["MONGODB_URI"] == "mongodb://127.0.0.1:1"

    def test_the_client_is_a_stub_that_refuses_to_connect(self):
        assert type(database.MongoClient).__name__ == "_NoRealDatabase"

    def test_init_db_cannot_reach_anything(self, no_real_database):
        with pytest.raises(RuntimeError, match="no test may reach a real database"):
            database.init_db()

        assert no_real_database.built == ["mongodb://127.0.0.1:1"]

    def test_the_connection_is_reset_around_every_test(self):
        """init_db returns early when _db is already set, so a test that
        forgets to reset it passes while proving nothing."""
        assert database._client is None and database._db is None


class TestOnlyOnePlaceInSrcBuildsAClient:
    """The guard patches one name, so that name must be the whole of it."""

    def test_no_other_module_constructs_a_mongo_client(self):
        found = []
        for path in sorted(SRC.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                name = node.func.id if isinstance(node.func, ast.Name) else (
                    node.func.attr if isinstance(node.func, ast.Attribute) else "")
                if name == "MongoClient":
                    found.append(f"{path.relative_to(SRC)}:{node.lineno}")

        assert len(found) == 1, found
        assert found[0].startswith("seqsetup/services/database.py:"), found
