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

    def test_the_source_the_tools_would_use_is_not_the_real_one(self):
        """The two server commands read what is wrong with the settings and
        say it; "Could not reach the database" hid the file and the key."""
        import inspect

        from seqsetup import create_admin, use_local_sign_in

        for module in (create_admin, use_local_sign_in):
            source = inspect.getsource(module)
            assert "except ValueError as settings:" in source, module.__name__

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


ROOT = SRC.parent


def _client_calls(folder):
    """Every ``MongoClient(...)`` call under ``folder``, with the first
    argument as it is written."""
    found = []
    for path in sorted(folder.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = node.func.id if isinstance(node.func, ast.Name) else (
                node.func.attr if isinstance(node.func, ast.Attribute) else "")
            if name != "MongoClient":
                continue
            where = f"{path.relative_to(ROOT)}:{node.lineno}"
            first = node.args[0] if node.args else None
            given = first.value if isinstance(first, ast.Constant) else None
            mock = isinstance(node.func, ast.Attribute) and getattr(
                node.func.value, "id", "") == "mongomock"
            found.append((where, given, mock))
    return found


class TestOnlyOnePlaceInSrcBuildsAClient:
    """The guard patches one name, so that name must be the whole of it."""

    def test_no_other_module_constructs_a_mongo_client(self):
        found = [where for where, _given, _mock in _client_calls(SRC)]

        assert len(found) == 1, found
        assert found[0].startswith("src/seqsetup/services/database.py:"), found


class TestNoTestOrToolBuildsAClientThatCouldReachTheRealOne:
    """A copy of a test's own client with no address goes to
    localhost:27017 on its own, and neither the stub nor the check above
    would see it (fresh review of 6164dd9, P3-7)."""

    ALLOWED = "mongodb://127.0.0.1:1"

    @pytest.mark.parametrize("folder", ["tests", "tools"])
    def test_every_client_is_a_mock_or_names_an_address_nothing_listens_on(self, folder):
        wrong = [f"{where}: {given!r}"
                 for where, given, mock in _client_calls(ROOT / folder)
                 if not mock and not (isinstance(given, str) and given.startswith(self.ALLOWED))]

        assert wrong == [], wrong


class TestTheGuardIsInPlaceBeforeAnyFixture:
    """An autouse function-scoped fixture runs AFTER every session- and
    module-scoped one, so a session fixture that called init_db would reach
    whatever is on port 27017. The guard goes in from ``pytest_configure``
    (fresh review of 6164dd9, P2-3)."""

    def test_a_session_scoped_fixture_already_sees_it(self, _what_a_session_fixture_saw):
        assert _what_a_session_fixture_saw == ("mongodb://127.0.0.1:1", "_NoRealDatabase")


@pytest.fixture(scope="session")
def _what_a_session_fixture_saw():
    from seqsetup.services import database

    return (os.environ.get("MONGODB_URI"), type(database.MongoClient).__name__)


def test_one_test_leaves_a_connection_behind():
    """Deliberately: the test below proves the guard cleared it. ``init_db``
    returns early when ``_db`` is already set, so a test that forgets the
    reset passes while proving nothing (break row W18)."""
    database._db = object()
    database._client = object()

    assert database._db is not None


def test_the_next_test_sees_none_of_it():
    assert database._db is None and database._client is None
