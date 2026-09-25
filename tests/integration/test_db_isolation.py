"""Each integration test gets its own fake database.

startup.py imports ``init_db`` by name. When a test file ran on its own,
the first import of startup happened inside a test, so that name kept the
first test's fake database and every later test shared it.
"""

import pytest


class TestEachTestGetsItsOwnDatabase:
    """The app's repos use this test's database, not an earlier test's."""

    @pytest.mark.parametrize("attempt", [1, 2])
    def test_repos_use_this_tests_database(self, fresh_app, attempt):
        _app, ctx, db = fresh_app
        assert ctx.run_repo.collection.database is db
