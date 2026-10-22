"""Every route that saves an edited run waits for the run's turn first.

Routes run on worker threads (review F9), so two quick saves to one run --
one person's two row boxes, a row save and a bulk Apply -- would overlap, and
the second would lose the run's version check. The turn
(``services/run_turns.py``) lines them up. ``get_editable_run`` takes it
before it loads the run, so a route has the turn exactly when it gets its run
from ``get_editable_run``. This test reads every route module and fails on a
route that saves a run (``with saving_run(``) and gets it some other way,
unless ``NO_TURN`` names the route and why.
"""

import ast
import inspect
from pathlib import Path

from seqsetup.routes.dependencies import get_editable_run, hold_run_turn

ROUTES = Path(__file__).resolve().parents[2] / "src" / "seqsetup" / "routes"

NO_TURN = {
    "update_status": "Mark Ready may run for minutes; it refuses a run that changed while its "
                     "files were written (CLAUDE.md), and holding the turn would stall the "
                     "person's other edits for that long",
    "archive_run": "a Ready run, which no edit can change; Archive is one click and the save "
                   "checks the run's version",
}


def _savers() -> dict:
    """Route-module function name -> True when it gets its run from
    get_editable_run, for each function that enters saving_run."""
    found = {}
    for path in sorted(ROUTES.rglob("*.py")):
        if path.name == "dependencies.py":
            continue
        for fn in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            saves = any(isinstance(node, ast.With) and any(
                "saving_run(" in ast.unparse(item.context_expr) for item in node.items)
                for node in ast.walk(fn))
            if saves:
                found[fn.name] = "get_editable_run" in ast.unparse(fn.args)
    return found


class TestTheTurnIsTakenWhereTheRunIsLoaded:
    def test_get_editable_run_waits_for_the_turn(self):
        turn = inspect.signature(get_editable_run).parameters["_turn"].default
        assert turn.dependency is hold_run_turn
        # Released when the route function returns, before the answer is sent.
        assert turn.scope == "function"


class TestEveryRunSaverHasTheTurn:
    def test_every_route_that_saves_a_run_gets_it_from_get_editable_run(self):
        without = sorted(name for name, has_turn in _savers().items()
                         if not has_turn and name not in NO_TURN)
        assert without == []

    def test_every_route_named_without_a_turn_still_saves_a_run(self):
        """A name left here after its route changed would excuse nothing."""
        savers = _savers()
        assert sorted(name for name in NO_TURN if name not in savers) == []
        assert sorted(name for name in NO_TURN if savers[name]) == []

    def test_the_scan_finds_the_editing_routes(self):
        """Control: the scan reaches the routes it is about."""
        savers = _savers()
        for name in ("update_sample_settings", "assign_index", "set_lanes_bulk", "update_run_name"):
            assert savers.get(name) is True, name
