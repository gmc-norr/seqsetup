"""Every route that saves a run waits for the run's turn first, or says why not.

Routes run on worker threads (review F9), so two quick saves to one run --
one person's two row boxes, a row save and a bulk Apply -- would overlap, and
the second would lose the run's version check. The turn
(``services/run_turns.py``) lines them up. ``get_editable_run`` takes it
before it loads the run, so a route has the turn exactly when it gets its run
from ``Depends(get_editable_run)``. This test reads every route module and
fails on a function that saves a run -- ``with saving_run(`` or
``run_repo.save(`` -- without that dependency, unless ``NO_TURN`` names it
and why. A route that saves nothing takes ``get_editable_run_to_read``, which
holds no turn.
"""

import ast
import inspect
from pathlib import Path

from seqsetup.routes.dependencies import (
    get_archivable_run,
    get_editable_run,
    get_editable_run_to_read,
    hold_run_turn,
    wait_for_run_turn,
)
from seqsetup.routes.runs import update_status

ROUTES = Path(__file__).resolve().parents[2] / "src" / "seqsetup" / "routes"

NO_TURN = {
    "update_status": "Mark Ready may run for minutes, so it holds no turn: it waits for the saves "
                     "in line (wait_for_run_turn), then refuses a run that changed while its "
                     "files were written (CLAUDE.md)",
    "archive_run": "a Ready run, which no edit can change; Archive is one click and the save "
                   "checks the run's version",
    "duplicate_run": "saves a new run, which nothing else can be editing",
    "_run_from_template": "saves a new run, which nothing else can be editing",
}


def _depends_on(fn, name: str) -> bool:
    """True when one of ``fn``'s parameters is ``Depends(<name>)``, exactly."""
    defaults = fn.args.defaults + [d for d in fn.args.kw_defaults if d is not None]
    return any(isinstance(d, ast.Call) and ast.unparse(d.func) == "Depends"
               and d.args and ast.unparse(d.args[0]) == name for d in defaults)


def _functions():
    for path in sorted(ROUTES.rglob("*.py")):
        if path.name == "dependencies.py":
            continue
        for fn in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                yield fn


def _saves_a_run(fn) -> bool:
    for node in ast.walk(fn):
        if isinstance(node, ast.With) and any(
                "saving_run(" in ast.unparse(item.context_expr) for item in node.items):
            return True
        if isinstance(node, ast.Call) and ast.unparse(node.func).endswith("run_repo.save"):
            return True
    return False


def _savers() -> dict:
    """Function name -> True when it takes Depends(get_editable_run), for
    each route-module function that saves a run."""
    return {fn.name: _depends_on(fn, "get_editable_run") for fn in _functions() if _saves_a_run(fn)}


class TestTheTurnIsTakenWhereTheRunIsLoaded:
    def test_get_editable_run_waits_for_the_turn(self):
        turn = inspect.signature(get_editable_run).parameters["_turn"].default
        assert turn.dependency is hold_run_turn
        # Released when the route function returns, before the answer is sent.
        assert turn.scope == "function"

    def test_the_reader_holds_no_turn(self):
        params = inspect.signature(get_editable_run_to_read).parameters.values()
        assert [p.name for p in params if getattr(p.default, "dependency", None) is hold_run_turn] == []

    def test_mark_ready_waits_for_the_saves_in_line_before_it_loads(self):
        names = list(inspect.signature(update_status).parameters)
        deps = {name: getattr(p.default, "dependency", None)
                for name, p in inspect.signature(update_status).parameters.items()}
        waits = [n for n in names if deps[n] is wait_for_run_turn]
        loads = [n for n in names if deps[n] is get_archivable_run]
        assert len(waits) == 1 and len(loads) == 1
        assert names.index(waits[0]) < names.index(loads[0])


class TestEveryRunSaverHasTheTurn:
    def test_every_function_that_saves_a_run_gets_it_from_get_editable_run(self):
        without = sorted(name for name, has_turn in _savers().items()
                         if not has_turn and name not in NO_TURN)
        assert without == []

    def test_every_name_without_a_turn_still_saves_a_run(self):
        """A name left here after its function changed would excuse nothing."""
        savers = _savers()
        assert sorted(name for name in NO_TURN if name not in savers) == []
        assert sorted(name for name in NO_TURN if savers[name]) == []

    def test_a_route_that_reads_without_a_turn_saves_nothing(self):
        readers = [fn.name for fn in _functions() if _depends_on(fn, "get_editable_run_to_read")]
        assert sorted(readers) == ["list_worklists", "preview_index_fill", "preview_paste",
                                   "preview_worklist"]
        assert [name for name in readers if name in _savers()] == []

    def test_the_scan_finds_the_editing_routes(self):
        """Control: the scan reaches the routes it is about, and tells a
        Depends(get_editable_run) from a name that only contains it."""
        savers = _savers()
        for name in ("update_sample_settings", "assign_index", "set_lanes_bulk", "update_run_name"):
            assert savers.get(name) is True, name
        fn = ast.parse("def f(run=Depends(get_editable_run_to_read)): pass").body[0]
        assert not _depends_on(fn, "get_editable_run")
