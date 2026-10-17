"""Every route that changes samples says what the page showed, or is named
here with the reason it need not.

CLAUDE.md, Data integrity: "A change from a page that is out of date is
refused, not applied" (docs/design/2026-10-17-stale-page-checks-design.md).
A route in ``routes/samples.py`` that answers POST, PUT, PATCH or DELETE must
read a ``target_*`` field -- what the page showed for the field it changes --
or be listed in NEED_NO_SHOWN_VALUE with the reason. A new route fails here
until someone decides which, so the rule does not depend on anyone
remembering it (the user's decision, 2026-10-17).
"""

import ast
import re
from pathlib import Path

ROUTES = Path(__file__).resolve().parents[2] / "src" / "seqsetup" / "routes" / "samples.py"
_CHANGING_METHODS = {"post", "put", "patch", "delete"}
_SHOWN_VALUE_FIELD = re.compile(r"\Atarget_[a-z_]+\Z")

# Each route here reads no target_* field, and why it need not.
NEED_NO_SHOWN_VALUE = {
    "add_sample": "adds a new row; changes no row the page showed",
    "add_bulk_samples": "a paste adds new rows; changes no row the page showed",
    "preview_paste": "saves nothing",
    "import_worklist_samples": ("adds new rows, and only the plan its preview showed "
                                "(the plan signature)"),
    "preview_index_fill": "saves nothing",
    "apply_index_fill": ("assigns only the plan its preview showed, rebuilt from the "
                         "stored run (the plan signature)"),
}


def _changing_routes(source: str) -> dict:
    """Handler name -> its function node, for each route in ``source`` that
    answers a method that can change something."""
    routes = {}
    for node in ast.parse(source).body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if (isinstance(decorator, ast.Call)
                    and isinstance(decorator.func, ast.Attribute)
                    and isinstance(decorator.func.value, ast.Name)
                    and decorator.func.value.id == "router"
                    and decorator.func.attr in _CHANGING_METHODS):
                routes[node.name] = node
    return routes


def _reads_a_shown_value(function) -> bool:
    """Whether the handler reads a target_* field: a parameter of that name
    (a DELETE's hx-vals arrive as query parameters), or a string in its code
    that is exactly such a name. A comment is not code, and a docstring that
    mentions one among other words is not that name."""
    arguments = function.args.args + function.args.kwonlyargs
    if any(_SHOWN_VALUE_FIELD.match(argument.arg) for argument in arguments):
        return True
    return any(isinstance(node, ast.Constant) and isinstance(node.value, str)
               and _SHOWN_VALUE_FIELD.match(node.value)
               for statement in function.body for node in ast.walk(statement))


class TestEverySampleChangeChecksThePage:

    def test_every_route_that_changes_samples_reads_what_the_page_showed(self):
        routes = _changing_routes(ROUTES.read_text())
        unchecked = sorted(name for name, function in routes.items()
                           if name not in NEED_NO_SHOWN_VALUE
                           and not _reads_a_shown_value(function))
        assert not unchecked, (
            f"{unchecked} change samples without reading what the page showed "
            "(a target_* field). Add the check (CLAUDE.md, 'A change from a page "
            "that is out of date is refused'), or list the route in "
            "NEED_NO_SHOWN_VALUE with the reason it need not.")

    def test_every_exception_names_a_route_that_reads_none(self):
        """A stale entry would let a route of that name skip the check."""
        routes = _changing_routes(ROUTES.read_text())
        for name in NEED_NO_SHOWN_VALUE:
            assert name in routes, f"{name} is no longer a route that changes something"
            assert not _reads_a_shown_value(routes[name]), (
                f"{name} reads a target_* field now: take it off the list")

    def test_the_scan_finds_the_routes_it_guards(self):
        routes = _changing_routes(ROUTES.read_text())
        for name in ("set_lanes_bulk", "delete_sample", "update_sample_settings",
                     "assign_index", "add_sample"):
            assert name in routes, f"the scan missed {name}"
        assert _reads_a_shown_value(routes["set_lanes_bulk"])
        assert _reads_a_shown_value(routes["delete_sample"])


class TestThePatternItself:

    _MODULE = '''
@router.post("/a")
async def reads_it(request):
    """Mentions target_lanes here, which does not count."""
    form = await request.form()
    return form.get("target_lanes")

@router.post("/b")
async def mentions_it_only_in_words(request):
    """Reads target_lanes, it says."""
    # target_lanes
    return None

@router.delete("/d")
def takes_it_as_a_parameter(request, target_indexes: str = ""):
    return target_indexes

@router.get("/c")
async def only_reads(request):
    return None

def not_a_route():
    return None
'''

    def test_only_routes_that_can_change_something_are_scanned(self):
        assert set(_changing_routes(self._MODULE)) == {
            "reads_it", "mentions_it_only_in_words", "takes_it_as_a_parameter"}

    def test_a_field_the_code_reads_counts(self):
        assert _reads_a_shown_value(_changing_routes(self._MODULE)["reads_it"])

    def test_a_query_parameter_of_that_name_counts(self):
        assert _reads_a_shown_value(_changing_routes(self._MODULE)["takes_it_as_a_parameter"])

    def test_a_field_named_only_in_the_docstring_or_a_comment_does_not(self):
        assert not _reads_a_shown_value(
            _changing_routes(self._MODULE)["mentions_it_only_in_words"])
