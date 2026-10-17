"""Every route that changes samples says what the page showed, or is named
here with the reason it need not.

CLAUDE.md, Data integrity: "A change from a page that is out of date is
refused, not applied" (docs/design/2026-10-17-stale-page-checks-design.md).
A route of ``routes/samples.py`` that answers POST, PUT, PATCH or DELETE must
read one of SHOWN_VALUE_FIELDS -- what the page showed for the field it
changes -- or be listed in NEED_NO_SHOWN_VALUE with the reason. A new route
fails here until someone decides which, so the rule does not depend on anyone
remembering it (the user's decision, 2026-10-17).

The routes are read from the router itself, so a route added with a
decorator, ``api_route`` or ``add_api_route`` is scanned alike. What this
proves is that the route reads what the page showed, not that it compares
it: each route's own tests prove that.
"""

import ast
import inspect
import textwrap

from fastapi import APIRouter

from seqsetup.routes.samples import router

_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# What the page showed for the field a route changes, one per kind of field.
# target_sample_ids is not one: it says which rows, not what they showed.
SHOWN_VALUE_FIELDS = {
    "target_indexes", "target_lanes", "target_mismatches",
    "target_override_cycles", "target_tests", "target_setting",
}

# Each route here reads none of them, and why it need not.
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


def _changing_routes(a_router) -> dict:
    """Handler name -> its function node, for each route of ``a_router`` that
    answers a method that can change something."""
    found = {}
    for route in a_router.routes:
        if set(getattr(route, "methods", None) or ()) & _CHANGING_METHODS:
            source = textwrap.dedent(inspect.getsource(route.endpoint))
            found[route.endpoint.__name__] = ast.parse(source).body[0]
    return found


def _reads_a_shown_value(function) -> bool:
    """Whether the handler reads one of SHOWN_VALUE_FIELDS: a parameter of
    that name (a DELETE's hx-vals arrive as query parameters), or a string in
    its code that is exactly that name. A comment is not code, and a
    docstring that mentions one among other words is not that name."""
    arguments = function.args.args + function.args.kwonlyargs
    if any(argument.arg in SHOWN_VALUE_FIELDS for argument in arguments):
        return True
    return any(isinstance(node, ast.Constant) and isinstance(node.value, str)
               and node.value in SHOWN_VALUE_FIELDS
               for statement in function.body for node in ast.walk(statement))


class TestEverySampleChangeChecksThePage:

    def test_every_route_that_changes_samples_reads_what_the_page_showed(self):
        routes = _changing_routes(router)
        unchecked = sorted(name for name, function in routes.items()
                           if name not in NEED_NO_SHOWN_VALUE
                           and not _reads_a_shown_value(function))
        assert not unchecked, (
            f"{unchecked} change samples without reading what the page showed "
            f"(one of {sorted(SHOWN_VALUE_FIELDS)}). Add the check (CLAUDE.md, 'A "
            "change from a page that is out of date is refused'), or list the "
            "route in NEED_NO_SHOWN_VALUE with the reason it need not.")

    def test_every_exception_names_a_route_that_reads_none(self):
        """A stale entry would let a route of that name skip the check."""
        routes = _changing_routes(router)
        for name in NEED_NO_SHOWN_VALUE:
            assert name in routes, f"{name} is no longer a route that changes something"
            assert not _reads_a_shown_value(routes[name]), (
                f"{name} reads what the page showed now: take it off the list")

    def test_the_scan_finds_the_routes_it_guards(self):
        routes = _changing_routes(router)
        for name in ("set_lanes_bulk", "delete_sample", "update_sample_settings",
                     "assign_index", "add_sample"):
            assert name in routes, f"the scan missed {name}"
        assert _reads_a_shown_value(routes["set_lanes_bulk"])
        assert _reads_a_shown_value(routes["delete_sample"])


# A router of its own for the tests of the scan itself.
_example = APIRouter()


@_example.post("/a")
async def reads_it(request):
    """Mentions target_lanes here, which does not count."""
    form = await request.form()
    return form.get("target_lanes")


@_example.post("/b")
async def mentions_it_only_in_words(request):
    """Reads target_lanes, it says."""
    # target_lanes
    return None


@_example.delete("/d")
def takes_it_as_a_parameter(request, target_indexes: str = ""):
    return target_indexes


@_example.api_route("/e", methods=["POST"])
async def added_with_api_route(request):
    return None


async def added_with_add_api_route(request):
    return None


_example.add_api_route("/f", added_with_add_api_route, methods=["PATCH"])


@_example.post("/g")
async def reads_only_which_rows(request):
    form = await request.form()
    return form.get("target_sample_ids")


@_example.get("/c")
async def only_reads(request):
    return None


class TestTheScanItself:

    def test_every_route_that_can_change_something_is_scanned_however_it_was_added(self):
        assert set(_changing_routes(_example)) == {
            "reads_it", "mentions_it_only_in_words", "takes_it_as_a_parameter",
            "added_with_api_route", "added_with_add_api_route", "reads_only_which_rows"}

    def test_a_field_the_code_reads_counts(self):
        assert _reads_a_shown_value(_changing_routes(_example)["reads_it"])

    def test_a_query_parameter_of_that_name_counts(self):
        assert _reads_a_shown_value(_changing_routes(_example)["takes_it_as_a_parameter"])

    def test_a_field_named_only_in_the_docstring_or_a_comment_does_not(self):
        assert not _reads_a_shown_value(_changing_routes(_example)["mentions_it_only_in_words"])

    def test_which_rows_alone_is_not_what_they_showed(self):
        assert not _reads_a_shown_value(_changing_routes(_example)["reads_only_which_rows"])
