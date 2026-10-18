"""The check pipeline: read, validate against a rulebook, run the cross-key
checks, and turn every finding into a problem with its place
(docs/design/2026-10-18-input-rules-design.md, "2. Validate", "3. Problems").

Messages are built here from the kind of error and the rulebook's own words.
Pydantic's message and the input value are never used: they can quote a
password.
"""

import typing
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

from pydantic import BaseModel, ValidationError

from .problems import InputProblem
from .reader import MAX_PROBLEMS_PER_FILE, Locations, read_yaml

FURTHER_CHECKS = "Further checks run once these problems are fixed."
UNKNOWN_KEY = "an unknown key"


@dataclass(frozen=True)
class Finding:
    """What a cross-key check or a warning found: the path it is about and
    a message of its own."""

    path: tuple
    message: str


@dataclass
class CheckResult:
    """The checked value (None when there is an error), every problem found,
    and a note saying more checks are waiting when some could not run."""

    value: Any
    problems: list[InputProblem] = field(default_factory=list)
    note: str = ""

    @property
    def ok(self) -> bool:
        return not any(problem.level == "error" for problem in self.problems)


CrossCheck = Callable[[Any], Iterable[Finding]]


def check_yaml(
    text: str,
    file: str,
    rulebook: type[BaseModel],
    *,
    cross_checks: Iterable[CrossCheck] = (),
    warnings: Optional[CrossCheck] = None,
    sensitive: bool = False,
    retired_keys: Optional[dict[str, str]] = None,
) -> CheckResult:
    """Check one YAML file against ``rulebook``. A ``sensitive`` file (one that
    can hold a secret) never has a value quoted, and a key name the rulebook
    does not define is kept only as "an unknown key"."""
    read = read_yaml(text, file, values_safe=not sensitive)
    if read.problems:
        return reader_refusal(read.problems, rulebook, sensitive)
    return check_data(read.data, read.locations, file, rulebook,
                      cross_checks=cross_checks, warnings=warnings, sensitive=sensitive,
                      retired_keys=retired_keys)


def reader_refusal(problems, rulebook: type[BaseModel], sensitive: bool = False) -> CheckResult:
    """The answer for a file the reader refused: its problems, and the note
    that the rulebook runs once they are fixed."""
    return _result(None, problems, FURTHER_CHECKS, rulebook, sensitive)


def check_data(
    data: Any,
    locations: Locations,
    file: str,
    rulebook: type[BaseModel],
    *,
    cross_checks: Iterable[CrossCheck] = (),
    warnings: Optional[CrossCheck] = None,
    sensitive: bool = False,
    retired_keys: Optional[dict[str, str]] = None,
) -> CheckResult:
    """Check data already read (with its locations) against ``rulebook``.
    ``retired_keys`` gives a key that is no longer read its own message
    instead of the unknown-key one."""
    if data is None:
        empty = InputProblem(file, 1, 1, (), "the file is empty")
        return _result(None, [empty], "", rulebook, sensitive)
    try:
        value = rulebook.model_validate(data)
    except ValidationError as error:
        problems = [_from_pydantic(item, locations, file, retired_keys or {})
                    for item in error.errors(include_url=False)]
        return _result(None, problems, FURTHER_CHECKS, rulebook, sensitive)

    problems = [
        _from_finding(finding, locations, file, "error")
        for check in cross_checks
        for finding in check(value)
    ]
    if problems:
        return _result(None, problems, "", rulebook, sensitive)
    if warnings is not None:
        problems = [_from_finding(finding, locations, file, "warning") for finding in warnings(value)]
    return _result(value, problems, "", rulebook, sensitive)


def _result(value, problems, note, rulebook, sensitive) -> CheckResult:
    if sensitive:
        known = _field_names(rulebook)
        problems = [_masked(problem, known) for problem in problems]
    if len(problems) > MAX_PROBLEMS_PER_FILE:
        left_out = len(problems) - MAX_PROBLEMS_PER_FILE
        last = problems[MAX_PROBLEMS_PER_FILE - 1]
        problems = problems[:MAX_PROBLEMS_PER_FILE] + [InputProblem(
            last.file, last.line, last.column, (), f"and {left_out} more problems not listed")]
    return CheckResult(value, problems, note if problems else "")


def _masked(problem: InputProblem, known: frozenset) -> InputProblem:
    path = tuple(
        item if isinstance(item, int) or item in known else UNKNOWN_KEY
        for item in problem.path
    )
    return InputProblem(problem.file, problem.line, problem.column, path,
                        problem.message, problem.level)


def _field_names(rulebook: type[BaseModel]) -> frozenset:
    """Every field name the rulebook and the models inside it define."""
    names: set = set()
    seen: set = set()

    def walk(annotation):
        if isinstance(annotation, type) and issubclass(annotation, BaseModel):
            if annotation in seen:
                return
            seen.add(annotation)
            for name, info in annotation.model_fields.items():
                names.add(name)
                walk(info.annotation)
            return
        for arg in typing.get_args(annotation):
            walk(arg)

    walk(rulebook)
    return frozenset(names)


def _place(locations: Locations, path: tuple, prefer_key: bool) -> tuple[int, int]:
    first, second = (locations.key, locations.value) if prefer_key else (locations.value, locations.key)
    for end in range(len(path), -1, -1):
        found = first(path[:end]) or second(path[:end])
        if found:
            return found
    return (1, 1)


def _from_finding(finding: Finding, locations: Locations, file: str, level: str) -> InputProblem:
    line, column = _place(locations, tuple(finding.path), prefer_key=True)
    return InputProblem(file, line, column, tuple(finding.path), finding.message, level)


def _from_pydantic(item: dict, locations: Locations, file: str, retired_keys: dict) -> InputProblem:
    loc = tuple(item["loc"])
    kind = item["type"]
    if loc and loc[-1] == "[key]":
        path = loc[:-1]
        line, column = _place(locations, path, prefer_key=True)
    elif kind == "missing":
        path = loc
        line, column = _place(locations, loc[:-1], prefer_key=False)
    elif kind == "extra_forbidden":
        path = loc
        line, column = _place(locations, path, prefer_key=True)
    else:
        path = loc
        line, column = _place(locations, path, prefer_key=False)
    message = _message(item)
    if kind == "extra_forbidden" and loc and loc[-1] in retired_keys:
        message = retired_keys[loc[-1]]
    return InputProblem(file, line, column, path, message)


_NO_VALUE = object()


def _message(item: dict) -> str:
    """A plain message for one Pydantic error, from its kind and the
    rulebook's own limits. The input is looked at only to tell a missing
    value from a value of another kind; it is never quoted."""
    kind = item["type"]
    ctx = item.get("ctx") or {}
    given = item.get("input", _NO_VALUE)
    if kind == "extra_forbidden":
        return "is not a key this file can have (check the spelling)"
    if kind == "missing":
        return "is required"
    if given is None:
        return "needs a value"
    if kind == "string_type":
        if isinstance(given, (int, bool)):
            return "must be text: put it in quotes"
        return "must be text"
    if kind in ("int_type", "int_parsing", "int_from_float"):
        return "must be a whole number"
    if kind == "bool_type":
        return "must be true or false"
    if kind in ("dict_type", "model_type", "model_attributes_type"):
        return "must be a map of keys and values"
    if kind == "list_type":
        return "must be a list"
    if kind == "literal_error":
        return f"must be one of: {ctx.get('expected')}"
    if kind == "greater_than_equal":
        return f"must be at least {ctx.get('ge')}"
    if kind == "less_than_equal":
        return f"must be at most {ctx.get('le')}"
    if kind == "greater_than":
        return f"must be more than {ctx.get('gt')}"
    if kind == "less_than":
        return f"must be less than {ctx.get('lt')}"
    if kind == "string_too_short":
        length = ctx.get("min_length")
        return "must not be empty" if length == 1 else f"must be at least {length} characters"
    if kind == "string_too_long":
        return f"must be at most {ctx.get('max_length')} characters"
    if kind == "too_short":
        return f"must have at least {ctx.get('min_length')} item(s)"
    if kind == "too_long":
        return f"must have at most {ctx.get('max_length')} item(s)"
    if kind in ("value_error", "assertion_error"):
        return str(ctx.get("error", "is not valid here"))
    return "is not valid here"
