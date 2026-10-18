"""What a check found: one problem per thing wrong, with where it is."""

from dataclasses import dataclass
from typing import Optional, Union

PathItem = Union[str, int]


@dataclass(frozen=True)
class InputProblem:
    """One thing wrong with an input. ``path`` is the keys and list indexes
    down to it, ``line`` and ``column`` count from 1 (``column`` is None when
    not known), and ``message`` is built by this package from the path and
    the kind of problem -- never a parser's or Pydantic's own text, which can
    quote a password."""

    file: str
    line: int
    column: Optional[int]
    path: tuple[PathItem, ...]
    message: str
    level: str = "error"


def problem_record(problem: InputProblem) -> dict:
    """The problem as plain data a MongoDB document can hold."""
    return {
        "file": problem.file, "line": problem.line, "column": problem.column,
        "path": list(problem.path), "message": problem.message, "level": problem.level,
    }


def problem_from_record(record: dict) -> InputProblem:
    return InputProblem(record["file"], record["line"], record["column"],
                        tuple(record["path"]), record["message"], record["level"])


_CUT = " [cut: the list of problems has the rest]"

# What a report may take in each store (encoded bytes, message included): the
# sync status shares one MongoDB document (16 MiB at most) with the settings,
# and an audit row's details are dropped whole above 64 KiB
# (models/audit_event.py, MAX_DETAILS_BYTES).
SYNC_STATUS_BUDGET = 1024 * 1024
AUDIT_BUDGET = 32 * 1024


def _encoded_size(value) -> int:
    import bson

    return len(bson.encode({"details": value}))


def bounded_report(message: str, problems: list[InputProblem], budget_bytes: int) -> dict:
    """``message`` and ``problems`` as one plain report whose encoded size
    (BSON, as MongoDB stores it) stays within ``budget_bytes``: the message is
    cut to a quarter of the budget at most, then problems are kept in order
    while they fit. The count of problems and the number left out are always
    kept, so a store never loses the report whole
    (docs/design/2026-10-18-input-rules-design.md, "6. Where problems are shown")."""
    report = {"message": "", "problems": [], "problem_count": len(problems),
              "problems_left_out": len(problems)}
    room = budget_bytes - _encoded_size(report)
    encoded = message.encode("utf-8")
    most = max(0, budget_bytes // 4 - len(_CUT.encode("utf-8")))
    if len(encoded) > most:
        message = encoded[:most].decode("utf-8", "ignore") + _CUT
    report["message"] = message
    room -= len(message.encode("utf-8"))
    for problem in problems:
        record = problem_record(problem)
        # An element of a BSON array costs its encoded value plus its index
        # key; measuring the record as a one-item document is close and
        # never smaller, and the final check below is exact.
        cost = _encoded_size(record)
        if cost > room:
            break
        report["problems"].append(record)
        room -= cost
    while report["problems"] and _encoded_size(report) > budget_bytes:
        report["problems"].pop()
    report["problems_left_out"] = len(problems) - len(report["problems"])
    return report


def path_text(path: tuple[PathItem, ...]) -> str:
    """The path as a person reads it: ``flowcells > 10B > lanes``, a list
    item as ``item 1``, the whole file as ``the file``."""
    if not path:
        return "the file"
    return " > ".join(
        f"item {item + 1}" if isinstance(item, int) and not isinstance(item, bool) else str(item)
        for item in path
    )


def problem_line(problem: InputProblem) -> str:
    """``file:line:column: path: message``, a warning marked as one."""
    where = f"{problem.file}:{problem.line}"
    if problem.column is not None:
        where += f":{problem.column}"
    mark = "" if problem.level == "error" else "warning: "
    return f"{where}: {mark}{path_text(problem.path)}: {problem.message}"
