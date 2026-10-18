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
