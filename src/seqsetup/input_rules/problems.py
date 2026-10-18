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
