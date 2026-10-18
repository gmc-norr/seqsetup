"""The strict base every rulebook derives from, and the building blocks they
share (docs/design/2026-10-18-input-rules-design.md, "2. Validate").

Pydantic's defaults are relaxed: an unknown key is ignored and "1" is read as
1. The base refuses both, checks defaults like written values, and keeps the
checked result from being reassigned. Strict mode still turns a whole number
into a float and still matches true and 2.0 against ``Literal[1, 2]``, so no
rulebook has a float field or a Literal of numbers; the guard test
(tests/unit/test_input_rules_guard.py) holds every rulebook to this.
"""

from typing import Annotated

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, StringConstraints

from ..services.sheet_text import PLAIN_NAME_RE, PLAIN_VERSION_RE

# MongoDB stores a whole number in 64 bits: a larger one passes a model and
# then fails to save. No range in a rulebook goes past it.
STORAGE_MAX_INT = 2**63 - 1

STRICT = ConfigDict(extra="forbid", strict=True, frozen=True, validate_default=True)


class StrictRules(BaseModel):
    """The base of every rulebook: unknown keys refused, no conversion between
    text, whole numbers and true/false, defaults checked."""

    model_config = STRICT


def _plain_name(value: str) -> str:
    if not PLAIN_NAME_RE.fullmatch(value):
        raise ValueError("may only hold letters, digits, '_' and '-'")
    return value


def _plain_version(value: str) -> str:
    if not PLAIN_VERSION_RE.fullmatch(value):
        raise ValueError("may only hold letters, digits, '.', '_' and '-'")
    return value


# A name written into a Sample Sheet as is.
PlainName = Annotated[str, StringConstraints(min_length=1, max_length=256), AfterValidator(_plain_name)]
# A version written into a Sample Sheet as is.
PlainVersion = Annotated[
    str, StringConstraints(min_length=1, max_length=256), AfterValidator(_plain_version)
]
# Text that must not be empty, such as a name shown to people.
Text256 = Annotated[str, StringConstraints(min_length=1, max_length=256)]
# Text that may be empty, such as a description.
Label = Annotated[str, StringConstraints(max_length=4096)]


def whole(low: int, high: int = STORAGE_MAX_INT):
    """A whole number from ``low`` to ``high``. Every whole number in a
    rulebook has a range: the narrowest its consumers accept unchanged."""
    return Annotated[int, Field(ge=low, le=min(high, STORAGE_MAX_INT))]
