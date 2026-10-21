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

from ..services.sheet_text import PLAIN_NAME_RE, PLAIN_VERSION_RE, describe, hidden_characters

# MongoDB stores a whole number in 64 bits: a larger one passes a model and
# then fails to save. No range in a rulebook goes past it.
STORAGE_MAX_INT = 2**63 - 1

STRICT = ConfigDict(extra="forbid", strict=True, frozen=True, validate_default=True)


class StrictRules(BaseModel):
    """The base of every rulebook: unknown keys refused, no conversion between
    text, whole numbers and true/false, defaults checked."""

    model_config = STRICT


def _hidden(value: str) -> None:
    chars = hidden_characters(value)
    if chars:
        raise ValueError(f"holds a hidden character: {describe(chars)}")


def _plain_name(value: str) -> str:
    _hidden(value)
    if not PLAIN_NAME_RE.fullmatch(value):
        raise ValueError("may only hold letters, digits, '_' and '-'")
    return value


def _plain_version(value: str) -> str:
    _hidden(value)
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


def _filled(value: str) -> str:
    if not value.strip():
        raise ValueError("must not be empty")
    return value


# Text that must hold more than spaces, kept as written (never trimmed).
FilledText256 = Annotated[str, StringConstraints(min_length=1, max_length=256), AfterValidator(_filled)]
FilledText4096 = Annotated[str, StringConstraints(min_length=1, max_length=4096), AfterValidator(_filled)]


def _exact_name(value: str) -> str:
    _hidden(value)
    ends = value[: len(value) - len(value.lstrip())] + value[len(value.rstrip()):]
    if ends:
        raise ValueError(f"must not begin or end with a space: {describe(list(dict.fromkeys(ends)))}")
    return value


# Text a sample names exactly, such as a TestName. Every page trims what is
# picked or pasted, so a space at either end would match another name or none,
# and a hidden character would make two names look like one.
ExactName256 = Annotated[
    str, StringConstraints(min_length=1, max_length=256), AfterValidator(_filled), AfterValidator(_exact_name)
]
# Text that may be empty, such as a description.
Label = Annotated[str, StringConstraints(max_length=4096)]


# The onboard applications as Illumina's NovaSeq X and NextSeq 1000/2000
# sample sheet version histories name their sections
# (help.connected.illumina.com, 2026-10-17;
# docs/design/2026-10-17-rna-section-spelling-design.md). An application
# Illumina adds is added here, with its source, before a file may name it.
ILLUMINA_APPLICATION_NAMES = (
    "BCLConvert", "DragenGermline", "DragenSomatic", "DragenRna",
    "DragenEnrichment", "DragenMethylation",
)


def _illumina_application(value: str) -> str:
    if value not in ILLUMINA_APPLICATION_NAMES:
        raise ValueError(
            "is not one of Illumina's application names ("
            + ", ".join(ILLUMINA_APPLICATION_NAMES) + ")"
        )
    return value


IlluminaApplicationName = Annotated[str, AfterValidator(_illumina_application)]


def whole(low: int, high: int = STORAGE_MAX_INT):
    """A whole number from ``low`` to ``high``. Every whole number in a
    rulebook has a range: the narrowest its consumers accept unchanged."""
    return Annotated[int, Field(ge=low, le=min(high, STORAGE_MAX_INT))]
