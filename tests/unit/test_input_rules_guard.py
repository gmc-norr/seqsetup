"""Every rulebook stays strict (docs/design/2026-10-18-input-rules-design.md,
"2. Validate").

One loosened rulebook brings back what the package exists to stop: an unknown
key ignored, "2" read as 2. Strict mode also has gaps of its own -- a whole
number turned into a float, true and 2.0 matched against Literal[1, 2], one
field switched back to lax with Field(strict=False) -- so this guard looks for
those too, in every model the package defines.
"""

import importlib
import inspect
import pkgutil
import typing
from typing import Literal

import pydantic
import pytest
from pydantic import BaseModel, ConfigDict, Field

import seqsetup.input_rules as package
from seqsetup.input_rules.base import STRICT, StrictRules


def _models():
    found = []
    for info in pkgutil.walk_packages(package.__path__, package.__name__ + "."):
        module = importlib.import_module(info.name)
        for _name, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, BaseModel) and obj.__module__ == module.__name__:
                found.append(obj)
    return found


def _annotation_problems(annotation) -> list[str]:
    problems = []
    if annotation is float:
        problems.append("a float field")
    origin = typing.get_origin(annotation)
    if origin is Literal and any(not isinstance(v, str) for v in typing.get_args(annotation)):
        problems.append("a Literal of something other than text")
    if origin in (set, frozenset):
        problems.append("a set (a file's list is a list whose items must be distinct)")
    for meta in getattr(annotation, "__metadata__", ()):
        if getattr(meta, "strict", None) is False:
            problems.append("a value loosened with strict=False")
    for arg in typing.get_args(annotation):
        if not isinstance(arg, (str, int, bool)):
            problems += _annotation_problems(arg)
    return problems


def guard_problems(model) -> list[str]:
    """What is not strict about ``model``."""
    problems = []
    if model is not StrictRules and not issubclass(model, StrictRules):
        problems.append("does not derive from StrictRules")
    for key in ("extra", "strict", "frozen", "validate_default"):
        if model.model_config.get(key) != STRICT[key]:
            problems.append(f"model_config {key} is {model.model_config.get(key)!r}")
    for name, info in model.model_fields.items():
        for meta in info.metadata:
            if getattr(meta, "strict", None) is False:
                problems.append(f"{name}: strict=False")
        problems += [f"{name}: {p}" for p in _annotation_problems(info.annotation)]
    return problems


class TestEveryRulebookIsStrict:

    def test_the_package_defines_rulebooks(self):
        assert StrictRules in _models()

    @pytest.mark.parametrize("model", _models(), ids=lambda m: m.__name__)
    def test_rulebook(self, model):
        assert guard_problems(model) == []


class TestTheGuardCatchesEachLoophole:

    def test_a_model_not_built_on_the_base(self):
        class Lax(BaseModel):
            a: int

        assert "does not derive from StrictRules" in guard_problems(Lax)

    def test_a_loosened_config(self):
        class Lax(StrictRules):
            model_config = ConfigDict(extra="ignore")

        assert any("extra" in p for p in guard_problems(Lax))

    def test_one_field_loosened(self):
        class Lax(StrictRules):
            a: int = Field(strict=False)

        assert any("strict=False" in p for p in guard_problems(Lax))

    def test_one_value_loosened_inside_a_list(self):
        class Lax(StrictRules):
            a: list[typing.Annotated[int, pydantic.Strict(False)]]

        assert any("strict=False" in p for p in guard_problems(Lax))

    def test_a_float_field(self):
        class Lax(StrictRules):
            a: dict[str, float]

        assert any("float" in p for p in guard_problems(Lax))

    def test_a_literal_of_numbers(self):
        class Lax(StrictRules):
            a: list[Literal[1, 2]]

        assert any("Literal" in p for p in guard_problems(Lax))

    def test_a_set(self):
        class Lax(StrictRules):
            a: set[int]

        assert any("set" in p for p in guard_problems(Lax))
