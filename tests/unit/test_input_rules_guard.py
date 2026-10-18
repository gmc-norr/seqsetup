"""Every rulebook stays strict (docs/design/2026-10-18-input-rules-design.md,
"2. Validate").

One loosened rulebook brings back what the package exists to stop: an unknown
key ignored, "2" read as 2. Strict mode also has gaps of its own -- a whole
number turned into a float, true and 2.0 matched against Literal[1, 2], one
field switched back to lax with Field(strict=False), a validator that runs
before the type check (``BeforeValidator(int)`` reads "012" as 12), a value
typed Any -- so this guard looks for those too, in every model the package
defines.
"""

import importlib
import inspect
import pkgutil
import typing
from typing import Literal

import pydantic
import pytest
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, PlainValidator, WrapValidator
from pydantic.fields import FieldInfo

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


_BEFORE_THE_TYPE_CHECK = "a validator that runs before the type check"


def _meta_problems(meta) -> list[str]:
    if isinstance(meta, FieldInfo):
        return [p for inner in meta.metadata for p in _meta_problems(inner)]
    if getattr(meta, "strict", None) is False:
        return ["a value loosened with strict=False"]
    if isinstance(meta, (BeforeValidator, PlainValidator, WrapValidator)):
        return [_BEFORE_THE_TYPE_CHECK]
    return []


def _annotation_problems(annotation) -> list[str]:
    problems = []
    if annotation is typing.Any or annotation is object:
        problems.append("a value that takes anything (Any)")
    if annotation is float:
        problems.append("a float field")
    origin = typing.get_origin(annotation)
    if origin is Literal and any(not isinstance(v, str) for v in typing.get_args(annotation)):
        problems.append("a Literal of something other than text")
    if origin in (set, frozenset):
        problems.append("a set (a file's list is a list whose items must be distinct)")
    for meta in getattr(annotation, "__metadata__", ()):
        problems += _meta_problems(meta)
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
            problems += [f"{name}: {p}" for p in _meta_problems(meta)]
        problems += [f"{name}: {p}" for p in _annotation_problems(info.annotation)]
    decorators = model.__pydantic_decorators__
    for name, decorator in decorators.field_validators.items():
        if decorator.info.mode != "after":
            problems.append(f"{name}: {_BEFORE_THE_TYPE_CHECK}")
    for name, decorator in decorators.model_validators.items():
        if decorator.info.mode != "after":
            problems.append(f"{name}: {_BEFORE_THE_TYPE_CHECK}")
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

    def test_one_value_loosened_with_field_inside_a_list(self):
        class Lax(StrictRules):
            a: list[typing.Annotated[int, Field(strict=False)]]

        assert any("strict=False" in p for p in guard_problems(Lax))

    @pytest.mark.parametrize("validator", [
        pydantic.BeforeValidator(int),
        pydantic.PlainValidator(int),
        pydantic.WrapValidator(lambda value, handler: handler(int(value))),
    ], ids=["before", "plain", "wrap"])
    @pytest.mark.parametrize("inside", [False, True], ids=["field", "list item"])
    def test_a_validator_that_runs_before_the_type_check(self, validator, inside):
        value = typing.Annotated[int, validator]

        class Lax(StrictRules):
            a: list[value] if inside else value

        assert any("before the type check" in p for p in guard_problems(Lax))

    @pytest.mark.parametrize("mode", ["before", "plain", "wrap"])
    def test_a_field_validator_that_runs_before_the_type_check(self, mode):
        def plain(cls, value):
            return int(value)

        def wrap(cls, value, handler):
            return handler(int(value))

        class Lax(StrictRules):
            a: int
            _a = pydantic.field_validator("a", mode=mode)(classmethod(wrap if mode == "wrap" else plain))

        assert any("before the type check" in p for p in guard_problems(Lax))

    def test_a_model_validator_that_runs_before_the_type_check(self):
        class Lax(StrictRules):
            a: int

            @pydantic.model_validator(mode="before")
            @classmethod
            def _all(cls, data):
                return data

        assert any("before the type check" in p for p in guard_problems(Lax))

    def test_a_value_that_takes_anything(self):
        class Lax(StrictRules):
            a: dict[str, typing.Any]

        assert any("anything" in p for p in guard_problems(Lax))
