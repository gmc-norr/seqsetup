"""The YAML reader every settings file goes through.

PyYAML changes values on its own before any check sees them: ``012`` is 10,
``0x10`` is 16, ``1:20`` is 80, ``yes`` is True, ``1.10`` is 1.1, a date
becomes a ``date``, and a tag (``!!int "012"``) brings any of these back
however the value is quoted. Two keys that read as one (``1`` and ``true``,
``a`` and ``'a'``) merge, and an anchor can expand a small file into gigabytes.

So this reader uses PyYAML only to compose the document into nodes, and builds
the values itself: one plain spelling per kind of value, every other spelling
refused; no tags, anchors, aliases or merge keys; a key given twice refused
after it is read. It records the line and column of every key, value and list
item, so every problem can say where it is
(docs/design/2026-10-18-input-rules-design.md, "1. Read").
"""

import re
from dataclasses import dataclass, field
from typing import Any, Optional

import yaml

from .problems import InputProblem, key_text

MAX_PROBLEMS_PER_FILE = 1000

_WHOLE_NUMBER = re.compile(r"-?(0|[1-9][0-9]*)")
_HALF_CHARACTER = re.compile("[\ud800-\udfff]")
_YAML = "tag:yaml.org,2002:"

_PLAIN_DIGITS = (
    "write a whole number as plain digits (no leading 0, no 0x, _, + or :), "
    "or put it in quotes if it is text"
)
_DECIMAL = "is read as a decimal number, which this file does not use: put it in quotes if it is text"
_YES_NO = "write true or false (yes, no, on and off are not used)"
_DATE = "is read as a date or time: put it in quotes"
_UNREADABLE_VALUE = "cannot be read as a plain value: put it in quotes if it is text"
_TAG = "a YAML tag (!, !!int, !!str, ...) is not allowed"
_ANCHOR = "a YAML anchor (&name) is not allowed"
_ALIAS = "a YAML alias (*name) is not allowed"
_MERGE = "a merge key (<<) is not allowed"
_KEY_NOT_PLAIN = "a key must be a plain value, not a list or a map"
_MORE_THAN_ONE = "holds more than one YAML document"
_HALF = "holds half of a character (a \\uD800-\\uDFFF escape): write the whole character"
_TOO_LONG = "is too long a number to read"
_CONTROL = "a control character (such as a form feed or NUL) a YAML file cannot hold: remove it"
_TOO_DEEP = "nests lists and maps too deep to read"
# The wording of a key given twice, which the kit checker recognises to keep
# the upload's ``repeated_names`` audit reason.
GIVEN_TWICE = "is given twice in one map"
# How much of a value a message may quote. ``values_safe`` quoted the whole
# scalar, so a 100,000-character value gave a message just as long, shown in
# the admin's HTML and printed by the settings command.
MOST_QUOTED = 60

# A fixed explanation per kind of parser error, chosen by the parser's own
# wording but never repeating it: that text can quote the line, and the line
# can hold a password.
_SYNTAX = [
    (("cannot start any token", "\\t"), "a tab: indent with spaces only"),
    (("found character '\\t'",), "a tab: indent with spaces only"),
    (("cannot start any token",), "a character that cannot start a value here: put the value in quotes"),
    (("expected ',' or ']'",), "a [ list ] that is not closed"),
    (("expected ',' or '}'",), "a { map } that is not closed"),
    (("while parsing a flow sequence",), "a [ list ] that is not closed"),
    (("while parsing a flow mapping",), "a { map } that is not closed"),
    (("while scanning a quoted scalar",), "a quoted value that is not closed"),
    (("mapping values are not allowed",), "a ':' where none can be: a value holding ': ' must be in quotes"),
    (("could not find expected ':'",), "a key with no ':' after it"),
    (("expected <block end>",), "the indentation does not line up"),
    (("did not find expected key",), "the indentation does not line up"),
    (("did not find expected '-'",), "the indentation does not line up"),
    (("while scanning a simple key",), "a key with no ':' after it"),
]
_SYNTAX_OTHER = "is not valid YAML here"


@dataclass
class Locations:
    """Where each key, value and list item came from: (line, column), both
    counted from 1. A path is looked up by the text of its items, so a map key
    read as the number 300 is found as 300 or "300"."""

    _keys: dict = field(default_factory=dict)
    _values: dict = field(default_factory=dict)

    @staticmethod
    def _id(path) -> tuple:
        return tuple(key_text(item) for item in path)

    def key(self, path) -> Optional[tuple[int, int]]:
        return self._keys.get(self._id(path))

    def value(self, path) -> Optional[tuple[int, int]]:
        return self._values.get(self._id(path))

    def _set_key(self, path, mark) -> None:
        self._keys[self._id(path)] = (mark.line + 1, mark.column + 1)

    def _set_value(self, path, mark) -> None:
        self._values[self._id(path)] = (mark.line + 1, mark.column + 1)

    def at(self, path, line: int, column: Optional[int] = None) -> None:
        """Record a line (and column) for a path a reader of another format
        knows: the kit adapters build a canonical map out of a TSV's or a
        CSV's own lines, so a problem the rulebook finds in it still names
        the line it came from."""
        self._keys[self._id(path)] = (line, column)
        self._values[self._id(path)] = (line, column)


@dataclass
class ReadResult:
    """The data read (None when there is any problem), its locations, and the
    problems found."""

    data: Any
    locations: Locations
    problems: list[InputProblem]


class _Problems:
    """Problems of one file, cut at MAX_PROBLEMS_PER_FILE with a count of the
    rest, so a broken or hostile file cannot fill the memory."""

    def __init__(self, file: str):
        self.file = file
        self.found: list[InputProblem] = []
        self.left_out = 0

    def add(self, mark, path, message) -> None:
        if len(self.found) >= MAX_PROBLEMS_PER_FILE:
            self.left_out += 1
            return
        line, column = (mark.line + 1, mark.column + 1) if mark is not None else (1, 1)
        path = tuple(item if isinstance(item, int) else key_text(item) for item in path)
        self.found.append(InputProblem(self.file, line, column, path, message))

    def all(self) -> list[InputProblem]:
        if not self.left_out:
            return list(self.found)
        last = self.found[-1]
        return self.found + [InputProblem(
            self.file, last.line, last.column, (),
            f"and {self.left_out} more problems not listed",
        )]


class _Composer(yaml.SafeLoader):
    """PyYAML's loader used only up to the node tree. A tag, anchor or alias
    is noted and dropped, so nothing is ever expanded and every one in the
    file is reported."""

    def __init__(self, text, problems: _Problems):
        super().__init__(text)
        self.noted = problems

    def compose_node(self, parent, index):
        if self.check_event(yaml.events.AliasEvent):
            event = self.get_event()
            self.noted.add(event.start_mark, (), _ALIAS)
            return yaml.ScalarNode(_YAML + "null", "", event.start_mark, event.end_mark)
        event = self.peek_event()
        if event.anchor is not None:
            self.noted.add(event.start_mark, (), _ANCHOR)
            event.anchor = None
        if getattr(event, "tag", None) is not None:
            self.noted.add(event.start_mark, (), _TAG)
            event.tag = None
            if isinstance(event, yaml.events.ScalarEvent):
                event.implicit = (True, True)
        return super().compose_node(parent, index)


class _Builder:
    """Builds plain values from the node tree with the spelling rules."""

    def __init__(self, problems: _Problems, values_safe: bool):
        self.problems = problems
        self.values_safe = values_safe
        self.locations = Locations()

    def _refuse(self, node, path, message) -> None:
        if self.values_safe and isinstance(node, yaml.ScalarNode):
            shown = node.value
            if len(shown) > MOST_QUOTED:
                shown = shown[:MOST_QUOTED] + "…"
            message = f"{shown!r}: {message}"
        self.problems.add(node.start_mark, path, message)

    def build(self, node, path=()):
        self.locations._set_value(path, node.start_mark)
        if isinstance(node, yaml.ScalarNode):
            return self.scalar(node, path)
        if isinstance(node, yaml.SequenceNode):
            return [self.build(item, (*path, index)) for index, item in enumerate(node.value)]
        return self.mapping(node, path)

    def mapping(self, node, path):
        built: dict = {}
        first_line: dict = {}
        for key_node, value_node in node.value:
            if not isinstance(key_node, yaml.ScalarNode):
                self.problems.add(key_node.start_mark, path, _KEY_NOT_PLAIN)
                continue
            if key_node.tag == _YAML + "merge" and key_node.style is None:
                self.problems.add(key_node.start_mark, path, _MERGE)
                continue
            key = self.scalar(key_node, (*path, key_node.value))
            if key is _REFUSED:
                self.build(value_node, (*path, key_node.value))
                continue
            key_path = (*path, key_text(key))
            if key in first_line:
                self.problems.add(
                    key_node.start_mark, key_path,
                    f"{GIVEN_TWICE} (also on line {first_line[key]})",
                )
                continue
            first_line[key] = key_node.start_mark.line + 1
            self.locations._set_key(key_path, key_node.start_mark)
            built[key] = self.build(value_node, key_path)
        return built

    def scalar(self, node, path):
        if _HALF_CHARACTER.search(node.value):
            self.problems.add(node.start_mark, path, _HALF)
            return _REFUSED
        if node.style is not None:
            return node.value
        tag = node.tag
        if tag == _YAML + "str":
            return node.value
        if tag == _YAML + "null":
            return None
        if tag == _YAML + "bool":
            if node.value.lower() in ("true", "false"):
                return node.value.lower() == "true"
            self._refuse(node, path, _YES_NO)
            return _REFUSED
        if tag == _YAML + "int":
            if _WHOLE_NUMBER.fullmatch(node.value):
                try:
                    return int(node.value)
                except ValueError:
                    # Past Python's limit on digits; no setting comes near it.
                    self.problems.add(node.start_mark, path, _TOO_LONG)
                    return _REFUSED
            self._refuse(node, path, _PLAIN_DIGITS)
            return _REFUSED
        if tag == _YAML + "float":
            self._refuse(node, path, _DECIMAL)
            return _REFUSED
        if tag == _YAML + "timestamp":
            self._refuse(node, path, _DATE)
            return _REFUSED
        self._refuse(node, path, _UNREADABLE_VALUE)
        return _REFUSED


_REFUSED = object()


def _syntax_message(error: yaml.YAMLError) -> str:
    said = " ".join(
        str(part) for part in (getattr(error, "context", None), getattr(error, "problem", None))
        if part
    )
    for words, message in _SYNTAX:
        if all(word in said for word in words):
            return message
    return _SYNTAX_OTHER


class _At:
    """A place in the text, counted from 0 as PyYAML's marks are."""

    def __init__(self, text: str, position: int):
        self.line = text.count("\n", 0, position)
        self.column = position - (text.rfind("\n", 0, position) + 1)


def read_yaml(text: str, file: str, values_safe: bool = False) -> ReadResult:
    """Read one YAML document. ``values_safe`` lets a message quote the value
    it is about; leave it False for a file that can hold a secret.

    Every file gives problems, never an exception: a control character, a
    number past Python's digit limit or lists nested past its recursion limit
    once stopped start-up with a traceback and the settings command part way."""
    problems = _Problems(file)
    try:
        composer = _Composer(text, problems)
    except yaml.reader.ReaderError as error:
        problems.add(_At(text, error.position), (), _CONTROL)
        return ReadResult(None, Locations(), problems.all())
    try:
        node = composer.get_single_node()
    except yaml.reader.ReaderError as error:
        problems.add(_At(text, error.position), (), _CONTROL)
        return ReadResult(None, Locations(), problems.all())
    except RecursionError:
        problems.add(None, (), _TOO_DEEP)
        return ReadResult(None, Locations(), problems.all())
    except yaml.composer.ComposerError as error:
        said = f"{getattr(error, 'context', '')} {getattr(error, 'problem', '')}"
        if "single document" in said:
            problems.add(getattr(error, "problem_mark", None), (), _MORE_THAN_ONE)
        else:
            problems.add(getattr(error, "problem_mark", None), (), _syntax_message(error))
        return ReadResult(None, Locations(), problems.all())
    except yaml.YAMLError as error:
        problems.add(getattr(error, "problem_mark", None), (), _syntax_message(error))
        return ReadResult(None, Locations(), problems.all())
    finally:
        composer.dispose()

    builder = _Builder(problems, values_safe)
    try:
        data = builder.build(node) if node is not None else None
    except RecursionError:
        problems.add(None, (), _TOO_DEEP)
        return ReadResult(None, Locations(), problems.all())
    found = problems.all()
    return ReadResult(None if found else data, builder.locations, found)
