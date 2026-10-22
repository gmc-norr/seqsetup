"""A kit file's refusal shows where a name holds a hidden character.

A zero-width space on one side of an Illumina YAML or TSV pair makes the i7 and
the i5 two names, so the pairing check refuses the file before the rulebook
sees it -- and its message listed two names that looked the same, with nothing
about the character between them (review leftover O6). The file was refused
and nothing saved; only the message could not be acted on.
"""

import pytest

from seqsetup.models.index import IndexMode
from seqsetup.services.index_parser import IndexParser, UnpairedIndexes


def _illumina_yaml(i7: dict, i5: dict) -> str:
    lines = ["Name: Old kit", 'Version: "1.0"', "IndexSequences:", "  i7Index1:"]
    lines += [f"    {name}: {seq}" for name, seq in i7.items()]
    lines += ["  i5Index2:"] + [f"    {name}: {seq}" for name, seq in i5.items()]
    return "\n".join(lines) + "\n"


def _illumina_tsv(i7: dict, i5: dict) -> str:
    lines = ["[IndexKit]", "Name\tOld kit", "Version\t1.0", "", "[Indices]", "Name\tSequence\tIndexNumber"]
    lines += [f"{name}\t{seq}\t1" for name, seq in i7.items()]
    lines += [f"{name}\t{seq}\t2" for name, seq in i5.items()]
    return "\n".join(lines)


SHAPES = {"yaml": _illumina_yaml, "tsv": _illumina_tsv}


def _refusal(shape: str, i5_name: str) -> str:
    text = SHAPES[shape]({"D701": "ATTACTCG", "D702": "TCCGGAGA"},
                         {"D701": "TATAGCCT", i5_name: "ATAGAGGC"})
    with pytest.raises(UnpairedIndexes) as refused:
        IndexParser.parse_from_content(text, f"kit.{shape}", shape,
                                       index_mode=IndexMode.UNIQUE_DUAL)
    return str(refused.value)


@pytest.mark.parametrize("shape", sorted(SHAPES))
class TestTheMessageNamesTheCharacter:
    def test_a_zero_width_space(self, shape):
        message = _refusal(shape, "D70​2")
        assert "U+200B" in message
        assert "hidden character" in message

    def test_the_character_itself_is_not_in_the_message(self, shape):
        # A direction override in a message would reorder the page around it.
        message = _refusal(shape, "D70‮2")
        assert "‮" not in message
        assert "U+202E" in message


@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_a_plain_unpaired_name_is_shown_as_it_is(shape):
    message = _refusal(shape, "D799")
    assert "'D799'" in message
    assert "hidden character" not in message
