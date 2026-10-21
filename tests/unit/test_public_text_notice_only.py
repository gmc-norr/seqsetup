"""The project's public text carries the plain use-at-your-own-risk notice and
says nothing about clinical or production readiness.

The repository is public. The README and the built documentation are what a
reader outside the lab sees: they state the notice, and they never claim (or
deny) readiness for clinical or production use, CE marking, IVDR conformity, or
say who must validate what. Design notes under ``docs/design/`` are the
project's own history and are not scanned.
"""

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

# The sentences the notice is made of, in the words README.md uses.
NOTICE = (
    "**Use at your own risk.**",
    "SeqSetup is provided as is, without warranty of any kind.",
    "Its authors and the organisations they work for are not responsible for any "
    "harm, loss or damage that comes from using it.",
)

# Readiness talk: a claim either way needs a judgement this project does not make
# in public text.
REFUSED = (
    "ready for production",
    "production use",
    "clinical safety",
    "clinical use",
    "clinically valid",
    "CE mark",
    "CE-mark",
    "IVDR",
    "in vitro diagnostic",
    "must be validated",
)


def _public_files() -> list[Path]:
    files = [ROOT / "README.md"]
    files += sorted(p for p in (ROOT / "docs").rglob("*.rst") if "design" not in p.parts)
    return files


def _flat(path: Path) -> str:
    """The file's text with newlines and runs of spaces squeezed, so a phrase
    wrapped over two lines is still one phrase."""
    return " ".join(path.read_text(encoding="utf-8").split())


class TestThePublicTextCarriesTheNotice:
    def test_every_public_entry_page_states_it(self):
        for path in (ROOT / "README.md", ROOT / "docs" / "index.rst"):
            flat = _flat(path)
            for sentence in NOTICE:
                assert " ".join(sentence.split()) in flat, f"{path.name}: {sentence}"


class TestThePublicTextMakesNoReadinessClaim:
    @pytest.mark.parametrize("path", _public_files(), ids=lambda p: str(p.relative_to(ROOT)))
    def test_the_file_says_nothing_about_readiness(self, path):
        flat = _flat(path).lower()
        found = [phrase for phrase in REFUSED if phrase.lower() in flat]
        assert not found, f"{path.relative_to(ROOT)} says {found}"
