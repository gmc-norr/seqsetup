"""The project's public text carries the plain use-at-your-own-risk notice and
says nothing about clinical or production readiness.

The repository is public. The README and the built documentation are what a
reader outside the lab sees: they state the notice, and they never claim (or
deny) readiness for clinical or production use, CE marking, IVDR conformity, or
say who must validate what. CLAUDE.md, the agents' instructions, is public too
and is held to the same. Design notes under ``docs/design/`` are the project's
own history and are not scanned.
"""

import re
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

# Readiness talk: a claim either way needs a judgement this project does not
# make in public text. Patterns, not plain words, so the obvious rewording of
# the sentence this guard was written for -- "not ready for production use" ->
# "production-ready" -- is caught too. "production" on its own is not refused:
# the deployment pages use it correctly for configuration ("Production
# Deployment", "NOT for production"), which claims nothing about the software.
REFUSED = (
    r"ready for production",
    r"production[-\s]?ready",
    r"clinical safety",
    r"clinical[-\s]use",
    r"clinically valid",
    r"CE[-\s]?mark",
    r"\bIVDR?\b",
    r"in[-\s]vitro diagnostic",
    r"medical device",
    r"must be validated",
    r"no further validation",
    r"fit for (clinical|diagnostic)",
)


def _public_files() -> list[Path]:
    files = [ROOT / "README.md", ROOT / "ARCHITECTURE.md", ROOT / "CLAUDE.md"]
    # relative_to(ROOT): on an absolute path every ancestor directory counts,
    # so a checkout under a directory called "design" would quietly leave the
    # whole docs tree unscanned.
    files += sorted(p for p in (ROOT / "docs").rglob("*.rst")
                    if "design" not in p.relative_to(ROOT).parts)
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
            # The notice ends by pointing at the licence; the two pages word
            # that pointer differently (a Markdown link, an RST sentence).
            tail = flat.split(" ".join(NOTICE[-1].split()))[1][:120]
            assert "LICENSE" in tail, f"{path.name}: {tail}"


class TestWhatCountsAsAReadinessClaim:
    """The list is only as good as the sentences it catches: the one that was
    removed, its obvious rewordings, and none of the deployment prose the
    getting-started pages need."""

    @pytest.mark.parametrize("sentence", [
        "This project is under active development and is not ready for production use.",
        "SeqSetup is production-ready.",
        "SeqSetup is production ready.",
        "It is a medical device.",
        "IVD-conformant",
        "The software is IVDR conformant.",
        "for in-vitro diagnostic use",
        "for in vitro diagnostic use",
        "the project's hard rules for clinical safety",
        "SeqSetup is a clinical-use application",
        "for clinical use",
        "a CE-marked instrument",
        "no further validation is needed",
        "fit for clinical use",
        "each laboratory must be validated against its own panels",
    ])
    def test_a_claim_is_refused(self, sentence):
        assert [p for p in REFUSED if re.search(p, sentence, re.IGNORECASE)], sentence

    @pytest.mark.parametrize("sentence", [
        "For production use a reverse proxy in front of SeqSetup.",
        "Production Deployment",
        "SEQSETUP_LDAP_ALLOW_CLEARTEXT=1   # NOT for production",
        "Session encryption secret key (use in production)",
        "Before deploying to production:",
        "Production must use HTTPS so the api-key is never sent in clear.",
    ])
    def test_deployment_prose_is_not_a_claim(self, sentence):
        assert [p for p in REFUSED if re.search(p, sentence, re.IGNORECASE)] == [], sentence


class TestThePublicTextMakesNoReadinessClaim:
    @pytest.mark.parametrize("path", _public_files(), ids=lambda p: str(p.relative_to(ROOT)))
    def test_the_file_says_nothing_about_readiness(self, path):
        flat = _flat(path)
        found = [pattern for pattern in REFUSED
                 if re.search(pattern, flat, re.IGNORECASE)]
        assert not found, f"{path.relative_to(ROOT)} says {found}"


def _pages() -> list[Path]:
    """What a reader outside the lab reads: the README, ARCHITECTURE.md and
    the built documentation."""
    return [p for p in _public_files() if p.name != "CLAUDE.md"]


class TestThePagesDoNotDescribeTheWorkAsClinical:
    """Not only a readiness claim: a page that calls the operators, the data or
    the setting "clinical" invites the same reading (review O1: "a trusted
    clinical operator team", "finalized clinical content")."""

    @pytest.mark.parametrize("path", _pages(), ids=lambda p: str(p.relative_to(ROOT)))
    def test_the_page_does_not_say_clinical(self, path):
        found = re.findall(r"\bclinical\w*", _flat(path), re.IGNORECASE)
        assert not found, f"{path.relative_to(ROOT)} says {found}"
