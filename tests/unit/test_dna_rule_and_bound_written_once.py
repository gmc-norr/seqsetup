"""The DNA rule and the paste and LIMS readers' 256 bound are written once
(docs/design/2026-10-18-input-rules-design.md, step 5: the user's word of
2026-10-20, option C).

A copy that drifts is a rule two inputs keep differently: the paste, the LIMS
import, a form and an index kit each wrote the DNA rule out.
"""

import re
from pathlib import Path

from seqsetup.models.index import VALID_DNA_RE
from seqsetup.models.sample import MAX_SAMPLE_TEXT
from seqsetup.services import sample_api, sample_parser

SRC = Path(__file__).resolve().parents[2] / "src" / "seqsetup"
# The validity rule written as a pattern: any number of A, C, G, T, N and
# nothing else, anchored or not, compiled or passed to re.match/fullmatch.
# Not the "looks like DNA" patterns ({4,}, {6,}), which are other rules.
_A_COPY = re.compile(r"""r?(['"])\^?\[ACGTN\]\*(\\Z|\$)?\1""")


class TestTheDnaRuleIsWrittenOnce:
    """One compiled rule, in models/index.py, which every reader imports."""

    def test_no_other_file_writes_it_out(self):
        copies = sorted(str(path.relative_to(SRC)) for path in SRC.rglob("*.py")
                        if _A_COPY.search(path.read_text(encoding="utf-8")))

        assert copies == ["models/index.py"]

    def test_it_takes_dna_and_nothing_else(self):
        assert VALID_DNA_RE.match("ACGTN")
        assert VALID_DNA_RE.match("")
        for text in ("ACGU", "acgt", "ACGT\n", "ACG T"):
            assert not VALID_DNA_RE.match(text), text


class TestTheCutFollowsTheSampleTextBound:
    """Both readers cut what they do not refuse at MAX_SAMPLE_TEXT, written
    as that name: a hand-copied 256 would not follow it."""

    def test_the_lims_bound_is_the_sample_text_bound(self):
        source = Path(sample_api.__file__).read_text(encoding="utf-8")

        assert "_MAX_FIELD_LEN = MAX_SAMPLE_TEXT\n" in source
        assert sample_api._MAX_FIELD_LEN == MAX_SAMPLE_TEXT

    def test_the_paste_bound_is_the_sample_text_bound(self):
        source = Path(sample_parser.__file__).read_text(encoding="utf-8")

        assert "_MAX_CELL_LEN = MAX_SAMPLE_TEXT\n" in source
