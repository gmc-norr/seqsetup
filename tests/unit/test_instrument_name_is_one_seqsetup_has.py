"""An instrument file names one of SeqSetup's own instruments.

A file naming another one -- "NovaSeq X" where SeqSetup has "NovaSeq X
Series" -- was read, stored and counted ("11 instruments synced"), and
``check-settings`` said "no errors"; then ``get_all_instruments`` skipped it
with a log line, and since synced records are the only ones that count, the
instrument the file was meant to describe was gone from every page. The run
it was for was refused far from the cause (review CONFIG-2). The rulebook
refuses it now, so the sync and ``check-settings`` both say so, with the
file, the line, the place and the names it accepts.
"""

import yaml

from seqsetup.input_rules.instruments import (
    PLATFORM_NAMES,
    check_local_instruments_file,
    check_synced_instrument_file,
)

from .test_check_settings_command import _folder, _run
from .test_i5_workflows import _yaml
from .test_input_rules_instruments import LOCAL, ONE
from .test_sync_instrument_files import ROOT, _fetch, _service, _text

UNKNOWN = "NovaSeq X"  # SeqSetup's own name is "NovaSeq X Series"


def _errors(result):
    return [(tuple(p.path), p.message) for p in result.problems if p.level == "error"]


class TestTheRulebook:

    def test_the_names_it_accepts_are_seqsetups_instruments(self):
        assert "NovaSeq X Series" in PLATFORM_NAMES and UNKNOWN not in PLATFORM_NAMES

    def test_a_single_instrument_file(self):
        result = check_synced_instrument_file(
            ONE.replace("\nname: NovaSeq X Series\n", f"\nname: {UNKNOWN}\n"), "one.yaml")

        ((path, message),) = _errors(result)
        assert path == ("name",)
        assert "NovaSeq X Series" in message and "MiSeq i100 Series" in message

    def test_a_file_holding_several_instruments_names_the_entry(self):
        data = {"instruments": {UNKNOWN: {k: v for k, v in _yaml().items() if k != "name"}}}

        ((path, _message),) = _errors(
            check_synced_instrument_file(yaml.safe_dump(data), "all.yaml"))

        assert path == ("instruments", UNKNOWN)

    def test_the_local_file(self):
        text = LOCAL.read_text().replace("  NovaSeq X Series:\n", f"  {UNKNOWN}:\n", 1)
        assert f"  {UNKNOWN}:\n" in text

        paths = [path for path, _ in _errors(check_local_instruments_file(text, "instruments.yaml"))]

        assert paths == [("instruments", UNKNOWN)]

    def test_a_good_file_still_passes(self):
        assert _errors(check_synced_instrument_file(ONE, "one.yaml")) == []


class TestTheSync:
    """A refused instrument file is named and no instrument is stored, as any
    other refused instrument file does (spec 2026-10-04 group A2, §5)."""

    def test_the_file_is_refused_and_named(self):
        instruments, refused = _fetch(_service({ROOT: {"nx.yaml": _text(name=UNKNOWN)}}))

        assert instruments == []
        (problem,) = refused
        assert problem.startswith(f"{ROOT}/nx.yaml:")
        assert "name" in problem and "NovaSeq X Series" in problem


class TestCheckSettings:

    def test_it_says_so_and_stops(self, tmp_path):
        folder = _folder(tmp_path, {"nx.yaml": _text(name=UNKNOWN)})

        done = _run(str(folder))

        assert done.returncode == 1, done.stdout + done.stderr
        said = done.stdout + done.stderr
        assert "nx.yaml" in said and "NovaSeq X Series" in said
