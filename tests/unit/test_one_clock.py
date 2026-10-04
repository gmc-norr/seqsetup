"""Every stored time is UTC and every shown time is in the display zone
(seqsetup.utils.clock). A time stored in the server's local clock would be
shown an hour or two off, and naive local times sort wrong when the clocks go
back; a template that formats a stored time itself shows it in UTC, unlabelled."""

import re
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src" / "seqsetup"

LOCAL_CLOCK = re.compile(
    r"datetime\.now\(\s*\)"
    r"|default_factory=datetime\.now\b(?!\()"
    r"|datetime\.today\("
    r"|date\.today\("
    r"|datetime\.utcnow\("
    r"|fromtimestamp\([^,()]*\)"
    r"|time\.localtime\("
)


def _hits(pattern, paths):
    return [
        f"{path.relative_to(SRC)}:{number}: {line.strip()}"
        for path in paths
        for number, line in enumerate(path.read_text().splitlines(), start=1)
        if pattern.search(line)
    ]


class TestOneClock:
    def test_no_code_reads_the_local_clock(self):
        assert _hits(LOCAL_CLOCK, sorted(SRC.rglob("*.py"))) == []

    def test_no_template_formats_a_time_itself(self):
        # Use the localtime filter: {{ value | localtime }}.
        assert _hits(re.compile(r"\.strftime\("), sorted(SRC.rglob("*.html"))) == []

    def test_the_pattern_finds_each_way_to_read_the_local_clock(self):
        for line in ("x = datetime.now()", "created_at: datetime = field(default_factory=datetime.now)",
                     "d = date.today()", "t = datetime.today()", "t = datetime.utcnow()",
                     "t = datetime.fromtimestamp(record.created)", "t = time.localtime()"):
            assert LOCAL_CLOCK.search(line), line
        for line in ("x = datetime.now(timezone.utc)", "t = datetime.fromtimestamp(s, timezone.utc)",
                     "x = utcnow()"):
            assert not LOCAL_CLOCK.search(line), line
