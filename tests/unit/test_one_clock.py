"""Every stored time is UTC and every shown time is in the display zone
(seqsetup.utils.clock). A time stored in the server's local clock would be
shown an hour or two off, and naive local times sort wrong when the clocks go
back; a template that formats or prints a stored time itself shows it in UTC,
unlabelled."""

import re
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src" / "seqsetup"
# The one module that turns stored times into the display zone; it reads no
# clock but the zone's.
CLOCK = SRC / "utils" / "clock.py"

LOCAL_CLOCK = re.compile(
    r"datetime\.now\((?![^()]*timezone\.utc)[^()]*\)"
    r"|default_factory=datetime\.now\b(?!\()"
    r"|datetime\.today\("
    r"|date\.today\("
    r"|datetime\.utcnow\("
    r"|fromtimestamp\((?![^()]*timezone\.utc)[^()]*\)"
    r"|\.astimezone\(\s*\)"
    r"|\btime\.(?:localtime|strftime|ctime|asctime|mktime)\("
)
TIME_FIELD = re.compile(r"\b\w*(?:_at|timestamp)\b")


def _hits(pattern, paths):
    return [
        f"{path.relative_to(SRC)}:{number}: {line.strip()}"
        for path in paths
        for number, line in enumerate(path.read_text().splitlines(), start=1)
        if pattern.search(line)
    ]


def _printed_times(paths, root=SRC):
    """Each {{ ... }} that prints a time field without the localtime filter
    (isoformat() is a machine value, not shown)."""
    return [
        f"{path.relative_to(root)}:{number}: {expr.strip()}"
        for path in paths
        for number, line in enumerate(path.read_text().splitlines(), start=1)
        for expr in re.findall(r"\{\{(.*?)\}\}", line)
        if TIME_FIELD.search(expr) and "localtime" not in expr and "isoformat" not in expr
    ]


class TestOneClock:
    def test_no_code_reads_the_local_clock(self):
        paths = [p for p in sorted(SRC.rglob("*.py")) if p != CLOCK]
        assert _hits(LOCAL_CLOCK, paths) == []

    def test_no_template_formats_a_time_itself(self):
        # Use the localtime filter: {{ value | localtime }}.
        assert _hits(re.compile(r"\.strftime\("), sorted(SRC.rglob("*.html"))) == []

    def test_no_template_prints_a_time_without_the_filter(self):
        assert _printed_times(sorted(SRC.rglob("*.html"))) == []

    def test_the_pattern_finds_each_way_to_read_the_local_clock(self):
        for line in ("x = datetime.now()", "x = datetime.now(tz=None)", "x = datetime.now(None)",
                     "created_at: datetime = field(default_factory=datetime.now)",
                     "d = date.today()", "t = datetime.today()", "t = datetime.utcnow()",
                     "t = datetime.fromtimestamp(record.created)",
                     "t = datetime.fromtimestamp(record.created, None)",
                     "t = value.astimezone()", "t = time.localtime()", "s = time.strftime('%H')",
                     "s = time.ctime()"):
            assert LOCAL_CLOCK.search(line), line
        for line in ("x = datetime.now(timezone.utc)", "x = datetime.now(tz=timezone.utc)",
                     "t = datetime.fromtimestamp(s, timezone.utc)", "x = utcnow()",
                     "t = value.astimezone(zone)", "t0 = time.monotonic()"):
            assert not LOCAL_CLOCK.search(line), line

    def test_the_template_check_finds_a_printed_time(self, tmp_path):
        page = tmp_path / "page.html"
        page.write_text('<td>{{ run.updated_at }}</td>\n<td>{{ e.timestamp }}</td>\n'
                        '<td>{{ token.expires_at if token.expires_at else "-" }}</td>\n'
                        '<td>{{ run.updated_at | localtime }}</td>\n'
                        '<input value="{{ run.updated_at.isoformat() }}">\n'
                        '<td>{{ created_at_str }}</td>\n')
        assert [hit.split(":")[1] for hit in _printed_times([page], tmp_path)] == ["1", "2", "3"]
