"""One clock: times are stored in UTC and shown in the server's time zone (the
TZ setting, an IANA name such as Europe/Stockholm), with the zone's name."""

import time
from datetime import date, datetime, timedelta, timezone

import pytest

from seqsetup.utils import clock
from seqsetup.utils.clock import (
    as_utc,
    check_display_zone,
    local_date,
    local_day_start_utc,
    local_time,
    to_local,
    utcnow,
)

WINTER = datetime(2026, 1, 15, 12, 0, 5)   # stored: naive means UTC
SUMMER = datetime(2026, 7, 15, 12, 0, 5)


@pytest.fixture
def stockholm(monkeypatch):
    monkeypatch.setenv("TZ", "Europe/Stockholm")


class TestStoredTimes:
    """utcnow: the form every stored time takes."""

    def test_utcnow_is_naive_utc(self):
        now = utcnow()
        assert now.tzinfo is None
        assert abs(now - datetime.now(timezone.utc).replace(tzinfo=None)) < timedelta(seconds=5)

    def test_as_utc_marks_a_stored_time_as_utc(self):
        assert as_utc(WINTER) == WINTER.replace(tzinfo=timezone.utc)

    def test_as_utc_keeps_an_aware_time(self):
        aware = datetime(2026, 1, 15, 13, 0, tzinfo=timezone(timedelta(hours=1)))
        assert as_utc(aware) is aware

    def test_as_utc_of_nothing_is_nothing(self):
        assert as_utc(None) is None


class TestShownTimes:
    """local_time / local_date / to_local: in the display zone, with its name."""

    def test_winter_time_in_stockholm(self, stockholm):
        assert local_time(WINTER) == "2026-01-15 13:00 CET"

    def test_summer_time_in_stockholm(self, stockholm):
        assert local_time(SUMMER) == "2026-07-15 14:00 CEST"

    def test_with_seconds(self, stockholm):
        assert local_time(WINTER, seconds=True) == "2026-01-15 13:00:05 CET"

    def test_an_aware_time_is_shown_the_same(self, stockholm):
        assert local_time(WINTER.replace(tzinfo=timezone.utc)) == "2026-01-15 13:00 CET"

    def test_utc_zone(self, monkeypatch):
        monkeypatch.setenv("TZ", "UTC")
        assert local_time(WINTER) == "2026-01-15 12:00 UTC"

    def test_a_leading_colon_in_tz_is_allowed(self, monkeypatch):
        monkeypatch.setenv("TZ", ":Europe/Stockholm")
        assert local_time(WINTER) == "2026-01-15 13:00 CET"

    def test_without_tz_the_servers_own_zone(self, monkeypatch):
        monkeypatch.delenv("TZ", raising=False)
        shown = to_local(WINTER)
        assert shown.utcoffset() is not None
        assert shown.astimezone(timezone.utc).replace(tzinfo=None) == WINTER

    def test_nothing_is_shown_as_empty(self, stockholm):
        assert local_time(None) == ""

    def test_the_local_date_can_be_the_next_day(self, stockholm):
        assert local_date(datetime(2026, 1, 15, 23, 30)) == "2026-01-16"


class TestLocalDays:
    """local_day_start_utc: where a calendar day starts in the display zone, in UTC."""

    def test_a_winter_day(self, stockholm):
        assert local_day_start_utc(date(2026, 1, 15)) == datetime(2026, 1, 14, 23, 0)

    def test_a_summer_day(self, stockholm):
        assert local_day_start_utc(date(2026, 7, 15)) == datetime(2026, 7, 14, 22, 0)

    def test_the_day_the_clocks_go_forward(self, stockholm):
        assert local_day_start_utc(date(2026, 3, 29)) == datetime(2026, 3, 28, 23, 0)

    def test_the_day_after(self, stockholm):
        assert local_day_start_utc(date(2026, 3, 30)) == datetime(2026, 3, 29, 22, 0)



@pytest.fixture
def server_zone_far_east(monkeypatch):
    """No TZ display zone, and the server's own zone (the C library's) 14
    hours ahead of UTC (a POSIX TZ, no zone files needed)."""
    monkeypatch.setenv("TZ", "LOC-14")
    time.tzset()
    monkeypatch.setattr(clock, "display_zone", lambda: None)
    yield
    monkeypatch.undo()
    time.tzset()


@pytest.mark.usefixtures("server_zone_far_east")
class TestWithoutTz:
    """Without TZ, times are shown in the server's own zone."""

    def test_a_time_is_shown_in_the_servers_zone(self):
        assert local_time(WINTER) == "2026-01-16 02:00 LOC"

    def test_a_day_starts_at_the_servers_midnight(self):
        assert local_day_start_utc(date(2026, 1, 15)) == datetime(2026, 1, 14, 10, 0)

class TestTheSettingIsChecked:
    """check_display_zone: a TZ that names no known zone stops the start."""

    @pytest.mark.parametrize("value", ["Mars/Olympus_Mons", "CET-1CEST,M3.5.0,M10.5.0/3",
                                       "../etc/passwd", "Europe/stockholm "])
    def test_an_unknown_zone_is_refused(self, monkeypatch, value):
        monkeypatch.setenv("TZ", value)
        with pytest.raises(RuntimeError, match="is not a known time zone"):
            check_display_zone()

    def test_the_message_says_what_to_set(self, monkeypatch):
        monkeypatch.setenv("TZ", "Mars/Olympus_Mons")
        with pytest.raises(RuntimeError) as e:
            check_display_zone()
        assert "TZ='Mars/Olympus_Mons'" in str(e.value)
        assert "such as Europe/Stockholm" in str(e.value)

    @pytest.mark.parametrize("value", ["Europe/Stockholm", "UTC", ":Europe/Stockholm"])
    def test_a_known_zone_is_accepted(self, monkeypatch, value):
        monkeypatch.setenv("TZ", value)
        check_display_zone()

    def test_no_tz_is_accepted(self, monkeypatch):
        monkeypatch.delenv("TZ", raising=False)
        check_display_zone()


class TestTheAppChecksTheSettingFirst:
    """The app stops at start with the message, before anything else runs."""

    def test_an_unknown_zone_stops_the_app(self, tmp_path):
        import os
        import subprocess
        import sys
        from pathlib import Path

        src = Path(__file__).resolve().parents[2] / "src"
        # An address nothing listens on: if the check were missing, the app
        # must not reach a real database.
        env = {**os.environ, "TZ": "Mars/Olympus_Mons", "PYTHONPATH": str(src),
               "MONGODB_URI": "mongodb://127.0.0.1:1"}
        proc = subprocess.run([sys.executable, "-c", "import seqsetup.app"], env=env, cwd=tmp_path,
                              capture_output=True, text=True, timeout=300)
        assert proc.returncode != 0
        assert "TZ='Mars/Olympus_Mons' is not a known time zone" in proc.stderr
