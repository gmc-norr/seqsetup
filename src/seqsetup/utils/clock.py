"""One clock for SeqSetup: times are stored in UTC and shown in the server's
time zone, with the zone's name next to them.

A stored time is a naive datetime that means UTC (what MongoDB keeps, and what
web_sessions already uses). The zone times are shown in is the TZ environment
variable, an IANA name such as Europe/Stockholm; without TZ, the server's own
zone. check_display_zone() refuses a TZ that names no known zone at start, so
times are never shown in UTC without anyone noticing.
"""

import os
from datetime import date, datetime, timezone, tzinfo
from typing import Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


def utcnow() -> datetime:
    """Now, as a naive datetime meaning UTC: the form every stored time takes."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def as_utc(value: Optional[datetime]) -> Optional[datetime]:
    """A stored time marked as UTC (an aware time is returned as it is)."""
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=timezone.utc)


def _zone_name() -> str:
    # POSIX allows ":Europe/Stockholm" for a zone name.
    return os.environ.get("TZ", "").removeprefix(":")


def display_zone() -> Optional[tzinfo]:
    """The zone times are shown in: TZ's zone, or None for the server's own."""
    name = _zone_name()
    return ZoneInfo(name) if name else None


def check_display_zone() -> None:
    """Raise RuntimeError when TZ is set but names no known time zone."""
    name = _zone_name()
    if not name:
        return
    try:
        ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as e:
        raise RuntimeError(
            f"TZ={os.environ['TZ']!r} is not a known time zone. Set TZ to an IANA time "
            "zone name such as Europe/Stockholm, or leave it unset to show times in the "
            "server's own zone."
        ) from e


def to_local(value: datetime) -> datetime:
    """A stored time (naive means UTC) in the display zone, as an aware time."""
    zone = display_zone()
    aware = as_utc(value)
    return aware.astimezone(zone) if zone is not None else aware.astimezone()


def local_time(value: Optional[datetime], *, seconds: bool = False) -> str:
    """'YYYY-MM-DD HH:MM ZONE' in the display zone (':SS' too with seconds);
    '' for no time."""
    if value is None:
        return ""
    return to_local(value).strftime("%Y-%m-%d %H:%M:%S %Z" if seconds else "%Y-%m-%d %H:%M %Z")


def local_date(value: datetime) -> str:
    """'YYYY-MM-DD': the calendar day of a stored time in the display zone."""
    return to_local(value).strftime("%Y-%m-%d")


def local_day_start_utc(day: date) -> datetime:
    """The moment ``day`` starts in the display zone, as a stored (naive UTC) time."""
    midnight = datetime(day.year, day.month, day.day)
    zone = display_zone()
    aware = midnight.replace(tzinfo=zone) if zone is not None else midnight.astimezone()
    return aware.astimezone(timezone.utc).replace(tzinfo=None)
