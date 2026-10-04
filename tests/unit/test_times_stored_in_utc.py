"""Every time SeqSetup stores or compares is UTC, whatever the server's own
zone: here the process's local clock runs 14 hours ahead of UTC, so a value
taken from the local clock is caught on any machine."""

import logging
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from seqsetup.models.api_token import ApiToken
from seqsetup.models.local_user import LocalUser
from seqsetup.models.profile_sync_config import ProfileSyncConfig
from seqsetup.models.run_template import RunTemplate
from seqsetup.models.sequencing_run import SequencingRun
from seqsetup.services.log_capture import LogCaptureHandler
from seqsetup.services.scheduler import ProfileSyncScheduler


@pytest.fixture
def far_local_clock(monkeypatch):
    """The process's local clock 14 hours ahead of UTC (a POSIX TZ, no zone files needed)."""
    monkeypatch.setenv("TZ", "LOC-14")
    time.tzset()
    yield
    monkeypatch.undo()
    time.tzset()


def _utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def assert_utc_now(value: datetime):
    assert value.tzinfo is None
    assert abs(value - _utc_now()) < timedelta(seconds=30), value


@pytest.mark.usefixtures("far_local_clock")
class TestStoredTimesAreUtc:
    def test_a_new_run(self):
        run = SequencingRun()
        assert_utc_now(run.created_at)
        assert_utc_now(run.updated_at)

    def test_a_saved_change_to_a_run(self):
        run = SequencingRun(updated_at=datetime(2026, 1, 1))
        run.touch("someone")
        assert_utc_now(run.updated_at)

    def test_a_run_read_back_without_times(self):
        run = SequencingRun.from_dict({"id": "r1", "run_name": "R"})
        assert_utc_now(run.created_at)
        assert_utc_now(run.updated_at)

    def test_a_template(self):
        template = RunTemplate(name="T")
        assert_utc_now(template.created_at)
        template.updated_at = datetime(2026, 1, 1)
        template.touch()
        assert_utc_now(template.updated_at)

    def test_a_local_user(self):
        user = LocalUser(username="u", display_name="U")
        assert_utc_now(user.created_at)
        user.set_password("A-Long-Enough-Pass-2026!")
        assert_utc_now(user.updated_at)

    def test_an_api_token(self):
        assert_utc_now(ApiToken(name="t").created_at)

    def test_a_log_line(self):
        handler = LogCaptureHandler()
        handler.emit(logging.LogRecord("x", logging.WARNING, __file__, 1, "hello", None, None))
        assert_utc_now(handler._buffer[-1].timestamp)


@pytest.mark.usefixtures("far_local_clock")
class TestComparisonsUseUtc:
    def test_a_token_that_ends_in_half_an_hour_still_works(self):
        token = ApiToken(name="t", expires_at=_utc_now() + timedelta(minutes=30))
        assert not token.is_expired()

    def test_a_token_that_ended_half_an_hour_ago_is_expired(self):
        token = ApiToken(name="t", expires_at=_utc_now() - timedelta(minutes=30))
        assert token.is_expired()

    def test_a_sync_ten_minutes_ago_is_not_due_on_an_hourly_schedule(self):
        scheduler = ProfileSyncScheduler(MagicMock(), MagicMock())
        config = ProfileSyncConfig(sync_interval_minutes=60,
                                   last_sync_at=_utc_now() - timedelta(minutes=10))
        assert scheduler._should_sync(config) is False

    def test_a_sync_two_hours_ago_is_due(self):
        scheduler = ProfileSyncScheduler(MagicMock(), MagicMock())
        config = ProfileSyncConfig(sync_interval_minutes=60,
                                   last_sync_at=_utc_now() - timedelta(hours=2))
        assert scheduler._should_sync(config) is True
