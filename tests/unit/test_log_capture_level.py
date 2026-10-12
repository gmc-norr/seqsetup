"""An INFO record on a captured logger reaches the capture buffer.

The capture handler is at DEBUG and Admin > Logs offers INFO and DEBUG
filters, but ``setup_log_capture`` only attached the handler: a named logger
left at NOTSET inherits root's WARNING, so no INFO record was ever made and
the INFO filter had nothing to show.
"""

import logging

import pytest

from seqsetup.services.log_capture import setup_log_capture


@pytest.fixture
def kept_level():
    """Restore the ``seqsetup`` logger's level after the test."""
    logger = logging.getLogger("seqsetup")
    saved = logger.level
    yield logger
    logger.setLevel(saved)


class TestAnInfoRecordReachesTheBuffer:
    def test_setup_log_capture_captures_an_info_record(self, kept_level):
        kept_level.setLevel(logging.NOTSET)

        handler = setup_log_capture(["seqsetup"])
        handler.clear()
        logging.getLogger("seqsetup.data.probe").info("an INFO line")

        assert [e.message for e in handler.get_entries(limit=10)] == ["an INFO line"]

    def test_an_explicitly_more_verbose_level_is_not_raised(self, kept_level):
        kept_level.setLevel(logging.DEBUG)

        setup_log_capture(["seqsetup"])

        assert kept_level.level == logging.DEBUG
