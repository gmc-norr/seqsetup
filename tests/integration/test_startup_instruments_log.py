"""The start says which instruments file it read, in the captured log.

Decision 1e asked for the path of the instruments file at INFO at start-up,
and the admin guide states it as fact. The read happens when
``data.instruments`` is imported -- before ``setup_log_capture`` exists -- so
the line is logged again once capture is installed.
"""

from seqsetup.data.instruments import _find_config_path
from seqsetup.services.log_capture import get_captured_logs


def _instrument_lines():
    return [e for e in get_captured_logs(limit=2000) if "Reading instruments from" in e.message]


class TestTheStartUpLogNamesTheInstrumentsFile:
    """A real app start leaves the line in the buffer Admin > Logs reads."""

    def test_the_line_is_captured(self, fresh_app):
        lines = _instrument_lines()

        assert lines, (
            "no 'Reading instruments from' line in the captured log; captured: "
            + repr([e.message for e in get_captured_logs(limit=2000)])
        )

    def test_the_line_is_at_info_and_names_the_file_read(self, fresh_app):
        lines = _instrument_lines()

        assert lines
        assert lines[0].level == "INFO"
        assert str(_find_config_path()) in lines[0].message
