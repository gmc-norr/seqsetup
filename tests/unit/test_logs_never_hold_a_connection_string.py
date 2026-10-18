"""No log record carries a connection string's credentials, wherever it came
from -- including a traceback.

``services/database._safe`` keeps the credentials out of the messages
``init_db`` writes, but ``init_db`` re-raises, and the request middleware logs
that exception with its traceback. ``scrub_log_message`` had no rule for a
connection string, and the external-file filter never looked at a traceback at
all (review of 5aef69b, P2-1). So a password could reach Admin -> Logs and the
log file by the back door.
"""

import logging

import pytest

from seqsetup.services.log_capture import (LogCaptureHandler, ScrubbingFilter,
                                           scrub_log_message)

PASSWORD = "sUp3r-s3cr3t-pw"
URI = f"mongodb://seqsetup_app:{PASSWORD}@mongodb:27017/seqsetup?authSource=seqsetup"


class TestScrubLogMessageKnowsAConnectionString:

    @pytest.mark.parametrize("text", [
        f"could not connect using {URI}",
        f"mongodb+srv://u:{PASSWORD}@cluster.example.net/db",
        f"MONGODB://u:{PASSWORD}@h:27017/",
        f"ldap://cn=admin,dc=x:{PASSWORD}@ldap:389",
        f"two of them: {URI} and mongodb://o:{PASSWORD}@h2/",
        f"Topology Description: <ServerDescription ('{URI}', 27017)>",
    ])
    def test_the_credentials_are_replaced(self, text):
        scrubbed = scrub_log_message(text)

        assert PASSWORD not in scrubbed, scrubbed
        assert "***@" in scrubbed, scrubbed

    def test_a_uri_with_no_credentials_is_left_alone(self):
        plain = "mongodb://mongodb:27017/seqsetup"

        assert scrub_log_message(plain) == plain

    def test_a_plain_address_is_left_alone(self):
        """No scheme, so no credential part: an e-mail address or a host
        must not be mangled."""
        text = "mail to someone@example.org about mongodb:27017"

        assert scrub_log_message(text) == text


def _record_with_traceback(uri: str) -> logging.LogRecord:
    try:
        raise RuntimeError(f"could not connect using {uri}")
    except RuntimeError:
        import sys
        return logging.LogRecord(
            "seqsetup.test", logging.ERROR, __file__, 1,
            "Unhandled error while serving a request", (), sys.exc_info())


class TestATracebackIsScrubbedToo:

    def test_the_admin_log_viewer_never_shows_it(self):
        handler = LogCaptureHandler(max_entries=4)
        handler.setFormatter(logging.Formatter("%(message)s"))

        handler.emit(_record_with_traceback(URI))
        (entry,) = handler.get_entries()

        assert PASSWORD not in entry.message, entry.message

    def test_the_log_file_never_holds_it(self):
        """``ScrubbingFilter`` feeds the handlers that write the file. It read
        only the message, so the traceback went through untouched."""
        record = _record_with_traceback(URI)
        ScrubbingFilter().filter(record)

        rendered = logging.Formatter("%(message)s").format(record)

        assert PASSWORD not in rendered, rendered

    def test_the_traceback_is_still_there(self):
        record = _record_with_traceback(URI)
        ScrubbingFilter().filter(record)

        rendered = logging.Formatter("%(message)s").format(record)

        assert "RuntimeError" in rendered and "Traceback" in rendered, rendered
