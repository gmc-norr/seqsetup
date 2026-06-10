"""Tests for the log_capture sensitive-value scrubber."""

import logging

from seqsetup.services.log_capture import (
    LogCaptureHandler,
    attach_scrubbing_filter_to_handler,
    scrub_log_message,
)


class _CapturingHandler(logging.Handler):
    """Records the (post-filter) formatted message of each record it sees."""

    def __init__(self):
        super().__init__()
        self.messages: list[str] = []

    def emit(self, record):
        self.messages.append(record.getMessage())


class TestScrubbingFilterOnHandler:
    """The scrubbing filter must run for records that PROPAGATE UP from child
    loggers (seqsetup.services.*) to a handler. A logger-level filter does not
    fire for propagated records — only a handler-level filter does — so the
    filter must be attachable to the handler.
    """

    def test_filter_on_handler_scrubs_propagated_child_logger_record(self):
        handler = _CapturingHandler()
        attach_scrubbing_filter_to_handler(handler)
        root = logging.getLogger()
        root.addHandler(handler)
        child = logging.getLogger("seqsetup.services.scrub_propagation_demo")
        prev_level = child.level
        child.setLevel(logging.DEBUG)
        try:
            child.warning("bind attempt bind_password='hunter2-secret'")
        finally:
            root.removeHandler(handler)
            child.setLevel(prev_level)

        assert handler.messages, "handler never received the propagated record"
        last = handler.messages[-1]
        assert "hunter2-secret" not in last
        assert "***" in last


class TestScrubLogMessage:
    """Pure-function tests for scrub_log_message()."""

    def test_bind_password_quoted_redacted(self):
        msg = 'config={"bind_dn": "CN=svc", "bind_password": "s3cret!"}'
        assert "s3cret!" not in scrub_log_message(msg)

    def test_bind_password_kv_redacted(self):
        msg = "Failed bind with bind_password=hunter2 — retrying"
        assert "hunter2" not in scrub_log_message(msg)

    def test_api_key_redacted(self):
        msg = 'request headers: {"api-key": "abc-123-XYZ"}'
        assert "abc-123-XYZ" not in scrub_log_message(msg)

    def test_token_hash_redacted(self):
        msg = "Stored token_hash: $2b$12$ABCDEFGHIJKLMNOPQRSTUVwxyzabcdefghijklmnopqrstuvwxy01"
        out = scrub_log_message(msg)
        # The bcrypt hash itself should be redacted by the bcrypt pattern.
        assert "ABCDEFGHIJKLMNOPQRSTUVwxyz" not in out

    def test_password_redacted_case_insensitive(self):
        msg = 'PaSSwOrd="case-test"'
        assert "case-test" not in scrub_log_message(msg)

    def test_non_sensitive_text_passes_through(self):
        msg = "username=alice email=alice@example.com"
        # Neither should be scrubbed — neither key is sensitive.
        out = scrub_log_message(msg)
        assert "alice" in out
        assert "alice@example.com" in out

    def test_session_secret_redacted(self):
        msg = 'session_secret: "0123456789abcdef" loaded from file'
        assert "0123456789abcdef" not in scrub_log_message(msg)

    def test_bcrypt_hash_in_freeform_text_redacted(self):
        msg = "Verifying against hash $2b$12$abcdefghijklmnopqrstuv0123456789abcdefghijklmnopqrst1"
        out = scrub_log_message(msg)
        assert "$2b$12$abcdefghij" not in out


class TestHandlerAppliesScrub:
    """Integration: a LogCaptureHandler must scrub before storing."""

    def test_handler_stores_scrubbed_message(self):
        handler = LogCaptureHandler(max_entries=10)
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(logging.Formatter("%(message)s"))

        logger = logging.getLogger("seqsetup.test_scrub")
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        try:
            logger.info('Loaded config: bind_password="s3cret!"')
            entries = handler.get_entries()
            assert len(entries) >= 1
            assert "s3cret!" not in entries[0].message
            assert "***" in entries[0].message
        finally:
            logger.removeHandler(handler)
