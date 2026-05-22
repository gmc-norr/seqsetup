"""Tests for the log_capture sensitive-value scrubber."""

import logging

from seqsetup.services.log_capture import (
    LogCaptureHandler,
    scrub_log_message,
)


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
