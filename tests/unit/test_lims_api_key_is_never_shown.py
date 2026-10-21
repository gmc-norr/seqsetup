"""A LIMS api-key that holds a control character is never sent and never shown.

A key ending in a line break -- a key file's newline, a CRLF ``.env`` -- made
``http.client`` raise ``ValueError("Invalid header value b'<the key>\\n'")``,
and the three LIMS calls caught it as "Unexpected error: {e}": the run page
showed that text, key and all, to any user who pressed Load Worklists, the
admin page showed it, ``logger.exception`` wrote it to Admin > Logs and to the
container log (review INGEST-1 / SEC-1). The key is refused at start-up, the
client refuses to send it in its own words, and no message built from a
request error carries a header value.
"""

from pathlib import Path

import pytest

from seqsetup.models.sample_api_config import SampleApiConfig
from seqsetup.services import sample_api as sa

KEY = "s3cret-lims-key-AAAA"
URL = "https://lims.example.org/api"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Nothing may leave this machine: the url check passes and the socket
    layer is never reached (every test here fails before it)."""
    monkeypatch.setattr(sa, "_validate_url", lambda url: [sa.ipaddress.ip_address("93.184.216.34")])
    monkeypatch.setattr(sa, "_throttle", lambda key: None)


def _config() -> SampleApiConfig:
    return SampleApiConfig(base_url=URL, enabled=True)


class TestTheKeyIsRefusedAtStartUp:

    @pytest.mark.parametrize("ending", ["\n", "\r\n", "\r", "\t", "\x1b", "\x7f"])
    def test_a_key_with_a_control_character_stops_the_start(self, monkeypatch, ending):
        monkeypatch.setenv("SEQSETUP_LIMS_API_KEY", KEY + ending)

        with pytest.raises(RuntimeError) as stopped:
            sa.check_lims_api_key()

        assert "SEQSETUP_LIMS_API_KEY" in str(stopped.value)
        assert KEY not in str(stopped.value)

    def test_a_plain_key_is_fine(self, monkeypatch):
        monkeypatch.setenv("SEQSETUP_LIMS_API_KEY", KEY)

        sa.check_lims_api_key()

    def test_no_key_at_all_is_fine(self, monkeypatch):
        monkeypatch.delenv("SEQSETUP_LIMS_API_KEY", raising=False)

        sa.check_lims_api_key()

    def test_the_start_runs_it(self):
        """app.py calls it beside the other start-up checks."""
        source = (Path(__file__).resolve().parents[2]
                  / "src" / "seqsetup" / "app.py").read_text(encoding="utf-8")

        assert "check_lims_api_key()" in source


class TestTheKeyIsNeverSentAndNeverShown:

    @pytest.mark.parametrize("ending", ["\n", "\r\n", "\r"])
    def test_fetch_worklists_says_so_without_the_key(self, monkeypatch, ending):
        monkeypatch.setenv("SEQSETUP_LIMS_API_KEY", KEY + ending)

        ok, message, worksheets, left_out = sa.fetch_worklists(_config())

        assert not ok
        assert KEY not in message
        assert "control character" in message and "SEQSETUP_LIMS_API_KEY" in message
        assert worksheets == [] and left_out == []

    def test_check_connection_says_so_without_the_key(self, monkeypatch):
        monkeypatch.setenv("SEQSETUP_LIMS_API_KEY", KEY + "\n")

        ok, message = sa.check_connection(_config())

        assert not ok and KEY not in message

    def test_fetch_worklist_samples_says_so_without_the_key(self, monkeypatch):
        monkeypatch.setenv("SEQSETUP_LIMS_API_KEY", KEY + "\n")

        ok, message, rows = sa.fetch_worklist_samples(_config(), "W1")

        assert not ok and KEY not in message and rows == []

    def test_the_log_does_not_carry_the_key(self, monkeypatch, caplog):
        monkeypatch.setenv("SEQSETUP_LIMS_API_KEY", KEY + "\n")

        with caplog.at_level("DEBUG"):
            sa.fetch_worklists(_config())

        logged = "\n".join(
            r.getMessage() + (caplog.handler.format(r) if r.exc_info else "")
            for r in caplog.records)
        assert KEY not in logged

    def test_the_key_never_reaches_the_connection(self, monkeypatch):
        """The refusal is before any connection is built, so the key is not
        in a socket buffer either."""
        monkeypatch.setenv("SEQSETUP_LIMS_API_KEY", KEY + "\n")
        built = []
        monkeypatch.setattr(sa, "_PinnedHTTPSConnection",
                            lambda **kw: built.append(kw) or (_ for _ in ()).throw(
                                AssertionError("a connection was built")))

        ok, _message, _ws, _left = sa.fetch_worklists(_config())

        assert not ok and built == []


class TestAHeaderValueIsNeverInAMessage:

    def test_a_header_a_header_may_not_carry(self, monkeypatch):
        """Whatever the value is -- a key, a path, a user agent -- the words
        http.client puts in its ValueError are never passed on."""
        monkeypatch.delenv("SEQSETUP_LIMS_API_KEY", raising=False)

        def refuse(*_args, **_kw):
            raise ValueError("Invalid header value b'secret-value\\n'")

        class Conn:
            def __init__(self, **_kw):
                pass
            request = refuse

            def close(self):
                pass

        monkeypatch.setattr(sa, "_PinnedHTTPSConnection", Conn)

        ok, message, _ws, _left = sa.fetch_worklists(_config())

        assert not ok
        assert "secret-value" not in message, message
