"""Tests for sample_api service."""

import io
import ipaddress
import json
import ssl
from types import SimpleNamespace
from unittest.mock import patch, MagicMock

import pytest

from seqsetup.models.sample_api_config import SampleApiConfig
from seqsetup.services import sample_api as sample_api_module
from seqsetup.services.sample_api import check_connection, parse_api_samples, SampleApiError


class TestParseApiSamplesCap:
    """The LIMS import parser is an ingest point and must enforce the same
    per-run sample cap as the paste parser (DoS / 16MB-BSON guard)."""

    def test_exceeding_cap_raises(self, monkeypatch):
        monkeypatch.setattr(sample_api_module, "MAX_SAMPLES_PER_RUN", 4)
        data = [{"sample_id": f"S{i}"} for i in range(5)]
        with pytest.raises(ValueError, match="maximum"):
            parse_api_samples(data)

    def test_at_cap_succeeds(self, monkeypatch):
        monkeypatch.setattr(sample_api_module, "MAX_SAMPLES_PER_RUN", 4)
        data = [{"sample_id": f"S{i}"} for i in range(4)]
        result = parse_api_samples(data)
        assert len(result) == 4


class TestParseApiSamplesIndexDna:
    """The LIMS parser must DNA-validate index sequences (like the paste path),
    raising a clean sample-naming error instead of letting a later Index()
    construction throw an uncaught ValueError (HTTP 500)."""

    def test_invalid_index1_dna_rejected_naming_sample(self):
        data = [{"sample_id": "S1", "index_i7": "ACGTXYZ"}]
        with pytest.raises(ValueError, match="S1"):
            parse_api_samples(data)

    def test_invalid_index2_dna_rejected_naming_sample(self):
        data = [{"sample_id": "S2", "index_i5": "ACGT123"}]
        with pytest.raises(ValueError, match="S2"):
            parse_api_samples(data)

    def test_valid_index_dna_uppercased(self):
        data = [{"sample_id": "S3", "index_i7": "acgtn", "index_i5": "ttaa"}]
        result = parse_api_samples(data)
        assert result[0]["index1_sequence"] == "ACGTN"
        assert result[0]["index2_sequence"] == "TTAA"


class TestCheckConnection:
    """Tests for check_connection()."""

    def test_empty_base_url(self):
        config = SampleApiConfig(base_url="", api_key="key", enabled=False)
        success, msg = check_connection(config)
        assert success is False
        assert "not configured" in msg

    @patch("seqsetup.services.sample_api._api_get")
    def test_successful_connection(self, mock_get):
        mock_get.return_value = [{"id": "1", "name": "WL1"}]
        config = SampleApiConfig(base_url="https://example.com/api", api_key="key")
        success, msg = check_connection(config)
        assert success is True
        assert "1 worksheets" in msg
        mock_get.assert_called_once_with("https://example.com/api/worksheets?detail=true", "key")

    @patch("seqsetup.services.sample_api._api_get")
    def test_successful_connection_empty_list(self, mock_get):
        mock_get.return_value = []
        config = SampleApiConfig(base_url="https://example.com/api", api_key="key")
        success, msg = check_connection(config)
        assert success is True
        assert "0 worksheets" in msg

    @patch("seqsetup.services.sample_api._api_get")
    def test_non_list_response(self, mock_get):
        mock_get.return_value = {"error": "not a list"}
        config = SampleApiConfig(base_url="https://example.com/api", api_key="key")
        success, msg = check_connection(config)
        assert success is False
        assert "not a valid format" in msg

    @patch("seqsetup.services.sample_api._api_get")
    def test_network_error(self, mock_get):
        mock_get.side_effect = SampleApiError("Network error: Connection refused")
        config = SampleApiConfig(base_url="https://example.com/api", api_key="key")
        success, msg = check_connection(config)
        assert success is False
        assert "Connection refused" in msg

    @patch("seqsetup.services.sample_api._api_get")
    def test_http_error(self, mock_get):
        mock_get.side_effect = SampleApiError("API error: 401 Unauthorized")
        config = SampleApiConfig(base_url="https://example.com/api", api_key="bad")
        success, msg = check_connection(config)
        assert success is False
        assert "401" in msg

    @patch("seqsetup.services.sample_api._api_get")
    def test_unexpected_error(self, mock_get):
        mock_get.side_effect = RuntimeError("something broke")
        config = SampleApiConfig(base_url="https://example.com/api", api_key="key")
        success, msg = check_connection(config)
        assert success is False
        assert "something broke" in msg

    @patch("seqsetup.services.sample_api._api_get")
    def test_does_not_require_enabled(self, mock_get):
        """check_connection works even when config.enabled is False."""
        mock_get.return_value = [{"id": "1"}]
        config = SampleApiConfig(base_url="https://example.com/api", enabled=False)
        success, msg = check_connection(config)
        assert success is True


class TestEffectiveApiKey:
    """The api_key the service uses must prefer the env var over the stored
    field so production deployments can keep the secret out of MongoDB."""

    def test_env_var_overrides_stored_key(self, monkeypatch):
        monkeypatch.setenv("SEQSETUP_LIMS_API_KEY", "env-secret")
        config = SampleApiConfig(base_url="https://x", api_key="stored-secret")
        assert config.effective_api_key() == "env-secret"

    def test_falls_back_to_stored_when_env_absent(self, monkeypatch):
        monkeypatch.delenv("SEQSETUP_LIMS_API_KEY", raising=False)
        config = SampleApiConfig(base_url="https://x", api_key="stored-secret")
        assert config.effective_api_key() == "stored-secret"

    def test_empty_env_value_treated_as_unset(self, monkeypatch):
        monkeypatch.setenv("SEQSETUP_LIMS_API_KEY", "")
        config = SampleApiConfig(base_url="https://x", api_key="stored-secret")
        assert config.effective_api_key() == "stored-secret"

    def test_returns_empty_when_neither_set(self, monkeypatch):
        monkeypatch.delenv("SEQSETUP_LIMS_API_KEY", raising=False)
        config = SampleApiConfig(base_url="https://x")
        assert config.effective_api_key() == ""

    @patch("seqsetup.services.sample_api._api_get")
    def test_request_uses_effective_key_not_raw_field(self, mock_get, monkeypatch):
        """The HTTP request must carry the env value, not the stored placeholder."""
        from seqsetup.services.sample_api import fetch_worklists

        monkeypatch.setenv("SEQSETUP_LIMS_API_KEY", "env-secret")
        mock_get.return_value = []
        config = SampleApiConfig(
            base_url="https://example.com/api",
            api_key="stored-secret",
            enabled=True,
        )
        fetch_worklists(config)
        # mock_get was called with (url, api_key) — check the api_key arg.
        args, kwargs = mock_get.call_args
        called_key = args[1] if len(args) > 1 else kwargs.get("api_key")
        assert called_key == "env-secret"


class TestThrottle:
    """Per-host throttle paces requests to a configurable minimum interval."""

    def _reset_state(self):
        from seqsetup.services import sample_api as mod
        mod._LAST_REQUEST_AT.clear()

    def test_no_sleep_on_first_request(self, monkeypatch):
        from seqsetup.services import sample_api as mod
        self._reset_state()
        monkeypatch.setenv("SEQSETUP_LIMS_MIN_INTERVAL_MS", "100")
        sleep_calls: list = []
        monkeypatch.setattr(mod.time, "sleep", lambda s: sleep_calls.append(s))
        mod._throttle("lims.example.com")
        assert sleep_calls == []

    def test_sleeps_on_rapid_consecutive_requests(self, monkeypatch):
        from seqsetup.services import sample_api as mod
        self._reset_state()
        monkeypatch.setenv("SEQSETUP_LIMS_MIN_INTERVAL_MS", "100")

        # Pin monotonic to advance only when we tell it to.
        fake_now = [1000.0]
        monkeypatch.setattr(mod.time, "monotonic", lambda: fake_now[0])
        sleep_calls: list = []

        def fake_sleep(s):
            sleep_calls.append(s)
            fake_now[0] += s
        monkeypatch.setattr(mod.time, "sleep", fake_sleep)

        mod._throttle("lims.example.com")
        # Second call immediately — must sleep ~0.1s.
        mod._throttle("lims.example.com")
        assert len(sleep_calls) == 1
        assert sleep_calls[0] == pytest.approx(0.1, abs=1e-6)

    def test_separate_hosts_have_independent_budgets(self, monkeypatch):
        from seqsetup.services import sample_api as mod
        self._reset_state()
        monkeypatch.setenv("SEQSETUP_LIMS_MIN_INTERVAL_MS", "100")
        sleep_calls: list = []
        monkeypatch.setattr(mod.time, "sleep", lambda s: sleep_calls.append(s))

        mod._throttle("lims-a.example.com")
        mod._throttle("lims-b.example.com")  # different host — no wait
        assert sleep_calls == []

    def test_interval_zero_disables_throttle(self, monkeypatch):
        from seqsetup.services import sample_api as mod
        self._reset_state()
        monkeypatch.setenv("SEQSETUP_LIMS_MIN_INTERVAL_MS", "0")
        sleep_calls: list = []
        monkeypatch.setattr(mod.time, "sleep", lambda s: sleep_calls.append(s))

        mod._throttle("lims.example.com")
        mod._throttle("lims.example.com")
        assert sleep_calls == []


class TestValidateUrl:
    """``_validate_url`` enforces SSRF policy via DNS resolution.

    These tests stub ``socket.getaddrinfo`` so they're deterministic and
    don't actually touch the network. Each case mocks the resolution that
    a real DNS lookup would return, then asserts the policy decision.
    """

    @staticmethod
    def _stub_resolve(monkeypatch, ips):
        """Make ``socket.getaddrinfo`` return the given IP strings."""
        import socket
        from seqsetup.services import sample_api as mod

        def fake_getaddrinfo(host, port, *args, **kwargs):
            return [
                # (family, type, proto, canonname, (ip, port))
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", (ip, port or 0))
                for ip in ips
            ]
        monkeypatch.setattr(mod.socket, "getaddrinfo", fake_getaddrinfo)

    def test_blocks_loopback_v4(self, monkeypatch):
        from seqsetup.services.sample_api import _validate_url, SampleApiError
        monkeypatch.delenv("SEQSETUP_LIMS_ALLOW_PRIVATE_NETS", raising=False)
        self._stub_resolve(monkeypatch, ["127.0.0.1"])
        with pytest.raises(SampleApiError, match="loopback"):
            _validate_url("https://attacker.example/api")

    def test_blocks_loopback_v6(self, monkeypatch):
        from seqsetup.services.sample_api import _validate_url, SampleApiError
        monkeypatch.delenv("SEQSETUP_LIMS_ALLOW_PRIVATE_NETS", raising=False)
        self._stub_resolve(monkeypatch, ["::1"])
        with pytest.raises(SampleApiError, match="loopback"):
            _validate_url("https://attacker.example/api")

    def test_blocks_rfc1918(self, monkeypatch):
        from seqsetup.services.sample_api import _validate_url, SampleApiError
        monkeypatch.delenv("SEQSETUP_LIMS_ALLOW_PRIVATE_NETS", raising=False)
        self._stub_resolve(monkeypatch, ["10.0.0.5"])
        with pytest.raises(SampleApiError, match="loopback/private"):
            _validate_url("https://internal.corp/api")

    def test_blocks_link_local(self, monkeypatch):
        from seqsetup.services.sample_api import _validate_url, SampleApiError
        monkeypatch.delenv("SEQSETUP_LIMS_ALLOW_PRIVATE_NETS", raising=False)
        self._stub_resolve(monkeypatch, ["169.254.169.254"])
        with pytest.raises(SampleApiError, match="loopback/private"):
            # The AWS instance metadata service IP.
            _validate_url("https://metadata.local/")

    def test_blocks_cgnat(self, monkeypatch):
        from seqsetup.services.sample_api import _validate_url, SampleApiError
        monkeypatch.delenv("SEQSETUP_LIMS_ALLOW_PRIVATE_NETS", raising=False)
        self._stub_resolve(monkeypatch, ["100.64.0.10"])
        with pytest.raises(SampleApiError, match="loopback/private"):
            _validate_url("https://cgnat-neighbor.example/")

    def test_blocks_when_any_resolved_ip_is_private(self, monkeypatch):
        """Multi-record DNS: if *any* answer is private, refuse the whole
        request — otherwise an attacker could serve a mixed answer and
        rely on the OS to pick the private one at connect time."""
        from seqsetup.services.sample_api import _validate_url, SampleApiError
        monkeypatch.delenv("SEQSETUP_LIMS_ALLOW_PRIVATE_NETS", raising=False)
        self._stub_resolve(monkeypatch, ["1.2.3.4", "10.0.0.5"])
        with pytest.raises(SampleApiError, match="loopback/private"):
            _validate_url("https://mixed.example/")

    def test_allows_public_ip(self, monkeypatch):
        from seqsetup.services.sample_api import _validate_url
        import ipaddress
        monkeypatch.delenv("SEQSETUP_LIMS_ALLOW_PRIVATE_NETS", raising=False)
        self._stub_resolve(monkeypatch, ["8.8.8.8"])
        ips = _validate_url("https://lims.example.com/api")
        # Returns the resolved IPs so the caller can pin its connection.
        assert ipaddress.IPv4Address("8.8.8.8") in ips

    def test_private_allowed_when_env_opt_in(self, monkeypatch):
        from seqsetup.services.sample_api import _validate_url
        monkeypatch.setenv("SEQSETUP_LIMS_ALLOW_PRIVATE_NETS", "1")
        self._stub_resolve(monkeypatch, ["127.0.0.1"])
        # No exception; private IP is permitted with explicit opt-in.
        ips = _validate_url("https://mock-lims.local/")
        assert len(ips) == 1

    def test_rejects_unresolvable_hostname(self, monkeypatch):
        from seqsetup.services.sample_api import _validate_url, SampleApiError
        from seqsetup.services import sample_api as mod
        monkeypatch.delenv("SEQSETUP_LIMS_ALLOW_PRIVATE_NETS", raising=False)

        def raise_oserror(*args, **kwargs):
            raise OSError("Name or service not known")
        monkeypatch.setattr(mod.socket, "getaddrinfo", raise_oserror)

        with pytest.raises(SampleApiError, match="Cannot resolve"):
            _validate_url("https://does-not-exist.invalid/")

    def test_rejects_http_without_opt_in(self, monkeypatch):
        from seqsetup.services.sample_api import _validate_url, SampleApiError
        monkeypatch.delenv("SEQSETUP_LIMS_ALLOW_HTTP", raising=False)
        monkeypatch.delenv("SEQSETUP_LIMS_ALLOW_PRIVATE_NETS", raising=False)
        self._stub_resolve(monkeypatch, ["8.8.8.8"])
        with pytest.raises(SampleApiError, match="HTTP"):
            _validate_url("http://lims.example.com/api")

    def test_rejects_unsupported_scheme(self, monkeypatch):
        from seqsetup.services.sample_api import _validate_url, SampleApiError
        with pytest.raises(SampleApiError, match="Unsupported URL scheme"):
            _validate_url("ftp://host.example/path")

    def test_rejects_missing_hostname(self, monkeypatch):
        from seqsetup.services.sample_api import _validate_url, SampleApiError
        with pytest.raises(SampleApiError, match="no hostname"):
            _validate_url("https:///path")


class TestParseApiSamplesRepeatedIds:
    """A worklist that lists one sample ID twice is refused as a whole, like
    a paste: SeqSetup cannot tell which row is right (review DI-01; spec
    2026-10-03 group A1, §3)."""

    def test_a_repeated_id_is_refused(self):
        data = [{"sample_id": "P1"}, {"sample_id": "P2"}, {"sample_id": "P1"}]
        with pytest.raises(ValueError) as exc:
            parse_api_samples(data)
        assert str(exc.value) == (
            "these sample IDs appear more than once in the worklist: P1. Nothing was added."
        )

    def test_ids_are_compared_after_clean_up(self):
        data = [{"sample_id": " P1"}, {"sample_id": "P1 "}]
        with pytest.raises(ValueError, match=r"more than once in the worklist: P1\. Nothing"):
            parse_api_samples(data)

    def test_repeated_ids_are_named_in_first_seen_order(self):
        data = [{"sample_id": s} for s in ["B", "A", "C", "A", "B"]]
        with pytest.raises(ValueError, match=r"in the worklist: B, A\. Nothing"):
            parse_api_samples(data)

    def test_more_than_ten_repeated_ids_are_counted(self):
        ids = [f"P{k:02d}" for k in range(12)]
        with pytest.raises(ValueError) as exc:
            parse_api_samples([{"sample_id": s} for s in ids + ids])
        assert str(exc.value) == (
            "these sample IDs appear more than once in the worklist: "
            "P00, P01, P02, P03, P04, P05, P06, P07, P08, P09 and 2 more. Nothing was added."
        )

    def test_a_worklist_without_repeats_is_unchanged(self):
        data = [{"sample_id": "P1", "test_id": "WGS"}, {"sample_id": "P2", "test_id": "WES"}]
        assert parse_api_samples(data) == [
            {"sample_id": "P1", "test_id": "WGS"},
            {"sample_id": "P2", "test_id": "WES"},
        ]

    def test_a_missing_sample_id_is_still_reported_first(self):
        data = [{"sample_id": "P1"}, {"sample_id": ""}, {"sample_id": "P1"}]
        with pytest.raises(ValueError, match=r"LIMS row\(s\) 2: sample_id is missing"):
            parse_api_samples(data)


_MAX = sample_api_module._MAX_RESPONSE_SIZE
_PUBLIC_IP = ipaddress.ip_address("93.184.216.34")


class _CountingReader(io.BytesIO):
    """The file the client reads the response from. Counts the body bytes
    it hands out; the status line and headers are read with readline,
    which is not counted."""

    def __init__(self, data: bytes):
        super().__init__(data)
        self.handed_out = 0

    def read(self, size=-1):
        chunk = super().read(size)
        self.handed_out += len(chunk)
        return chunk

    def read1(self, size=-1):
        chunk = super().read1(size)
        self.handed_out += len(chunk)
        return chunk

    def readinto(self, buffer):
        n = super().readinto(buffer)
        self.handed_out += n
        return n


class _FakeSocket:
    """Stands in for the TCP connection: keeps what the client sends and
    plays back a 200 response with ``body``."""

    def __init__(self, body: bytes):
        head = (
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
        ).encode()
        self.reader = _CountingReader(head + body)
        self.sent = b""

    def sendall(self, data):
        self.sent += data

    def makefile(self, mode, *args, **kwargs):
        return self.reader

    def close(self):
        pass


@pytest.fixture
def lims_wire(monkeypatch):
    """Runs _api_get's real body and the real _PinnedHTTPSConnection.connect()
    with no network: the URL check returns a public address, the TCP
    connection is a _FakeSocket, and SSLContext.wrap_socket is a spy that
    records the context and host name, then hands the fake socket back."""
    wire = SimpleNamespace(body=b"[]", sockets=[], connects=[], wraps=[])

    def create_connection(address, *args, **kwargs):
        wire.connects.append(address)
        sock = _FakeSocket(wire.body)
        wire.sockets.append(sock)
        return sock

    def wrap_socket(context, sock, *args, server_hostname=None, **kwargs):
        wire.wraps.append((context, server_hostname))
        return sock

    monkeypatch.setenv("SEQSETUP_LIMS_MIN_INTERVAL_MS", "0")
    monkeypatch.setattr(sample_api_module, "_validate_url", lambda url: [_PUBLIC_IP])
    monkeypatch.setattr(sample_api_module.socket, "create_connection", create_connection)
    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", wrap_socket)
    return wire


def _get():
    return sample_api_module._api_get("https://lims.example.org/api/worksheets", api_key="k")


class TestLimsClientChecksTheCertificate:
    """CLAUDE.md: the LIMS client verifies the server's certificate. The
    check happens in _PinnedHTTPSConnection.connect(), which this runs
    (review H-4; spec 2026-10-03 group A1, §4)."""

    def test_https_wraps_the_connection_in_a_verifying_context(self, lims_wire):
        assert _get() == []
        assert lims_wire.connects == [("93.184.216.34", 443)]
        [(context, host)] = lims_wire.wraps
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname is True
        assert host == "lims.example.org"


class TestLimsClientCapsTheResponse:
    """CLAUDE.md: LIMS responses are capped at 10 MB, and the body is read
    with that bound, so a huge reply cannot fill the memory (review H-4;
    spec 2026-10-03 group A1, §4)."""

    def test_exactly_10_mb_is_read(self, lims_wire):
        lims_wire.body = b"[" + b" " * (_MAX - 2) + b"]"
        assert _get() == []

    def test_one_byte_over_10_mb_is_refused(self, lims_wire):
        lims_wire.body = b"[" + b" " * (_MAX - 1) + b"]"
        with pytest.raises(SampleApiError, match="exceeds maximum size limit"):
            _get()

    def test_the_body_is_read_with_a_bound(self, lims_wire):
        lims_wire.body = b"[" + b" " * (2 * _MAX - 2) + b"]"
        with pytest.raises(SampleApiError, match="exceeds maximum size limit"):
            _get()
        [sock] = lims_wire.sockets
        assert sock.reader.handed_out <= _MAX + 1
