"""Tests for sample_api service."""

import json
from unittest.mock import patch, MagicMock

import pytest

from seqsetup.models.sample_api_config import SampleApiConfig
from seqsetup.services.sample_api import check_connection, SampleApiError


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
