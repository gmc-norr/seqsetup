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
