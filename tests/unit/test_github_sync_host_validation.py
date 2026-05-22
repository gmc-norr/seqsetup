"""Tests for the GitHub content-host allow-list."""

import pytest

from seqsetup.services.github_sync import (
    GitHubSyncError,
    _validate_github_content_host,
)


class TestValidateGithubContentHost:
    """Refuse to fetch from hosts outside the GitHub content infrastructure.

    The download_url is API-returned but a maliciously-configured GitHub
    Enterprise base URL could direct us at arbitrary hosts; the allow-list
    is the seatbelt."""

    def test_raw_githubusercontent_allowed(self):
        _validate_github_content_host(
            "https://raw.githubusercontent.com/owner/repo/main/profiles/x.yaml"
        )

    def test_subdomain_of_githubusercontent_allowed(self):
        _validate_github_content_host(
            "https://media.githubusercontent.com/some/path.yaml"
        )

    def test_arbitrary_host_rejected(self):
        with pytest.raises(GitHubSyncError, match="Refused to fetch"):
            _validate_github_content_host("https://attacker.example.com/x.yaml")

    def test_lookalike_host_rejected(self):
        """`evil-githubusercontent.com` must not match the suffix rule."""
        with pytest.raises(GitHubSyncError, match="Refused to fetch"):
            _validate_github_content_host("https://evil-githubusercontent.com/x.yaml")

    def test_http_scheme_rejected(self):
        with pytest.raises(GitHubSyncError, match="non-HTTPS"):
            _validate_github_content_host("http://raw.githubusercontent.com/x.yaml")

    def test_empty_url_rejected(self):
        with pytest.raises(GitHubSyncError):
            _validate_github_content_host("")

    def test_metadata_endpoint_rejected(self):
        """Cloud metadata IPs/hosts must not slip through."""
        with pytest.raises(GitHubSyncError):
            _validate_github_content_host("https://169.254.169.254/latest/meta-data/")

    def test_exact_match_no_subdomain_allowed(self):
        """Exact match to raw.githubusercontent.com works."""
        _validate_github_content_host(
            "https://raw.githubusercontent.com/some/path.yaml"
        )
