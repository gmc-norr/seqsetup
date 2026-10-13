"""The LIMS api-key comes only from SEQSETUP_LIMS_API_KEY.

A key used to be stored in the settings document and preferred whenever the
environment variable was unset, so the secret lived in every database backup
and in the admin form's round trip. The settings model now never writes an
api-key, never holds one it read, and never uses one it finds: it only
reports that an old one is there, so the admin page can say that saving
removes it.
"""

import dataclasses

import pytest

from seqsetup.models.sample_api_config import SampleApiConfig


KEY_ENV = "SEQSETUP_LIMS_API_KEY"
STORED = "STORED-KEY-FROM-AN-OLD-DEPLOYMENT"


class TestTheKeyComesFromTheEnvironment:
    """``effective_api_key`` reads one source and no other."""

    def test_the_environment_value_is_used(self, monkeypatch):
        monkeypatch.setenv(KEY_ENV, "env-value")
        assert SampleApiConfig(base_url="https://x").effective_api_key() == "env-value"

    def test_no_environment_value_means_no_key(self, monkeypatch):
        monkeypatch.delenv(KEY_ENV, raising=False)
        assert SampleApiConfig(base_url="https://x").effective_api_key() == ""

    def test_a_stored_key_is_not_used(self, monkeypatch):
        """The whole point: a document that still holds a key is ignored."""
        monkeypatch.delenv(KEY_ENV, raising=False)
        config = SampleApiConfig.from_dict({"base_url": "https://x", "api_key": STORED})
        assert config.effective_api_key() == ""

    def test_a_stored_key_is_not_kept_on_the_model(self, monkeypatch):
        monkeypatch.delenv(KEY_ENV, raising=False)
        config = SampleApiConfig.from_dict({"base_url": "https://x", "api_key": STORED})
        assert STORED not in repr(config)
        assert STORED not in str(dataclasses.asdict(config))

    def test_the_model_has_no_api_key_field(self):
        names = {f.name for f in dataclasses.fields(SampleApiConfig)}
        assert "api_key" not in names


class TestSavingRemovesAnOldStoredKey:
    """``to_dict`` is what the repository writes."""

    def test_the_saved_document_has_no_api_key(self):
        assert "api_key" not in SampleApiConfig(base_url="https://x").to_dict()

    def test_a_document_read_and_written_back_loses_the_key(self):
        config = SampleApiConfig.from_dict({"base_url": "https://x", "api_key": STORED})
        assert "api_key" not in config.to_dict()

    def test_a_stored_key_is_reported_so_the_page_can_say_so(self):
        config = SampleApiConfig.from_dict({"base_url": "https://x", "api_key": STORED})
        assert config.legacy_api_key_stored is True

    @pytest.mark.parametrize("data", [
        {"base_url": "https://x"},
        {"base_url": "https://x", "api_key": ""},
    ])
    def test_no_stored_key_is_reported_when_there_is_none(self, data):
        assert SampleApiConfig.from_dict(data).legacy_api_key_stored is False

    def test_the_report_is_not_written_back_to_the_database(self):
        config = SampleApiConfig.from_dict({"base_url": "https://x", "api_key": STORED})
        assert "legacy_api_key_stored" not in config.to_dict()
