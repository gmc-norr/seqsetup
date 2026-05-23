"""Tests for the LIMS worklist_id validator (audit C7).

Operator-supplied worklist_id flows into the URL path. The validator
keeps it strictly path-segment-safe, and the URL builder quotes it
defensively in case the regex ever loosens.
"""

import pytest

from seqsetup.models.sample_api_config import (
    InvalidWorklistIdError,
    SampleApiConfig,
    validate_worklist_id,
)


class TestValidateWorklistId:
    def test_well_formed_id_allowed(self):
        validate_worklist_id("WL-2025-001")
        validate_worklist_id("worklist.123")
        validate_worklist_id("a_b-c.d~e")

    def test_empty_rejected(self):
        with pytest.raises(InvalidWorklistIdError, match="required"):
            validate_worklist_id("")

    def test_too_long_rejected(self):
        with pytest.raises(InvalidWorklistIdError, match="too long"):
            validate_worklist_id("x" * 129)

    def test_path_injection_rejected(self):
        with pytest.raises(InvalidWorklistIdError):
            validate_worklist_id("../admin")

    def test_query_injection_rejected(self):
        with pytest.raises(InvalidWorklistIdError):
            validate_worklist_id("wl-1?status=draft")

    def test_fragment_rejected(self):
        with pytest.raises(InvalidWorklistIdError):
            validate_worklist_id("wl-1#frag")

    def test_space_rejected(self):
        with pytest.raises(InvalidWorklistIdError):
            validate_worklist_id("wl 1")

    def test_unicode_rejected(self):
        with pytest.raises(InvalidWorklistIdError):
            validate_worklist_id("wl-café")


class TestWorklistUrlBuilder:
    def test_well_formed_id_round_trips(self):
        config = SampleApiConfig(base_url="https://lims.example.com/api")
        url = config.worklist_samples_url("WL-2025-001")
        assert url == "https://lims.example.com/api/worksheets/WL-2025-001"

    def test_injection_attempt_raises_before_url_built(self):
        config = SampleApiConfig(base_url="https://lims.example.com/api")
        with pytest.raises(InvalidWorklistIdError):
            config.worklist_samples_url("WL-1/../admin")
