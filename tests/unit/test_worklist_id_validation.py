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
    def test_a_newline_at_the_end_is_refused(self):
        """The pattern's $ also matched before a final newline, so "W2\\n"
        passed (review of the fixes after the build of later list slice 2)."""
        with pytest.raises(InvalidWorklistIdError):
            validate_worklist_id("W2\n")

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


class TestAnIdMadeOnlyOfDots:
    """The alphabet admitted ".", ".." and "...", and ``quote`` leaves a dot
    alone, so ``GET {base}/worksheets/..`` went out with the LIMS api-key --
    and any server or proxy that normalises dot segments served ``{base}/``
    instead. Whatever JSON came back was shown in the preview or imported as
    samples (security review 2026-10)."""

    @pytest.mark.parametrize("worklist_id", [".", "..", "...", "." * 10, "." * 128])
    def test_it_is_refused(self, worklist_id):
        with pytest.raises(InvalidWorklistIdError, match="only of dots"):
            validate_worklist_id(worklist_id)

    @pytest.mark.parametrize("worklist_id", [".", "..", "..."])
    def test_no_url_is_built_for_it(self, worklist_id):
        config = SampleApiConfig(base_url="https://lims.example.com/api")

        with pytest.raises(InvalidWorklistIdError, match="only of dots"):
            config.worklist_samples_url(worklist_id)

    @pytest.mark.parametrize("worklist_id",
                             ["WL-1", "1.2", "1.0.2", ".hidden", "trailing.", "W-2_a.b~c"])
    def test_an_id_that_merely_holds_a_dot_still_passes(self, worklist_id):
        validate_worklist_id(worklist_id)

    def test_an_id_that_merely_holds_a_dot_still_round_trips(self):
        config = SampleApiConfig(base_url="https://lims.example.com/api")

        assert config.worklist_samples_url("1.2") == (
            "https://lims.example.com/api/worksheets/1.2")
