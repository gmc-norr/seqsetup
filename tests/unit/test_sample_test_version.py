"""A sample's test version (spec 2026-10-07 group A4, §1): empty, or 1 to 3
whole numbers joined by dots, each at most 9 digits, checked on every
assignment and never shortened."""

import pytest

from seqsetup.models.sample import TEST_VERSION_RULE, Sample, checked_test_version


ALLOWED = ["1", "1.2", "1.2.3", "0", "10.0.1", "999999999.999999999.999999999"]
REFUSED = ["v1", "1.x", "1.2.3.4", "01", "1.", ".1", "1..2", "-1", "1234567890", "9" * 4301]


class TestTheRule:
    """What a sample's test version may be."""

    @pytest.mark.parametrize("text", ALLOWED)
    def test_these_are_kept(self, text):
        assert Sample(sample_id="S1", test_version=text).test_version == text

    def test_empty_is_no_version(self):
        assert Sample(sample_id="S1").test_version == ""
        assert Sample(sample_id="S1", test_version="").test_version == ""

    def test_spaces_around_are_stripped(self):
        assert Sample(sample_id="S1", test_version=" 1.2 ").test_version == "1.2"

    @pytest.mark.parametrize("text", REFUSED)
    def test_these_are_refused_at_construction(self, text):
        with pytest.raises(ValueError, match=TEST_VERSION_RULE):
            Sample(sample_id="S1", test_version=text)

    @pytest.mark.parametrize("text", REFUSED)
    def test_these_are_refused_on_assignment(self, text):
        sample = Sample(sample_id="S1", test_version="1")
        with pytest.raises(ValueError, match=TEST_VERSION_RULE):
            sample.test_version = text
        assert sample.test_version == "1"

    @pytest.mark.parametrize("value", [1, 1.1, True, None, ["1"]])
    def test_a_value_that_is_not_text_is_refused(self, value):
        with pytest.raises(ValueError, match=TEST_VERSION_RULE):
            Sample(sample_id="S1", test_version=value)

    def test_a_long_value_is_refused_not_shortened(self):
        # The model cuts other identifiers at 256; a version is never cut, so
        # a cut can never turn a bad value into a good one (review of 311d730).
        text = "1" + "0" * 300 + "v"
        with pytest.raises(ValueError, match=TEST_VERSION_RULE):
            Sample(sample_id="S1", test_version=text)


class TestTheMessage:
    """The message names the rule and shows at most 40 characters."""

    def test_it_shows_the_value(self):
        with pytest.raises(ValueError) as caught:
            checked_test_version("v1")
        assert str(caught.value) == f"{TEST_VERSION_RULE}: 'v1'"

    def test_a_long_value_is_shown_cut_to_40_characters(self):
        with pytest.raises(ValueError) as caught:
            checked_test_version("9" * 4301)
        assert str(caught.value) == f"{TEST_VERSION_RULE}: '{'9' * 40}…'"

    def test_the_rule_text(self):
        assert TEST_VERSION_RULE == (
            "A test version is 1, 2 or 3 whole numbers joined by dots, each at most "
            "9 digits, like 1, 1.2 or 1.2.3"
        )


class TestStorage:
    """The version is stored with the sample and copied with it."""

    def test_it_round_trips(self):
        sample = Sample(sample_id="S1", test_id="WGS", test_version="1.2")
        again = Sample.from_dict(sample.to_dict())
        assert (again.test_id, again.test_version) == ("WGS", "1.2")

    def test_a_sample_stored_before_versions_has_none(self):
        data = Sample(sample_id="S1", test_id="WGS").to_dict()
        del data["test_version"]
        assert Sample.from_dict(data).test_version == ""
