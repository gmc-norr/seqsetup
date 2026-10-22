"""The colour balance and dark cycle tabs say why they are empty.

When the instrument says colour balance is on but its stored settings state no
dye channels, the checks do not run (``color_balance_without_channels`` on the
Issues tab). The two tabs then said "No indexed samples to analyze" -- on a run
that has indexed samples (review leftover O5).
"""

from seqsetup.models.validation import ValidationResult
from seqsetup.routes.validation import _render_tab_contents

NO_SAMPLES = "No indexed samples to analyze"
NO_CHANNELS = "settings state no dye channels"


def _tabs(**fields):
    result = ValidationResult(duplicate_sample_ids=[], index_collision_groups=[],
                              distance_matrices={}, **fields)
    return _render_tab_contents("run-1", result)


class TestWithoutDyeChannels:
    """Colour balance on, no channels: the check did not run, and the tabs say so."""

    def test_the_colour_balance_tab_names_the_reason(self):
        html = _tabs(color_balance_enabled=True, channel_config=None)["color_balance_html"]
        assert NO_CHANNELS in html
        assert NO_SAMPLES not in html

    def test_the_dark_cycle_tab_names_the_reason(self):
        html = _tabs(color_balance_enabled=True, channel_config=None)["dark_cycles_html"]
        assert NO_CHANNELS in html
        assert NO_SAMPLES not in html

    def test_both_point_at_the_issues_tab(self):
        tabs = _tabs(color_balance_enabled=True, channel_config=None)
        for key in ("color_balance_html", "dark_cycles_html"):
            assert "Issues tab" in tabs[key], key


class TestTheOtherCasesKeepTheirWords:
    """Controls: with channels and nothing to count, the old words stay; with
    colour balance off, the not-applicable words stay."""

    CHANNELS = {"channel1_name": "Blue", "channel1_bases": ["A", "C"],
                "channel2_name": "Green", "channel2_bases": ["C", "T"], "dark_base": "G"}

    def test_channels_but_no_indexed_samples(self):
        tabs = _tabs(color_balance_enabled=True, channel_config=self.CHANNELS)
        for key in ("color_balance_html", "dark_cycles_html"):
            assert NO_SAMPLES in tabs[key], key
            assert NO_CHANNELS not in tabs[key], key

    def test_colour_balance_off(self):
        tabs = _tabs(color_balance_enabled=False, channel_config=None)
        for key in ("color_balance_html", "dark_cycles_html"):
            assert "not applicable for this instrument" in tabs[key], key
            assert NO_CHANNELS not in tabs[key], key
