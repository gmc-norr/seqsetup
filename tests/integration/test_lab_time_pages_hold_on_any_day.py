"""The lab-time page checks must not depend on the day they run.

``test_lab_time_pages.py``'s token-page check seeds a token and asserts the page
says neither "(expires soon)" nor "(EXPIRED)". The page compares the expiry with
the clock the route reads (``routes/api_tokens.utcnow``), so a fixed future
expiry rots: the same check fails from a week before that date onwards. This
runs that very check with the route's clock moved years ahead, and again on
today's clock.
"""

from datetime import datetime

import pytest

from seqsetup.routes import api_tokens as api_tokens_module

from . import test_lab_time_pages as lab_time_pages


class TestTheTokenPageCheckHoldsOnAnyDay:
    """The token page's lab-time check reads its expiry from the page's own clock."""

    @pytest.mark.parametrize("clock", [datetime(2027, 1, 9, 12, 0),
                                       datetime(2031, 6, 1, 12, 0)])
    def test_the_check_passes_whatever_the_clock_says(
        self, clock, logged_in_client, fresh_app, monkeypatch
    ):
        monkeypatch.setenv("TZ", "Europe/Stockholm")
        monkeypatch.setattr(api_tokens_module, "utcnow", lambda: clock)
        lab_time_pages.TestAdminPages().test_api_tokens(logged_in_client, fresh_app)

    def test_the_check_passes_on_todays_clock(
        self, logged_in_client, fresh_app, monkeypatch
    ):
        monkeypatch.setenv("TZ", "Europe/Stockholm")
        lab_time_pages.TestAdminPages().test_api_tokens(logged_in_client, fresh_app)
