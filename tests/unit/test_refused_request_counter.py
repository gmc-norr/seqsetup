"""One audit row per client address per limiter window, carrying the count.

Every refused sign-in used to write its own ``login.rate_limited`` row, so
a flood of a few thousand requests buried every other event on
Admin > Audit under a few thousand rows that all said the same thing. The
counter below decides what the handler writes: a row for the first refusal
of an address's window, nothing for the ones that follow, and their count
carried by that address's next row. The audit trail is insert-only, so a
row that has been written is never changed.
"""

import pytest

from seqsetup.rate_limit import RefusedRequestCounter


WINDOW = 60


@pytest.fixture
def counter():
    return RefusedRequestCounter(WINDOW)


def _age(counter, identity, seconds):
    """Move an identity's window back in time, as waiting would."""
    started, pending = counter._windows[identity]
    counter._windows[identity] = (started - seconds, pending)


def _sweep_is_due(counter):
    """The sweep runs at most once per window; make the next call do it."""
    counter._swept_at -= counter.window_seconds


class TestOneRowPerWindow:
    def test_the_first_refusal_asks_for_a_row_of_one(self, counter):
        assert counter.count_refusal("1.2.3.4") == 1

    def test_the_refusals_that_follow_ask_for_none(self, counter):
        counter.count_refusal("1.2.3.4")
        assert [counter.count_refusal("1.2.3.4") for _ in range(9)] == [0] * 9

    def test_each_address_has_its_own_window(self, counter):
        assert counter.count_refusal("1.2.3.4") == 1
        assert counter.count_refusal("5.6.7.8") == 1
        assert counter.count_refusal("1.2.3.4") == 0


class TestTheCountIsCarriedByTheNextRow:
    def test_the_next_window_carries_what_was_counted(self, counter):
        counter.count_refusal("1.2.3.4")           # row of 1
        for _ in range(9):
            counter.count_refusal("1.2.3.4")       # counted, no row
        _age(counter, "1.2.3.4", WINDOW)

        assert counter.count_refusal("1.2.3.4") == 1 + 9

    def test_nothing_is_counted_twice(self, counter):
        counter.count_refusal("1.2.3.4")
        for _ in range(4):
            counter.count_refusal("1.2.3.4")
        _age(counter, "1.2.3.4", WINDOW)
        counter.count_refusal("1.2.3.4")

        assert counter.count_refusal("1.2.3.4") == 0

    def test_every_refusal_is_accounted_for_exactly_once(self, counter):
        """The sum of the rows asked for equals the refusals that happened."""
        asked = 0
        for round_number in range(5):
            for _ in range(7):
                asked += counter.count_refusal("1.2.3.4")
            _age(counter, "1.2.3.4", WINDOW)
        asked += counter.count_refusal("1.2.3.4")

        assert asked == 5 * 7 + 1

    def test_a_window_with_no_second_refusal_carries_nothing_extra(self, counter):
        counter.count_refusal("1.2.3.4")
        _age(counter, "1.2.3.4", WINDOW)

        assert counter.count_refusal("1.2.3.4") == 1


class TestWhatItHoldsOnTo:
    """A flood from many addresses must not add a key per address and give
    none back, the way RateLimiter._sweep already stops it doing."""

    def test_an_address_that_owes_nothing_is_forgotten(self, counter):
        counter.count_refusal("1.2.3.4")
        _age(counter, "1.2.3.4", WINDOW * 3)
        _sweep_is_due(counter)

        counter.count_refusal("5.6.7.8")

        assert "1.2.3.4" not in counter._windows

    def test_an_address_that_owes_a_count_is_kept(self, counter):
        """The sweep must not be where a count is lost."""
        counter.count_refusal("1.2.3.4")
        counter.count_refusal("1.2.3.4")           # one owed
        _age(counter, "1.2.3.4", WINDOW * 3)
        _sweep_is_due(counter)

        counter.count_refusal("5.6.7.8")

        assert "1.2.3.4" in counter._windows
        assert counter.count_refusal("1.2.3.4") == 2

    def test_the_sweep_runs_at_most_once_per_window(self, counter):
        """Not due: the stale entry is still there, and nothing walked the
        whole dict on this refusal."""
        counter.count_refusal("1.2.3.4")
        _age(counter, "1.2.3.4", WINDOW * 3)

        counter.count_refusal("5.6.7.8")

        assert "1.2.3.4" in counter._windows

    def test_reset_empties_it(self, counter):
        counter.count_refusal("1.2.3.4")
        counter.reset()
        assert counter._windows == {}
        assert counter.count_refusal("1.2.3.4") == 1


class TestItTakesTheLoginLimitersWindow:
    def test_the_shared_counter_matches_the_login_limiter(self):
        from seqsetup.rate_limit import get_login_limiter, get_login_refusal_counter

        assert (get_login_refusal_counter().window_seconds
                == get_login_limiter().window_seconds)

    def test_reset_all_limiters_resets_it_too(self):
        from seqsetup.rate_limit import get_login_refusal_counter, reset_all_limiters

        get_login_refusal_counter().count_refusal("1.2.3.4")
        reset_all_limiters()
        assert get_login_refusal_counter().count_refusal("1.2.3.4") == 1
