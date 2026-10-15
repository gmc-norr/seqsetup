"""The run status rules in ``check_status_transition`` (routes/utils.py).

Draft -> Ready, Ready -> Draft and Ready -> Archived are the only moves;
Archived is terminal, and staying in the same status is not a move. The
function had no test of its own ("Risk 5" gap); this file checks every
(from, to) pair of the RunStatus values, so a new status or a new move
shows up here.
"""

import itertools

import pytest
from starlette.responses import Response

from seqsetup.models.sequencing_run import RunStatus
from seqsetup.routes.utils import check_status_transition

ALLOWED = {
    (RunStatus.DRAFT, RunStatus.READY),
    (RunStatus.READY, RunStatus.DRAFT),
    (RunStatus.READY, RunStatus.ARCHIVED),
}
ALL_PAIRS = list(itertools.product(RunStatus, RunStatus))
REFUSED = [pair for pair in ALL_PAIRS if pair not in ALLOWED]


def _id(pair):
    return f"{pair[0].value}->{pair[1].value}"


class TestTheStatusValues:
    """The rules below are written for exactly these three statuses."""

    def test_the_statuses_are_draft_ready_and_archived(self):
        assert [s.value for s in RunStatus] == ["draft", "ready", "archived"]

    def test_every_pair_is_either_allowed_or_refused(self):
        assert len(ALL_PAIRS) == 9
        assert len(REFUSED) == 6
        assert ALLOWED <= set(ALL_PAIRS)


class TestAllowedTransitions:
    """The three moves of the state machine pass: no response is returned."""

    @pytest.mark.parametrize("current,target", sorted(ALLOWED, key=_id),
                             ids=[_id(pair) for pair in sorted(ALLOWED, key=_id)])
    def test_an_allowed_move_returns_none(self, current, target):
        assert check_status_transition(current, target) is None


class TestRefusedTransitions:
    """Every other pair, same-status ones included, is refused with a 400
    that names both statuses."""

    @pytest.mark.parametrize("current,target", REFUSED, ids=[_id(pair) for pair in REFUSED])
    def test_a_refused_move_returns_a_400(self, current, target):
        refusal = check_status_transition(current, target)

        assert isinstance(refusal, Response)
        assert refusal.status_code == 400
        assert refusal.body.decode("utf-8") == (
            f"Invalid status transition: {current.value} → {target.value}"
        )

    @pytest.mark.parametrize("target", list(RunStatus), ids=lambda s: s.value)
    def test_archived_is_terminal(self, target):
        assert check_status_transition(RunStatus.ARCHIVED, target) is not None

    @pytest.mark.parametrize("status", list(RunStatus), ids=lambda s: s.value)
    def test_staying_in_the_same_status_is_refused(self, status):
        assert check_status_transition(status, status) is not None

    def test_a_draft_cannot_be_archived_without_being_ready(self):
        assert check_status_transition(RunStatus.DRAFT, RunStatus.ARCHIVED) is not None
