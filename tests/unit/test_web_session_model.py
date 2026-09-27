"""One login row: bounded text, UTC times, a clean round trip."""

from datetime import datetime, timedelta, timezone

from seqsetup.models.user import UserRole
from seqsetup.models.web_session import TEXT_CAP, WebSession, as_utc

T0 = datetime(2026, 9, 27, 8, 0, 0)


def _ws(**kw):
    base = dict(id="h" * 64, username="alice", display_name="Alice", role=UserRole.ADMIN,
                source="local", session_stamp="s" * 32, created_at=T0, last_seen_at=T0)
    base.update(kw)
    return WebSession(**base)


class TestWebSession:
    """The model bounds text and keeps times in UTC."""

    def test_round_trip(self):
        ws = _ws(email="a@example.com")
        again = WebSession.from_dict(ws.to_dict())
        assert again == ws and ws.to_dict()["_id"] == ws.id

    def test_text_is_capped_on_construction_and_assignment(self):
        ws = _ws(username="u" * 999)
        assert len(ws.username) == TEXT_CAP
        ws.display_name = "d" * 999
        ws.email = "e" * 999
        assert len(ws.display_name) == TEXT_CAP and len(ws.email) == TEXT_CAP

    def test_aware_times_become_naive_utc(self):
        aware = datetime(2026, 9, 27, 10, 0, tzinfo=timezone(timedelta(hours=2)))
        ws = _ws(created_at=aware, last_seen_at=aware)
        assert ws.created_at == T0 and ws.created_at.tzinfo is None

    def test_as_utc_leaves_naive_alone(self):
        assert as_utc(T0) == T0

    def test_to_user_carries_source_and_stamp(self):
        user = _ws(email="a@example.com").to_user()
        assert (user.username, user.role, user.email) == ("alice", UserRole.ADMIN, "a@example.com")
        assert (user.source, user.session_stamp) == ("local", "s" * 32)
