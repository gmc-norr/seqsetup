"""AuditEvent bounds every field, on construction and on assignment."""

from datetime import datetime, timedelta, timezone

from seqsetup.models.audit_event import FIELD_CAPS, MAX_DETAILS_BYTES, AuditEvent

T0 = datetime(2026, 9, 26, 12, 0, 0, tzinfo=timezone.utc)


class TestAuditEventCaps:
    """Text fields are cut to their cap; None becomes empty text."""

    def test_each_text_field_is_cut_to_its_cap(self):
        e = AuditEvent(
            timestamp=T0, event="e" * 500, actor="a" * 500,
            target="t" * 5000, outcome="o" * 500,
        )
        assert len(e.event) == FIELD_CAPS["event"] == 128
        assert len(e.actor) == FIELD_CAPS["actor"] == 256
        assert len(e.target) == FIELD_CAPS["target"] == 1024
        assert len(e.outcome) == FIELD_CAPS["outcome"] == 32

    def test_caps_apply_on_assignment_too(self):
        e = AuditEvent(timestamp=T0, event="x")
        e.target = "t" * 5000
        assert len(e.target) == 1024

    def test_none_and_non_text_become_text(self):
        e = AuditEvent(timestamp=T0, event="x", actor=None, target=42)
        assert e.actor == ""
        assert e.target == "42"


class TestAuditEventDetails:
    """Details stay small enough to store."""

    def test_small_details_are_kept(self):
        e = AuditEvent(timestamp=T0, event="x", details={"a": 1, "b": ["c"]})
        assert e.details == {"a": 1, "b": ["c"]}

    def test_missing_details_become_empty(self):
        assert AuditEvent(timestamp=T0, event="x", details=None).details == {}

    def test_oversized_details_are_replaced_by_a_marker(self):
        e = AuditEvent(timestamp=T0, event="x", details={"blob": "x" * (MAX_DETAILS_BYTES + 1)})
        assert e.details["details_omitted"] is True
        assert e.details["bytes"] > MAX_DETAILS_BYTES
        assert "blob" not in e.details

    def test_non_dict_details_are_replaced_by_a_marker(self):
        e = AuditEvent(timestamp=T0, event="x", details=["not", "a", "dict"])
        assert e.details == {"details_omitted": True, "reason": "not a dict"}


class TestAuditEventStorage:
    """to_dict / from_dict round-trip; timestamps are canonical UTC."""

    def test_round_trip(self):
        e = AuditEvent(timestamp=T0, event="run.status.changed", actor="alice",
                       target="run-1", outcome="success", details={"to": "ready"})
        back = AuditEvent.from_dict(e.to_dict())
        assert back.to_dict() == e.to_dict()
        assert back.id == e.id

    def test_timestamp_is_stored_as_utc_without_offset(self):
        cet = timezone(timedelta(hours=2))
        e = AuditEvent(timestamp=datetime(2026, 9, 26, 14, 0, tzinfo=cet), event="x")
        assert e.to_dict()["timestamp"] == "2026-09-26T12:00:00"

    def test_document_id_is_the_event_id(self):
        e = AuditEvent(timestamp=T0, event="x")
        assert e.to_dict()["_id"] == e.id
        assert e.cursor() == ("2026-09-26T12:00:00", e.id)
