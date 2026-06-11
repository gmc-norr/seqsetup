"""Tests for the RunHistoryEntry model."""

from datetime import datetime

from seqsetup.models.run_history import RunHistoryEntry


def _entry(**kw):
    base = dict(
        run_id="run-1",
        timestamp=datetime(2026, 6, 11, 10, 30, 0),
        actor="alice",
        kind="updated",
        field_changes=[{"field": "flowcell_type", "before": "10B", "after": "25B"}],
        sample_changes=[{"sample_id": "S1", "kind": "added",
                         "fields": [{"name": "sample_id", "before": None, "after": "S1"}]}],
    )
    base.update(kw)
    return RunHistoryEntry(**base)


class TestRunHistoryEntry:
    def test_round_trips_through_dict(self):
        e = _entry(provenance=None)
        r = RunHistoryEntry.from_dict(e.to_dict())
        assert r.run_id == "run-1"
        assert r.actor == "alice"
        assert r.kind == "updated"
        assert r.timestamp == datetime(2026, 6, 11, 10, 30, 0)
        assert r.field_changes[0]["after"] == "25B"
        assert r.sample_changes[0]["sample_id"] == "S1"
        assert r.provenance is None

    def test_created_entry_carries_provenance(self):
        e = _entry(kind="created", field_changes=[], sample_changes=[],
                   provenance={"source": "template", "ref": "tmpl-9"})
        r = RunHistoryEntry.from_dict(e.to_dict())
        assert r.kind == "created"
        assert r.provenance == {"source": "template", "ref": "tmpl-9"}

    def test_id_assigned_by_default_and_in_dict(self):
        e = _entry()
        assert e.id
        assert e.to_dict()["_id"] == e.id
        assert e.to_dict()["id"] == e.id

    def test_cursor_exposes_timestamp_and_id(self):
        e = _entry()
        assert e.cursor() == (e.timestamp.isoformat(), e.id)
