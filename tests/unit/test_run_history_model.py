"""Tests for the RunHistoryEntry model."""

from datetime import datetime, timedelta, timezone

from seqsetup.models.run_history import RunHistoryEntry, _canonical_ts


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

    def test_cursor_matches_stored_timestamp(self):
        # The keyset cursor MUST equal the persisted timestamp string, or
        # pagination's $lt comparison skips/duplicates entries.
        e = _entry()
        assert e.cursor() == (e.to_dict()["timestamp"], e.id)


class TestTimestampNormalization:
    """Keyset pagination compares ISO timestamp STRINGS lexically; that only
    matches chronological order if every stored timestamp uses one canonical,
    fixed-width, offset-free representation. These tests lock that contract."""

    def test_naive_timestamp_is_byte_identical_to_isoformat(self):
        # The canonical form must match plain isoformat() for naive datetimes so
        # rows written before this normalization (which used isoformat) compare
        # byte-for-byte equal — no migration boundary in the keyset cursor.
        for ts in (datetime(2026, 6, 11, 10, 30, 0),          # whole second
                   datetime(2026, 6, 11, 10, 30, 0, 123456)):  # sub-second
            assert _entry(timestamp=ts).to_dict()["timestamp"] == ts.isoformat()

    def test_timezone_aware_normalized_to_utc_naive(self):
        tz = timezone(timedelta(hours=2))
        e = _entry(timestamp=datetime(2026, 6, 11, 12, 30, 0, tzinfo=tz))
        ts = e.to_dict()["timestamp"]
        assert ts == "2026-06-11T10:30:00"   # 12:30+02:00 == 10:30 UTC, offset-free
        assert "+" not in ts                 # no offset suffix
        assert e.cursor()[0] == ts

    def test_naive_and_tzaware_same_instant_serialize_equal(self):
        naive = _entry(timestamp=datetime(2026, 6, 11, 10, 30, 0))
        aware = _entry(timestamp=datetime(2026, 6, 11, 12, 30, 0,
                                          tzinfo=timezone(timedelta(hours=2))))
        assert naive.to_dict()["timestamp"] == aware.to_dict()["timestamp"]
