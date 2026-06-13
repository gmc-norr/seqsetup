"""Unit tests for run_history service helpers (size-bounding summarization).

A bulk paste / worklist import wraps the whole import in one saving_run, so the
diff produces a single RunHistoryEntry covering all N samples. With
MAX_SAMPLES_PER_RUN=5000 and per-field before/after snapshots, that entry can
approach or exceed MongoDB's 16 MB BSON document limit; the oversized insert
would then be swallowed by the best-effort guard, silently dropping the most
audit-worthy edit from the clinical change history. The service summarizes
oversized entries so the trail always records THAT a bulk change happened.
"""

from seqsetup.services.run_history import (
    _summarize_field_changes,
    _summarize_sample_changes,
)


def _sc(kind, sid):
    return {"sample_id": sid, "kind": kind, "fields": [
        {"name": "sample_id", "before": None, "after": sid}]}


class TestSummarizeSampleChanges:
    def test_counts_by_kind_and_total(self):
        changes = (
            [_sc("added", f"A{i}") for i in range(3)]
            + [_sc("removed", f"R{i}") for i in range(2)]
            + [_sc("modified", f"M{i}") for i in range(4)]
        )
        out = _summarize_sample_changes(changes)
        assert len(out) == 1
        s = out[0]
        assert s["kind"] == "summary"
        assert s["fields"] == []          # detail intentionally omitted
        assert s["summary"] == {"added": 3, "removed": 2, "modified": 4,
                                "total": 9}

    def test_empty(self):
        out = _summarize_sample_changes([])
        assert out[0]["summary"]["total"] == 0


class TestSummarizeFieldChanges:
    def test_collapses_to_single_count_marker(self):
        changes = [{"field": "run_name", "before": "A", "after": "B"},
                   {"field": "analyses", "before": [], "after": [1, 2, 3]}]
        out = _summarize_field_changes(changes)
        assert len(out) == 1
        assert out[0]["field"] == "(summary)"
        assert "2" in out[0]["after"]   # the count appears in the marker
