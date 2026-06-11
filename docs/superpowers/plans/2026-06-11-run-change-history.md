# Per-Run Change History Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give each run a queryable, append-only, field-level change history (who changed what, when) captured automatically at the run-mutation chokepoint and surfaced read-only in the run UI.

**Architecture:** A pure diff engine (`services/run_diff.py`) compares `SequencingRun.to_dict()` snapshots; a `RunHistoryEntry` model + insert-only `RunHistoryRepository` persist entries; recording helpers in `services/run_history.py` are invoked from `saving_run` (edits, after a successful save) and the three creation sites (blank/clone/template); a lazy-loaded HTMX panel renders the timeline. History writes are exception-guarded and best-effort (standalone Mongo has no transactions) — failures log + audit, never block the clinical edit.

**Tech Stack:** Python 3 / dataclasses, FastAPI + APIRouter, Jinja2 + HTMX, MongoDB via `BaseRepository`, pytest (`pixi run test`).

## Spec

Source: `docs/superpowers/specs/2026-06-11-run-change-history-design.md`. Read it before starting.

## File Structure

**Create:**
- `src/seqsetup/models/run_history.py` — `RunHistoryEntry` dataclass.
- `src/seqsetup/services/run_diff.py` — pure diff engine (`diff_run`, `is_empty`, ignore sets).
- `src/seqsetup/services/run_history.py` — recording helpers (`record_run_updated`, `record_run_created`).
- `src/seqsetup/repositories/run_history_repo.py` — `RunHistoryRepository` (insert-only, indexed, pageable).
- `src/seqsetup/templates/runs/_history_list.html` — timeline partial.
- `tests/unit/test_run_history_model.py`
- `tests/unit/test_run_diff.py`
- `tests/integration/test_run_history.py`

**Modify:**
- `src/seqsetup/context.py` — add `run_history_repo` field.
- `src/seqsetup/startup.py` — register repo + getter + wire into `get_app_context()`.
- `src/seqsetup/routes/dependencies.py` — `saving_run` captures before-snapshot + records after save.
- `src/seqsetup/routes/wizard.py` — `wizard_new` records a `created` (blank) entry.
- `src/seqsetup/routes/run_templates.py` — `duplicate_run` + `new_run_from_template` record `created` entries.
- `src/seqsetup/routes/dashboard.py` — `delete_run` cascades `delete_by_run`.
- `src/seqsetup/routes/runs.py` — add `GET /runs/{run_id}/history` route.
- `src/seqsetup/templates/runs/edit.html` — add lazy-loaded History panel.

---

## Task 1: `RunHistoryEntry` model

**Files:**
- Create: `src/seqsetup/models/run_history.py`
- Test: `tests/unit/test_run_history_model.py`

- [ ] **Step 1: Write the failing test**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pixi run test tests/unit/test_run_history_model.py -v`
Expected: FAIL — `ModuleNotFoundError: seqsetup.models.run_history`.

- [ ] **Step 3: Write the implementation**

Create `src/seqsetup/models/run_history.py`:

```python
"""Append-only per-run change-history entry.

Records who changed what on a run and when. Produced by services.run_history
from the diff in services.run_diff; persisted by RunHistoryRepository
(insert-only). Not user-input-facing — values come from the diff engine and
run metadata, so this model is a plain serializable record.
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class RunHistoryEntry:
    """One change-history record for a run."""

    run_id: str
    timestamp: datetime
    actor: str
    kind: str  # "created" | "updated"
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    provenance: Optional[dict] = None  # created: {"source": ..., "ref": ...}
    field_changes: list = field(default_factory=list)   # [{field, before, after}]
    sample_changes: list = field(default_factory=list)  # [{sample_id, kind, fields}]

    def cursor(self) -> tuple:
        """Keyset-pagination cursor: (timestamp_iso, id)."""
        return (self.timestamp.isoformat(), self.id)

    def to_dict(self) -> dict:
        return {
            "_id": self.id,
            "id": self.id,
            "run_id": self.run_id,
            "timestamp": self.timestamp.isoformat(),
            "actor": self.actor,
            "kind": self.kind,
            "provenance": self.provenance,
            "field_changes": self.field_changes,
            "sample_changes": self.sample_changes,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "RunHistoryEntry":
        ts = data["timestamp"]
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts)
        return cls(
            id=data.get("_id") or data["id"],
            run_id=data["run_id"],
            timestamp=ts,
            actor=data.get("actor", ""),
            kind=data.get("kind", "updated"),
            provenance=data.get("provenance"),
            field_changes=data.get("field_changes", []),
            sample_changes=data.get("sample_changes", []),
        )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pixi run test tests/unit/test_run_history_model.py -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add src/seqsetup/models/run_history.py tests/unit/test_run_history_model.py
git commit -m "feat(history): add RunHistoryEntry model

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Diff engine (`services/run_diff.py`)

**Files:**
- Create: `src/seqsetup/services/run_diff.py`
- Test: `tests/unit/test_run_diff.py`

This is pure logic over `SequencingRun.to_dict()` dicts — no DB, no model imports.

- [ ] **Step 1: Write the failing tests**

```python
"""Tests for the run diff engine."""

from seqsetup.services.run_diff import diff_run, is_empty


def _run_dict(**over):
    base = {
        "_id": "r1", "id": "r1",
        "run_name": "Run", "run_description": "",
        "status": "draft", "created_by": "bob", "updated_by": "bob",
        "created_at": "2026-06-11T10:00:00", "updated_at": "2026-06-11T10:00:00",
        "wizard_step": 1,
        "instrument_platform": "NovaSeq X Series", "flowcell_type": "10B",
        "reagent_cycles": 300, "run_cycles": {"read1_cycles": 151},
        "barcode_mismatches_index1": 1, "barcode_mismatches_index2": 1,
        "adapter_behavior": "trim", "create_fastq_for_index_reads": False,
        "no_lane_splitting": False, "samples": [], "analyses": [],
        "generated_samplesheet_v2": None, "generated_json": None,
    }
    base.update(over)
    return base


def _sample(sid_uuid="u1", sample_id="S1", **over):
    s = {
        "id": sid_uuid, "sample_id": sample_id, "sample_name": "", "project": "",
        "test_id": "", "worksheet_id": "", "lanes": [], "index_pair": None,
        "index1": None, "index2": None, "index_kit_name": None,
        "override_cycles": None, "barcode_mismatches_index1": 1,
        "barcode_mismatches_index2": 1, "index1_cycles": None, "index2_cycles": None,
        "index1_override_pattern": None, "index2_override_pattern": None,
        "read1_override_pattern": None, "read2_override_pattern": None,
        "analyses": [], "description": "", "metadata": {},
    }
    s.update(over)
    return s


class TestConfigDiff:
    def test_scalar_field_change(self):
        fc, sc = diff_run(_run_dict(), _run_dict(flowcell_type="25B"))
        assert sc == []
        assert {"field": "flowcell_type", "before": "10B", "after": "25B"} in fc

    def test_status_change(self):
        fc, _ = diff_run(_run_dict(), _run_dict(status="ready"))
        assert {"field": "status", "before": "draft", "after": "ready"} in fc

    def test_ignored_keys_excluded(self):
        # Only volatile fields differ -> no field_changes.
        after = _run_dict(updated_at="2026-06-11T11:00:00", updated_by="alice",
                          wizard_step=3, generated_samplesheet_v2="SHEET",
                          generated_json="J")
        fc, sc = diff_run(_run_dict(), after)
        assert fc == [] and sc == []

    def test_nested_run_cycles_whole_value(self):
        fc, _ = diff_run(_run_dict(), _run_dict(run_cycles={"read1_cycles": 100}))
        assert any(c["field"] == "run_cycles" for c in fc)


class TestSampleDiff:
    def test_added(self):
        fc, sc = diff_run(_run_dict(samples=[]), _run_dict(samples=[_sample()]))
        assert len(sc) == 1 and sc[0]["kind"] == "added" and sc[0]["sample_id"] == "S1"
        # snapshot present
        names = {f["name"] for f in sc[0]["fields"]}
        assert "sample_id" in names

    def test_removed(self):
        fc, sc = diff_run(_run_dict(samples=[_sample()]), _run_dict(samples=[]))
        assert sc[0]["kind"] == "removed" and sc[0]["sample_id"] == "S1"

    def test_index_reassignment_is_modified(self):
        before = _run_dict(samples=[_sample(index1={"name": "D701", "sequence": "ATTACTCG"})])
        after = _run_dict(samples=[_sample(index1={"name": "D702", "sequence": "TCCGGAGA"})])
        fc, sc = diff_run(before, after)
        assert sc[0]["kind"] == "modified"
        chg = next(f for f in sc[0]["fields"] if f["name"] == "index1")
        assert chg["before"]["name"] == "D701" and chg["after"]["name"] == "D702"

    def test_easily_forgotten_field_tracked(self):
        before = _run_dict(samples=[_sample(index1_cycles=8)])
        after = _run_dict(samples=[_sample(index1_cycles=10)])
        _, sc = diff_run(before, after)
        chg = next(f for f in sc[0]["fields"] if f["name"] == "index1_cycles")
        assert chg["before"] == 8 and chg["after"] == 10

    def test_sample_id_rename_same_uuid_is_modified_not_replace(self):
        before = _run_dict(samples=[_sample(sid_uuid="u1", sample_id="S1")])
        after = _run_dict(samples=[_sample(sid_uuid="u1", sample_id="S2")])
        _, sc = diff_run(before, after)
        assert len(sc) == 1 and sc[0]["kind"] == "modified"
        chg = next(f for f in sc[0]["fields"] if f["name"] == "sample_id")
        assert chg["before"] == "S1" and chg["after"] == "S2"


class TestIsEmpty:
    def test_empty_true_when_no_changes(self):
        fc, sc = diff_run(_run_dict(), _run_dict())
        assert is_empty(fc, sc) is True

    def test_empty_false_with_a_change(self):
        fc, sc = diff_run(_run_dict(), _run_dict(run_name="X"))
        assert is_empty(fc, sc) is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pixi run test tests/unit/test_run_diff.py -v`
Expected: FAIL — `ModuleNotFoundError: seqsetup.services.run_diff`.

- [ ] **Step 3: Write the implementation**

Create `src/seqsetup/services/run_diff.py`:

```python
"""Pure field-level diff of two SequencingRun.to_dict() snapshots.

Produces (field_changes, sample_changes) for the change-history feature.
No DB, no model imports — operates only on plain dicts so it is trivially
unit-tested.
"""

# Top-level run keys excluded from the config diff: volatile outputs, per-touch
# metadata, the optimistic-lock token, transient UI state, the doc id, and
# `samples` (handled separately, deep). Mirrors _FINGERPRINT_IGNORED_KEYS in
# routes/runs.py plus wizard_step and samples.
RUN_DIFF_IGNORED_KEYS = {
    "_id", "id", "samples",
    "updated_at", "updated_by", "_loaded_updated_at", "wizard_step",
    "generated_samplesheet_v2", "generated_samplesheet_v1", "generated_json",
    "generated_validation_json", "generated_validation_pdf",
}

# Sample keys excluded from the per-sample diff: only the pairing uuid. Every
# other persisted field is tracked (a DENYLIST — an allowlist would silently
# drop fields the way audit drift does, which is exactly what this prevents).
SAMPLE_IGNORED_KEYS = {"id"}


def _config_changes(before: dict, after: dict) -> list:
    changes = []
    keys = (set(before) | set(after)) - RUN_DIFF_IGNORED_KEYS
    for k in sorted(keys):
        b, a = before.get(k), after.get(k)
        if b != a:
            changes.append({"field": k, "before": b, "after": a})
    return changes


def _sample_field_changes(before_s: dict, after_s: dict) -> list:
    fields = []
    keys = (set(before_s) | set(after_s)) - SAMPLE_IGNORED_KEYS
    for k in sorted(keys):
        b, a = before_s.get(k), after_s.get(k)
        if b != a:
            fields.append({"name": k, "before": b, "after": a})
    return fields


def _snapshot_fields(sample: dict, *, present_key: str) -> list:
    """All tracked fields of a sample as before/after, for added/removed.

    present_key is 'after' for an added sample, 'before' for a removed one;
    the opposite side is None.
    """
    other = "before" if present_key == "after" else "after"
    fields = []
    for k in sorted(set(sample) - SAMPLE_IGNORED_KEYS):
        fields.append({"name": k, present_key: sample[k], other: None})
    return fields


def _sample_changes(before: dict, after: dict) -> list:
    before_by_id = {s["id"]: s for s in before.get("samples", [])}
    after_by_id = {s["id"]: s for s in after.get("samples", [])}
    changes = []
    # Removed (in before, not after) — sorted by id for determinism.
    for sid in sorted(set(before_by_id) - set(after_by_id)):
        s = before_by_id[sid]
        changes.append({"sample_id": s.get("sample_id"), "kind": "removed",
                        "fields": _snapshot_fields(s, present_key="before")})
    # Added (in after, not before).
    for sid in sorted(set(after_by_id) - set(before_by_id)):
        s = after_by_id[sid]
        changes.append({"sample_id": s.get("sample_id"), "kind": "added",
                        "fields": _snapshot_fields(s, present_key="after")})
    # Modified (in both, differing tracked fields).
    for sid in sorted(set(before_by_id) & set(after_by_id)):
        diff = _sample_field_changes(before_by_id[sid], after_by_id[sid])
        if diff:
            changes.append({"sample_id": after_by_id[sid].get("sample_id"),
                            "kind": "modified", "fields": diff})
    return changes


def diff_run(before: dict, after: dict) -> tuple:
    """Return (field_changes, sample_changes) between two run dicts."""
    return _config_changes(before, after), _sample_changes(before, after)


def is_empty(field_changes: list, sample_changes: list) -> bool:
    return not field_changes and not sample_changes
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pixi run test tests/unit/test_run_diff.py -v`
Expected: PASS (all classes).

- [ ] **Step 5: Commit**

```bash
git add src/seqsetup/services/run_diff.py tests/unit/test_run_diff.py
git commit -m "feat(history): add pure run diff engine

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: `RunHistoryRepository` (insert-only, indexed, pageable) + DI wiring

**Files:**
- Create: `src/seqsetup/repositories/run_history_repo.py`
- Modify: `src/seqsetup/context.py` (field), `src/seqsetup/startup.py` (registry + getter + wiring)
- Test: `tests/integration/test_run_history.py` (repo tests; needs Mongo)

- [ ] **Step 1: Write the failing tests**

Create `tests/integration/test_run_history.py`:

```python
"""Integration tests for run change history (repo, capture, route)."""

from datetime import datetime

import pytest

from seqsetup.models.run_history import RunHistoryEntry


def _origin() -> dict:
    return {"Origin": "http://testserver"}


def _entry(run_id, ts, kind="updated", **kw):
    return RunHistoryEntry(run_id=run_id, timestamp=ts, actor="alice", kind=kind, **kw)


class TestRunHistoryRepository:
    def test_append_and_list_newest_first(self, fresh_app):
        _app, ctx, _db = fresh_app
        repo = ctx.run_history_repo
        repo.append(_entry("r1", datetime(2026, 6, 11, 10, 0, 0)))
        repo.append(_entry("r1", datetime(2026, 6, 11, 11, 0, 0)))
        repo.append(_entry("r2", datetime(2026, 6, 11, 10, 30, 0)))
        got = repo.list_by_run("r1", limit=10)
        assert [e.timestamp.hour for e in got] == [11, 10]   # newest first
        assert all(e.run_id == "r1" for e in got)

    def test_append_duplicate_id_raises(self, fresh_app):
        _app, ctx, _db = fresh_app
        repo = ctx.run_history_repo
        e = _entry("r1", datetime(2026, 6, 11, 10, 0, 0))
        repo.append(e)
        with pytest.raises(Exception):
            repo.append(e)   # same _id -> DuplicateKeyError

    def test_repo_has_no_update_path(self, fresh_app):
        _app, ctx, _db = fresh_app
        # The append-only guarantee: no `save` upsert method is exposed.
        assert not hasattr(ctx.run_history_repo, "save")

    def test_list_is_bounded_and_pageable(self, fresh_app):
        _app, ctx, _db = fresh_app
        repo = ctx.run_history_repo
        for h in range(5):
            repo.append(_entry("r1", datetime(2026, 6, 11, 10, h, 0)))
        page1 = repo.list_by_run("r1", limit=2)
        assert len(page1) == 2 and page1[0].timestamp.minute == 4
        cur_ts, cur_id = page1[-1].cursor()
        page2 = repo.list_by_run("r1", limit=2, before_ts=cur_ts, before_id=cur_id)
        assert len(page2) == 2 and page2[0].timestamp.minute < page1[-1].timestamp.minute

    def test_delete_by_run(self, fresh_app):
        _app, ctx, _db = fresh_app
        repo = ctx.run_history_repo
        repo.append(_entry("r1", datetime(2026, 6, 11, 10, 0, 0)))
        repo.append(_entry("r1", datetime(2026, 6, 11, 11, 0, 0)))
        repo.append(_entry("r2", datetime(2026, 6, 11, 10, 0, 0)))
        assert repo.delete_by_run("r1") == 2
        assert repo.list_by_run("r1", limit=10) == []
        assert len(repo.list_by_run("r2", limit=10)) == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pixi run test tests/integration/test_run_history.py::TestRunHistoryRepository -v`
Expected: FAIL — `ctx.run_history_repo` is `None` / `RunHistoryRepository` missing.

- [ ] **Step 3: Write the repository**

Create `src/seqsetup/repositories/run_history_repo.py`:

```python
"""Insert-only repository for run change-history entries.

Application-level append-only: it exposes `append` (insert_one) and read/delete,
but NO update/upsert path — `RunHistoryEntry` documents are never rewritten
through the app. This is not cryptographic tamper-evidence (a DB admin can edit
the collection); that is out of scope.
"""

from typing import Optional

from pymongo.database import Database

from ..models.run_history import RunHistoryEntry


class RunHistoryRepository:
    """Manages the `run_history` collection. Insert-only by API surface."""

    COLLECTION = "run_history"

    def __init__(self, db: Database):
        self.collection = db[self.COLLECTION]
        # Index per-run keyset queries. idempotent.
        self.collection.create_index([("run_id", 1), ("timestamp", -1)])

    def append(self, entry: RunHistoryEntry) -> None:
        """Insert a new entry. Raises DuplicateKeyError on a colliding _id."""
        self.collection.insert_one(entry.to_dict())

    def list_by_run(
        self,
        run_id: str,
        *,
        limit: int,
        before_ts: Optional[str] = None,
        before_id: Optional[str] = None,
    ) -> list[RunHistoryEntry]:
        """Newest-first, bounded by `limit`. Keyset-paginate older with the
        (before_ts, before_id) cursor from a prior page's last entry."""
        flt: dict = {"run_id": run_id}
        if before_ts is not None and before_id is not None:
            flt["$or"] = [
                {"timestamp": {"$lt": before_ts}},
                {"timestamp": before_ts, "_id": {"$lt": before_id}},
            ]
        cur = (
            self.collection.find(flt)
            .sort([("timestamp", -1), ("_id", -1)])
            .limit(limit)
        )
        return [RunHistoryEntry.from_dict(doc) for doc in cur]

    def delete_by_run(self, run_id: str) -> int:
        """Delete all history for a run (cascade). Returns count deleted."""
        return self.collection.delete_many({"run_id": run_id}).deleted_count
```

- [ ] **Step 4: Wire DI**

In `src/seqsetup/context.py`, add the import and an optional field in the "Optional repositories" block:

```python
from .repositories.run_history_repo import RunHistoryRepository
```
```python
    run_history_repo: Optional[RunHistoryRepository] = None
```

In `src/seqsetup/startup.py`: import `RunHistoryRepository` near the other repo imports (use the submodule path style the file already uses), add to `_REPO_REGISTRY`:

```python
    "run_history": RunHistoryRepository,
```

add a getter beside the others:

```python
def get_run_history_repo() -> RunHistoryRepository:
    return _get_repo("run_history")
```

and add the kwarg in `get_app_context()`:

```python
        run_history_repo=get_run_history_repo(),
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pixi run test tests/integration/test_run_history.py::TestRunHistoryRepository -v`
Expected: PASS (5 tests).

- [ ] **Step 6: Commit**

```bash
git add src/seqsetup/repositories/run_history_repo.py src/seqsetup/context.py src/seqsetup/startup.py tests/integration/test_run_history.py
git commit -m "feat(history): add insert-only RunHistoryRepository and DI wiring

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Recording helpers + capture in `saving_run` (edits)

**Files:**
- Create: `src/seqsetup/services/run_history.py`
- Modify: `src/seqsetup/routes/dependencies.py` (`saving_run`)
- Test: `tests/integration/test_run_history.py` (add class)

- [ ] **Step 1: Write the failing tests**

Append to `tests/integration/test_run_history.py`:

```python
def _create_run(client) -> str:
    r = client.post("/runs/new", follow_redirects=False, headers=_origin())
    assert r.status_code == 303, r.text[:300]
    return r.headers["location"].split("run_id=", 1)[1].split("&", 1)[0]


class TestEditCapture:
    def test_edit_records_field_change(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        logged_in_client.post(f"/runs/{run_id}/name",
                              data={"run_name": "Renamed", "run_description": ""},
                              headers=_origin())
        entries = ctx.run_history_repo.list_by_run(run_id, limit=10)
        updated = [e for e in entries if e.kind == "updated"]
        assert updated, "an updated entry should be recorded"
        fields = {c["field"]: c for c in updated[0].field_changes}
        assert fields["run_name"]["after"] == "Renamed"
        assert updated[0].actor   # actor recorded
        run = ctx.run_repo.get_by_id(run_id)
        assert updated[0].timestamp == run.updated_at

    def test_noop_save_records_nothing(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        before = len([e for e in ctx.run_history_repo.list_by_run(run_id, limit=50)
                      if e.kind == "updated"])
        # Re-submit identical name -> no field change.
        run = ctx.run_repo.get_by_id(run_id)
        logged_in_client.post(f"/runs/{run_id}/name",
                              data={"run_name": run.run_name,
                                    "run_description": run.run_description},
                              headers=_origin())
        after = len([e for e in ctx.run_history_repo.list_by_run(run_id, limit=50)
                     if e.kind == "updated"])
        assert after == before

    def test_sample_add_records_added_entry(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        logged_in_client.post(f"/runs/{run_id}/samples",
                              data={"sample_id": "S1"}, headers=_origin())
        entries = ctx.run_history_repo.list_by_run(run_id, limit=50)
        sample_adds = [e for e in entries
                       for sc in e.sample_changes if sc["kind"] == "added"]
        assert sample_adds

    def test_no_phantom_entry_on_conflict(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        from seqsetup.repositories.base import ConflictError
        before = len(ctx.run_history_repo.list_by_run(run_id, limit=50))
        monkeypatch.setattr(ctx.run_repo, "save",
                            lambda run: (_ for _ in ()).throw(ConflictError("x")))
        # The mutation raises ConflictError on save -> no history entry.
        logged_in_client.post(f"/runs/{run_id}/name",
                              data={"run_name": "Z", "run_description": ""},
                              headers=_origin())
        after = len(ctx.run_history_repo.list_by_run(run_id, limit=50))
        assert after == before

    def test_history_write_failure_does_not_break_edit(
        self, logged_in_client, fresh_app, monkeypatch
    ):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        monkeypatch.setattr(ctx.run_history_repo, "append",
                            lambda entry: (_ for _ in ()).throw(RuntimeError("boom")))
        # The edit must still succeed (200), even though history append fails.
        r = logged_in_client.post(f"/runs/{run_id}/name",
                                  data={"run_name": "Persisted", "run_description": ""},
                                  headers=_origin())
        assert r.status_code == 200
        assert ctx.run_repo.get_by_id(run_id).run_name == "Persisted"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pixi run test tests/integration/test_run_history.py::TestEditCapture -v`
Expected: FAIL — no entries recorded (capture not wired).

- [ ] **Step 3: Write the recording helpers**

Create `src/seqsetup/services/run_history.py`:

```python
"""Recording helpers for per-run change history.

Invoked from saving_run (edits) and the creation sites. All callers wrap these
in their own try/except so a history failure never breaks a persisted clinical
edit (the deployment's standalone MongoDB has no transactions; the run save and
the history append are separate writes — best-effort by necessity).
"""

from ..models.run_history import RunHistoryEntry
from .run_diff import diff_run, is_empty


def record_run_updated(ctx, run, before: dict, actor: str) -> None:
    """Diff `before` (pre-mutation to_dict) against the run's current state and
    append an 'updated' entry if anything tracked changed. No-op if nothing
    changed or history isn't configured."""
    if ctx.run_history_repo is None:
        return
    field_changes, sample_changes = diff_run(before, run.to_dict())
    if is_empty(field_changes, sample_changes):
        return
    ctx.run_history_repo.append(RunHistoryEntry(
        run_id=run.id,
        timestamp=run.updated_at,
        actor=actor,
        kind="updated",
        field_changes=field_changes,
        sample_changes=sample_changes,
    ))


def record_run_created(ctx, run, actor: str, source: str, ref=None) -> None:
    """Append a 'created' anchor entry with provenance."""
    if ctx.run_history_repo is None:
        return
    ctx.run_history_repo.append(RunHistoryEntry(
        run_id=run.id,
        timestamp=run.created_at,
        actor=actor,
        kind="created",
        provenance={"source": source, "ref": ref},
    ))
```

- [ ] **Step 4: Wire capture into `saving_run`**

In `src/seqsetup/routes/dependencies.py`, add imports near the top:

```python
import logging

from ..services.audit_log import audit
from ..services.run_history import record_run_updated
```

Replace the `saving_run` context manager body with the snapshot + guarded record:

```python
@contextmanager
def saving_run(
    run: SequencingRun,
    ctx: AppContext,
    request: Request,
) -> Iterator[SequencingRun]:
    """Context manager: on successful exit, ``touch + save`` the run, then
    record a change-history entry for the diff.

    On exception, do NOT save and do NOT record — the exception propagates and
    the run stays untouched. The post-save history block is exception-guarded so
    a diff/append failure can never 500 a clinical edit that already persisted
    (history is best-effort; failures are logged + audited).
    """
    before = run.to_dict()
    try:
        yield run
    except BaseException:
        raise
    else:
        actor = get_username(request)
        run.touch(updated_by=actor)
        ctx.run_repo.save(run)
        try:
            record_run_updated(ctx, run, before, actor)
        except Exception:
            logging.getLogger(__name__).error(
                "Failed to record run history for %s", run.id, exc_info=True
            )
            audit("run.history.record_failed", actor=actor, target=run.id,
                  outcome="failure", reason="append_error")
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pixi run test tests/integration/test_run_history.py::TestEditCapture -v`
Expected: PASS (5 tests).

- [ ] **Step 6: Run the full suite to confirm no regression**

Run: `pixi run test -q`
Expected: PASS (the 27 `saving_run` call sites still behave; new tests pass).

- [ ] **Step 7: Commit**

```bash
git add src/seqsetup/services/run_history.py src/seqsetup/routes/dependencies.py tests/integration/test_run_history.py
git commit -m "feat(history): capture field-level diffs in saving_run

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Creation entries (blank / clone / template)

**Files:**
- Modify: `src/seqsetup/routes/wizard.py` (`wizard_new`)
- Modify: `src/seqsetup/routes/run_templates.py` (`duplicate_run`, `new_run_from_template`)
- Test: `tests/integration/test_run_history.py` (add class)

- [ ] **Step 1: Write the failing tests**

Append to `tests/integration/test_run_history.py`:

```python
import json


class TestCreationEntries:
    def test_blank_creation_records_created_entry(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        entries = ctx.run_history_repo.list_by_run(run_id, limit=10)
        created = [e for e in entries if e.kind == "created"]
        assert len(created) == 1
        assert created[0].provenance == {"source": "blank", "ref": None}

    def test_clone_records_created_with_source(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        src_id = _create_run(logged_in_client)
        r = logged_in_client.post(f"/runs/{src_id}/duplicate",
                                  data={"include_samples": "false"},
                                  headers=_origin(), follow_redirects=False)
        new_id = r.headers["location"].rsplit("/", 1)[1]
        created = [e for e in ctx.run_history_repo.list_by_run(new_id, limit=10)
                   if e.kind == "created"]
        assert created[0].provenance == {"source": "clone", "ref": src_id}

    def test_from_template_records_created_with_template_ref(
        self, logged_in_client, fresh_app
    ):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        logged_in_client.post(f"/runs/{run_id}/save-as-template",
                              data={"name": "T", "description": "",
                                    "scaffold_sample_ids": "[]"},
                              headers=_origin(), follow_redirects=False)
        tid = ctx.run_template_repo.list_all()[0].id
        r = logged_in_client.post(f"/runs/new/from-template/{tid}",
                                  headers=_origin(), follow_redirects=False)
        new_id = r.headers["location"].rsplit("/", 1)[1]
        created = [e for e in ctx.run_history_repo.list_by_run(new_id, limit=10)
                   if e.kind == "created"]
        assert created[0].provenance == {"source": "template", "ref": tid}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pixi run test tests/integration/test_run_history.py::TestCreationEntries -v`
Expected: FAIL — no `created` entries.

- [ ] **Step 3: Record creation in `wizard_new`**

In `src/seqsetup/routes/wizard.py`, add the import:

```python
from ..services.run_history import record_run_created
```

and update `wizard_new` to record after creation (guarded, so a history failure never breaks run creation):

```python
@router.post("/runs/new")
def wizard_new(
    request: Request,
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /runs/new — create the run row and redirect to step 1."""
    user = request.scope.get("auth")
    actor = user.username if user else ""
    run = ctx.run_repo.create_run(actor)
    try:
        record_run_created(ctx, run, actor, source="blank")
    except Exception:
        import logging
        logging.getLogger(__name__).error(
            "Failed to record creation history for %s", run.id, exc_info=True
        )
    return RedirectResponse(f"/runs/new/step/1?run_id={run.id}", status_code=303)
```

- [ ] **Step 4: Record creation in clone + from-template**

In `src/seqsetup/routes/run_templates.py`, add the import:

```python
from ..services.run_history import record_run_created
```

In `duplicate_run`, after `ctx.run_repo.save(new_run)` and before the existing `audit(...)`, add:

```python
    try:
        record_run_created(ctx, new_run, get_username(request),
                           source="clone", ref=run.id)
    except Exception:
        import logging
        logging.getLogger(__name__).error(
            "Failed to record clone history for %s", new_run.id, exc_info=True)
```

In `new_run_from_template`, after `ctx.run_repo.save(new_run)` and before the existing `audit(...)`, add:

```python
    try:
        record_run_created(ctx, new_run, get_username(request),
                           source="template", ref=template_id)
    except Exception:
        import logging
        logging.getLogger(__name__).error(
            "Failed to record from-template history for %s", new_run.id, exc_info=True)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pixi run test tests/integration/test_run_history.py::TestCreationEntries -v`
Expected: PASS (3 tests).

- [ ] **Step 6: Commit**

```bash
git add src/seqsetup/routes/wizard.py src/seqsetup/routes/run_templates.py tests/integration/test_run_history.py
git commit -m "feat(history): record created entries with provenance (blank/clone/template)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Cascade delete

**Files:**
- Modify: `src/seqsetup/routes/dashboard.py` (`delete_run`)
- Test: `tests/integration/test_run_history.py` (add class)

- [ ] **Step 1: Write the failing test**

Append to `tests/integration/test_run_history.py`:

```python
from seqsetup.models.sequencing_run import RunStatus


class TestCascadeDelete:
    def test_deleting_archived_run_removes_its_history(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        logged_in_client.post(f"/runs/{run_id}/name",
                              data={"run_name": "X", "run_description": ""},
                              headers=_origin())
        assert ctx.run_history_repo.list_by_run(run_id, limit=10)   # has history
        # Move to ARCHIVED, then delete.
        run = ctx.run_repo.get_by_id(run_id)
        run.status = RunStatus.ARCHIVED
        ctx.run_repo.save(run)
        r = logged_in_client.delete(f"/runs/{run_id}", headers=_origin())
        assert r.status_code == 200
        assert ctx.run_history_repo.list_by_run(run_id, limit=10) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pixi run test tests/integration/test_run_history.py::TestCascadeDelete -v`
Expected: FAIL — history remains after run delete.

- [ ] **Step 3: Add the cascade to `delete_run`**

In `src/seqsetup/routes/dashboard.py` `delete_run`, after `ctx.run_repo.delete(run.id)` and before/after the existing `audit("run.deleted", ...)`, add a guarded cascade:

```python
    ctx.run_repo.delete(run.id)
    try:
        ctx.run_history_repo.delete_by_run(run.id)
    except Exception:
        import logging
        logging.getLogger(__name__).error(
            "Failed to cascade-delete history for %s", run.id, exc_info=True)
    audit(
        "run.deleted",
        actor=get_username(request),
        target=run.id,
        previous_status=previous_status,
        run_name=run.run_name,
    )
```

(Leave the rest of `delete_run` unchanged.)

- [ ] **Step 4: Run test to verify it passes**

Run: `pixi run test tests/integration/test_run_history.py::TestCascadeDelete -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/seqsetup/routes/dashboard.py tests/integration/test_run_history.py
git commit -m "feat(history): cascade-delete run history on run deletion

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: History route + lazy-loaded panel + baseline marker

**Files:**
- Modify: `src/seqsetup/routes/runs.py` (new GET route)
- Create: `src/seqsetup/templates/runs/_history_list.html`
- Modify: `src/seqsetup/templates/runs/edit.html` (panel)
- Test: `tests/integration/test_run_history.py` (add class)

- [ ] **Step 1: Write the failing tests**

Append to `tests/integration/test_run_history.py`:

```python
class TestHistoryRouteAndPanel:
    def test_edit_page_shows_history_panel(self, logged_in_client, fresh_app):
        run_id = _create_run(logged_in_client)
        r = logged_in_client.get(f"/runs/{run_id}")
        assert r.status_code == 200
        assert f"/runs/{run_id}/history" in r.text

    def test_history_route_renders_entries(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        logged_in_client.post(f"/runs/{run_id}/name",
                              data={"run_name": "Visible", "run_description": ""},
                              headers=_origin())
        r = logged_in_client.get(f"/runs/{run_id}/history")
        assert r.status_code == 200
        assert "Visible" in r.text          # the new value appears
        assert "Created" in r.text          # the blank-creation entry

    def test_history_route_404_for_missing_run(self, logged_in_client):
        r = logged_in_client.get("/runs/nope/history")
        assert r.status_code == 404

    def test_history_route_works_for_archived_run(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        run = ctx.run_repo.get_by_id(run_id)
        run.status = RunStatus.ARCHIVED
        ctx.run_repo.save(run)
        r = logged_in_client.get(f"/runs/{run_id}/history")
        assert r.status_code == 200

    def test_baseline_marker_for_run_without_created_entry(
        self, logged_in_client, fresh_app
    ):
        _app, ctx, _db = fresh_app
        # Simulate a pre-feature run: history exists but no 'created' entry.
        from seqsetup.models.run_history import RunHistoryEntry
        run_id = _create_run(logged_in_client)
        ctx.run_history_repo.delete_by_run(run_id)   # drop the auto 'created'
        ctx.run_history_repo.append(RunHistoryEntry(
            run_id=run_id, timestamp=datetime(2026, 6, 11, 9, 0, 0),
            actor="alice", kind="updated",
            field_changes=[{"field": "run_name", "before": "A", "after": "B"}]))
        r = logged_in_client.get(f"/runs/{run_id}/history")
        assert r.status_code == 200
        assert "history began" in r.text.lower()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pixi run test tests/integration/test_run_history.py::TestHistoryRouteAndPanel -v`
Expected: FAIL — route 404 / panel string absent.

- [ ] **Step 3: Add the route to `routes/runs.py`**

In `src/seqsetup/routes/runs.py`, add the handler (near the other GET-ish handlers). It loads any run, paginates, and computes the baseline marker. `render` and `get_ctx` are already imported in this module; confirm and add any missing import.

```python
_HISTORY_PAGE = 50


@router.get("/runs/{run_id}/history", response_class=HTMLResponse)
def run_history(
    request: Request,
    run_id: str,
    before_ts: str = "",
    before_id: str = "",
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """GET /runs/{run_id}/history — read-only change-history panel (any status)."""
    run = ctx.run_repo.get_by_id(run_id)
    if run is None:
        return Response("Run not found", status_code=404)

    entries = ctx.run_history_repo.list_by_run(
        run_id,
        limit=_HISTORY_PAGE + 1,
        before_ts=before_ts or None,
        before_id=before_id or None,
    )
    has_more = len(entries) > _HISTORY_PAGE
    entries = entries[:_HISTORY_PAGE]

    next_ts = next_id = None
    if has_more and entries:
        next_ts, next_id = entries[-1].cursor()

    # Baseline marker: show once we've reached the oldest page and the oldest
    # entry isn't a 'created' (run predates the feature, or has no history yet).
    show_baseline = (not has_more) and (
        not entries or entries[-1].kind != "created"
    )

    return render(request, "runs/_history_list.html", {
        "run": run,
        "entries": entries,
        "next_ts": next_ts,
        "next_id": next_id,
        "show_baseline": show_baseline,
    })
```

If `AppContext` / `get_ctx` / `render` / `HTMLResponse` / `Response` aren't already imported in `routes/runs.py`, add them (the module already imports `render`, `HTMLResponse`, `Response`, `get_ctx`, `AppContext` per its existing handlers — verify and only add what's missing).

- [ ] **Step 4: Create the timeline partial**

Create `src/seqsetup/templates/runs/_history_list.html`. CSP-safe (no inline handlers; HTMX attributes only; Jinja autoescaping on). Renders newest-first; `created` entries show provenance; `updated` entries render field + sample changes; a "Load older" button when paginating; the baseline marker when `show_baseline`.

```html
<div class="text-sm">
  {% if not entries and show_baseline %}
    <p class="text-slate-500 italic">No change history recorded yet.</p>
  {% endif %}
  {% for e in entries %}
  <div class="border-t py-2">
    <div class="flex justify-between text-xs text-slate-500">
      <span>{{ e.timestamp.strftime("%Y-%m-%d %H:%M") }}</span>
      <span>{{ e.actor or "unknown" }}</span>
    </div>
    {% if e.kind == "created" %}
      <div class="font-medium">
        Created{% if e.provenance and e.provenance.source == "clone" %}
          (cloned from run {{ e.provenance.ref }}){% elif e.provenance and e.provenance.source == "template" %}
          (from template {{ e.provenance.ref }}){% endif %}
      </div>
    {% else %}
      <ul class="list-disc ml-5">
        {% for c in e.field_changes %}
          <li>{{ c.field }}: {{ c.before }} → {{ c.after }}</li>
        {% endfor %}
        {% for sc in e.sample_changes %}
          <li>
            Sample {{ sc.sample_id }}
            {% if sc.kind == "added" %}added{% elif sc.kind == "removed" %}removed{% else %}changed:
              {% for f in sc.fields %}{{ f.name }} {{ f.before }} → {{ f.after }}{% if not loop.last %}; {% endif %}{% endfor %}
            {% endif %}
          </li>
        {% endfor %}
      </ul>
    {% endif %}
  </div>
  {% endfor %}

  {% if next_ts and next_id %}
  <button class="mt-2 bg-slate-200 hover:bg-slate-300 rounded px-2 py-1 text-xs"
          hx-get="/runs/{{ run.id }}/history?before_ts={{ next_ts | urlencode }}&before_id={{ next_id | urlencode }}"
          hx-target="closest .run-history-panel"
          hx-swap="innerHTML">Load older</button>
  {% endif %}

  {% if show_baseline %}
  <p class="mt-3 text-xs text-slate-400 italic">
    Change history began when this feature was deployed; edits before that point were not recorded.
  </p>
  {% endif %}
</div>
```

- [ ] **Step 5: Add the panel to `edit.html`**

In `src/seqsetup/templates/runs/edit.html`, after the Samples `<fieldset>` (the `_sample_section.html` block), add a History fieldset whose body lazy-loads the partial. Use `hx-trigger="revealed"` so it fetches when scrolled into view (cheap initial render). Match the existing fieldset markup style:

```html
    <fieldset class="config-panel">
        <legend>Change history</legend>
        <div class="run-history-panel"
             hx-get="/runs/{{ run.id }}/history"
             hx-trigger="revealed"
             hx-swap="innerHTML">
            <p class="text-slate-400 text-sm">Loading history…</p>
        </div>
    </fieldset>
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `pixi run test tests/integration/test_run_history.py::TestHistoryRouteAndPanel -v`
Expected: PASS (5 tests).

- [ ] **Step 7: Run the CSP-compliance test + full suite**

Run: `pixi run test tests/unit/test_template_csp_compliance.py -q`
Expected: PASS (the new partial has no inline handlers).

Run: `pixi run test -q`
Expected: PASS — entire suite green.

- [ ] **Step 8: Commit**

```bash
git add src/seqsetup/routes/runs.py src/seqsetup/templates/runs/_history_list.html src/seqsetup/templates/runs/edit.html tests/integration/test_run_history.py
git commit -m "feat(history): add lazy-loaded history panel, route, and baseline marker

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-Review Notes (for the implementer)

- **Spec coverage:** model (T1); diff engine with denylist + structured values + snapshots (T2); insert-only indexed pageable repo + DI (T3); `saving_run` capture, guarded, after-save, with the recording service (T4); creation provenance at all 3 sites (T5); cascade delete (T6); route + lazy panel + baseline marker + pagination (T7). The durability story (best-effort, logged + `run.history.record_failed` audited) is realized by the guarded blocks in T4/T5/T6.
- **Type consistency:** `record_run_updated(ctx, run, before, actor)` and `record_run_created(ctx, run, actor, source, ref=None)` are called identically wherever they appear. `list_by_run(run_id, *, limit, before_ts=None, before_id=None)` and `RunHistoryEntry.cursor() -> (timestamp_iso, id)` are used consistently in repo, route, and tests. `append`/`delete_by_run` are the only write methods; there is no `save` on the history repo (asserted in T3).
- **Watch points:** confirm `routes/runs.py` already imports `render`, `HTMLResponse`, `Response`, `get_ctx`, `AppContext` (it does for its existing handlers) — add only what's missing. Confirm the `edit.html` Samples fieldset is the right anchor for the new panel. The `run.history.record_failed` audit event is new — no allow-list needs updating (audit names are free-form).
- **Deliberately out of scope (do not add):** admin cross-run viewer, rollback, retaining history after delete, UTC migration, per-cycle/per-analysis deep diffing.

---

## Execution Handoff

Choose execution approach (subagent-driven recommended).
