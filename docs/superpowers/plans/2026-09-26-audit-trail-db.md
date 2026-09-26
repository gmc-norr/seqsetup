# Permanent Audit Trail Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Store every `audit()` event permanently in MongoDB (`audit_events`), with web-address secrets removed, and show it to admins on a searchable `/admin/audit` page (security audit N-18, N-21).

**Architecture:** `services/audit_log.audit()` redacts address secrets, logs the JSON line as today, then appends an `AuditEvent` through a module-level sink (`set_audit_sink`, set in `app.py`) under `pymongo.timeout(2)`, never raising. `AuditEventRepository` is insert-only. The in-memory log viewer stops keeping `seqsetup.audit` records. A new admin route renders the trail with keyset pagination.

**Tech Stack:** Python 3.14, FastAPI, Jinja2 + jinja2-fragments, HTMX, pymongo 4.16 (mongomock 4.3 in tests), pytest.

**Spec:** `docs/superpowers/specs/2026-09-26-audit-trail-db-design.md`

> **Superseded in part.** After an independent review, the address cleaning, the target filter length and the log-line fallback were redesigned. The spec's "Review changes" section and the code are the source of truth where they differ from the tasks below.

## Global Constraints

- Worktree `/home/parlar_ai/dev/seqsetup/.worktrees/audit-trail`, branch `feat/audit-trail-db`, base `2694574`.
- Run everything from the worktree with `PY=/home/parlar_ai/dev/seqsetup/.pixi/envs/default/bin/python` and `PYTHONPATH=src`. Never `pixi run`/`pixi install` in the worktree.
- **No commits** until the user says "commit" (CLAUDE.md). Each task ends with its tests green instead.
- TDD: every test is run and seen failing for the stated reason before the code that makes it pass.
- `audit()` must never raise into its caller (existing contract).
- Audit write bound: `AUDIT_WRITE_TIMEOUT_S = 2.0`, via `pymongo.timeout`.
- Field caps (model and search boxes alike): event 128, actor 256, target 1024, outcome 32; details ≤ 64 KiB BSON.
- The app gets no code path that updates or deletes an audit event.
- Two tests written for N-07 earlier today change meaning on purpose (audit events move off `/admin/logs`): `tests/unit/test_audit_log_enabled.py::test_audit_event_reaches_the_log_viewer_handler` and `tests/integration/test_audit_trail_visible.py`. Every other existing test stays as it is.
- Baseline before Task 1: server suite `1596 passed`, browser suite `87 passed`.

## File Structure

| File | Responsibility |
|---|---|
| Create `src/seqsetup/models/audit_event.py` | `AuditEvent` record, size caps, `to_dict`/`from_dict`/`cursor` |
| Create `src/seqsetup/repositories/audit_event_repo.py` | insert-only `audit_events` access: `append`, `search` |
| Modify `src/seqsetup/startup.py`, `src/seqsetup/context.py` | register the repo; `get_audit_event_repo()`; `AppContext.audit_event_repo` |
| Modify `src/seqsetup/services/audit_log.py` | `redact_url_secrets`, `set_audit_sink`, bounded best-effort store |
| Modify `src/seqsetup/services/log_capture.py` | log-viewer buffer skips `seqsetup.audit` records |
| Modify `src/seqsetup/app.py` | set the sink before auth/scheduler start; include the new router |
| Create `src/seqsetup/routes/admin/audit.py` | `GET /admin/audit` |
| Create `src/seqsetup/templates/admin/audit.html` | the page |
| Modify `src/seqsetup/templates/_app_shell.html`, `src/seqsetup/templates/admin/logs.html`, `src/seqsetup/routes/admin/__init__.py` | nav link, pointer line, package index |
| Tests | `tests/unit/test_audit_event_model.py`, `tests/integration/test_audit_event_repo.py`, `tests/unit/test_audit_redaction.py`, `tests/unit/test_audit_sink.py`, `tests/unit/test_audit_log_enabled.py` (modify), `tests/integration/test_audit_trail_visible.py` (rewrite), `tests/integration/test_audit_trail_page.py` |

---

### Task 1: `AuditEvent` model

**Files:**
- Create: `src/seqsetup/models/audit_event.py`
- Test: `tests/unit/test_audit_event_model.py`

**Interfaces:**
- Produces: `AuditEvent(timestamp: datetime, event: str, actor: str = "", target: str = "", outcome: str = "success", details: dict = {}, id: str = uuid4)`; `.to_dict() -> dict`; `AuditEvent.from_dict(dict)`; `.cursor() -> tuple[str, str]`; module constants `FIELD_CAPS: dict[str, int]`, `MAX_DETAILS_BYTES = 65536`.

- [ ] **Step 1: Write the failing test**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src $PY -m pytest tests/unit/test_audit_event_model.py -q -p no:cacheprovider`
Expected: collection ERROR, `ModuleNotFoundError: No module named 'seqsetup.models.audit_event'`.

- [ ] **Step 3: Write the model**

```python
"""One audit-trail event: who did what, to what, when, and how it ended.

Built by ``services.audit_log.audit()`` for every audit call and kept by
``AuditEventRepository`` (insert-only). Web-address secrets are already
removed by ``audit()``; this model bounds sizes so one event can never grow
large, on construction and on every later assignment.
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime

import bson

from .run_history import _canonical_ts

# Longest stored value per text field. The /admin/audit search boxes use the
# same limits, so any stored value can be searched for.
FIELD_CAPS = {"event": 128, "actor": 256, "target": 1024, "outcome": 32}

# Details bigger than this (BSON-encoded) are replaced by a marker.
MAX_DETAILS_BYTES = 64 * 1024


def _bounded_details(value) -> dict:
    if not value:
        return {}
    if not isinstance(value, dict):
        return {"details_omitted": True, "reason": "not a dict"}
    try:
        size = len(bson.encode({"details": value}))
    except Exception:
        return {"details_omitted": True, "reason": "not storable"}
    if size > MAX_DETAILS_BYTES:
        return {"details_omitted": True, "bytes": size}
    return value


@dataclass
class AuditEvent:
    """One audit-trail record."""

    timestamp: datetime
    event: str
    actor: str = ""
    target: str = ""
    outcome: str = "success"
    details: dict = field(default_factory=dict)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def __setattr__(self, name, value):
        if name in FIELD_CAPS:
            value = ("" if value is None else str(value))[:FIELD_CAPS[name]]
        elif name == "details":
            value = _bounded_details(value)
        object.__setattr__(self, name, value)

    def cursor(self) -> tuple:
        """Keyset-pagination cursor: (canonical timestamp, id)."""
        return (_canonical_ts(self.timestamp), self.id)

    def to_dict(self) -> dict:
        return {
            "_id": self.id,
            "id": self.id,
            "timestamp": _canonical_ts(self.timestamp),
            "event": self.event,
            "actor": self.actor,
            "target": self.target,
            "outcome": self.outcome,
            "details": self.details,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AuditEvent":
        ts = data["timestamp"]
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts)
        return cls(
            id=data.get("_id") or data["id"],
            timestamp=ts,
            event=data.get("event", ""),
            actor=data.get("actor", ""),
            target=data.get("target", ""),
            outcome=data.get("outcome", ""),
            details=data.get("details") or {},
        )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `PYTHONPATH=src $PY -m pytest tests/unit/test_audit_event_model.py -q -p no:cacheprovider`
Expected: `10 passed`.

---

### Task 2: `AuditEventRepository` + registration

**Files:**
- Create: `src/seqsetup/repositories/audit_event_repo.py`
- Modify: `src/seqsetup/startup.py` (import, `_REPO_REGISTRY`, getter, `get_app_context`)
- Modify: `src/seqsetup/context.py` (import, field)
- Test: `tests/integration/test_audit_event_repo.py`

**Interfaces:**
- Consumes: `AuditEvent`, `AuditEvent.cursor()` (Task 1).
- Produces: `AuditEventRepository(db)`; `.append(event: AuditEvent) -> None`; `.search(*, limit: int, event_prefix: str | None = None, actor: str | None = None, target: str | None = None, from_ts: str | None = None, to_ts: str | None = None, before_ts: str | None = None, before_id: str | None = None) -> list[AuditEvent]` (newest first; `from_ts` inclusive, `to_ts` exclusive, canonical strings); `startup.get_audit_event_repo()`; `AppContext.audit_event_repo`.

- [ ] **Step 1: Write the failing test**

```python
"""AuditEventRepository: insert-only, newest first, filters, keyset pages."""

import re
from datetime import datetime, timedelta, timezone

import mongomock
import pytest

from seqsetup.models.audit_event import AuditEvent
from seqsetup.repositories.audit_event_repo import AuditEventRepository

T0 = datetime(2026, 9, 26, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def repo():
    return AuditEventRepository(mongomock.MongoClient()["t"])


def _add(repo, minutes, event="x.y", actor="alice", target="run-1"):
    e = AuditEvent(timestamp=T0 + timedelta(minutes=minutes), event=event,
                   actor=actor, target=target)
    repo.append(e)
    return e


class TestAuditEventRepositorySearch:
    """Newest first, with each filter on its own."""

    def test_newest_first(self, repo):
        for m in (1, 3, 2):
            _add(repo, m, target=f"t{m}")
        assert [e.target for e in repo.search(limit=10)] == ["t3", "t2", "t1"]

    def test_limit(self, repo):
        for m in range(5):
            _add(repo, m)
        assert len(repo.search(limit=2)) == 2

    def test_event_prefix_matches_the_start_only(self, repo):
        _add(repo, 1, event="login.success")
        _add(repo, 2, event="login.failure")
        _add(repo, 3, event="logout")
        _add(repo, 4, event="api.login.x")
        assert sorted(e.event for e in repo.search(limit=10, event_prefix="login")) == [
            "login.failure", "login.success"]

    def test_event_prefix_is_literal_text_not_a_pattern(self, repo):
        _add(repo, 1, event="aXb")
        _add(repo, 2, event="a.b")
        assert [e.event for e in repo.search(limit=10, event_prefix="a.")] == ["a.b"]

    def test_actor_matches_exactly(self, repo):
        _add(repo, 1, actor="alice")
        _add(repo, 2, actor="alice2")
        assert [e.actor for e in repo.search(limit=10, actor="alice")] == ["alice"]

    def test_target_matches_exactly_even_when_long(self, repo):
        long_target = "https://lims.example.com/" + "p" * 275  # 300 chars
        assert len(long_target) == 300
        _add(repo, 1, target=long_target)
        _add(repo, 2, target=long_target + "x")
        found = repo.search(limit=10, target=long_target)
        assert [e.target for e in found] == [long_target]

    def test_from_is_inclusive_and_to_is_exclusive(self, repo):
        for m in (0, 10, 20):
            _add(repo, m, target=f"t{m}")
        from_ts = (T0 + timedelta(minutes=10)).replace(tzinfo=None).isoformat()
        to_ts = (T0 + timedelta(minutes=20)).replace(tzinfo=None).isoformat()
        assert [e.target for e in repo.search(limit=10, from_ts=from_ts, to_ts=to_ts)] == ["t10"]


class TestAuditEventRepositoryPaging:
    """Keyset pages cover every event once, even with equal timestamps."""

    def test_pages_through_ties_without_gaps_or_repeats(self, repo):
        same = [AuditEvent(timestamp=T0, event="x", target=f"t{i}") for i in range(5)]
        for e in same:
            repo.append(e)
        seen, cursor = [], (None, None)
        while True:
            page = repo.search(limit=2, before_ts=cursor[0], before_id=cursor[1])
            if not page:
                break
            seen += [e.id for e in page]
            cursor = page[-1].cursor()
        assert sorted(seen) == sorted(e.id for e in same)
        assert len(seen) == 5

    def test_paging_keeps_the_filters(self, repo):
        for m in range(4):
            _add(repo, m, actor="alice" if m % 2 else "bob", target=f"t{m}")
        first = repo.search(limit=1, actor="alice")
        rest = repo.search(limit=10, actor="alice",
                           before_ts=first[0].cursor()[0], before_id=first[0].cursor()[1])
        assert [e.target for e in first + rest] == ["t3", "t1"]


class TestAuditEventRepositoryIsInsertOnly:
    """No method can change or remove an event."""

    def test_no_update_or_delete_methods(self):
        names = [n for n in dir(AuditEventRepository)
                 if re.match(r"(delete|update|replace|remove|drop|clear|upsert|save)", n)]
        assert names == []


class TestAuditEventRepositoryRegistration:
    """The app builds the repository and hands it out through AppContext."""

    def test_app_context_carries_the_repo(self, fresh_app):
        _app, ctx, _db = fresh_app
        assert isinstance(ctx.audit_event_repo, AuditEventRepository)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src $PY -m pytest tests/integration/test_audit_event_repo.py -q -p no:cacheprovider`
Expected: collection ERROR, `No module named 'seqsetup.repositories.audit_event_repo'`.

- [ ] **Step 3: Write the repository**

```python
"""Insert-only repository for the audit trail.

Exposes ``append`` and ``search`` only — no update, replace or delete — so no
code path in the app can change or remove an audit event. This is not
tamper-evidence against a database administrator; that is out of scope.
"""

import re
from typing import Optional

from pymongo.database import Database

from ..models.audit_event import AuditEvent


class AuditEventRepository:
    """Manages the ``audit_events`` collection. Insert-only by API surface."""

    COLLECTION = "audit_events"

    def __init__(self, db: Database):
        self.collection = db[self.COLLECTION]
        # Newest-first listing with the _id tiebreak, and one index per filter.
        self.collection.create_index([("timestamp", -1), ("_id", -1)])
        self.collection.create_index([("event", 1), ("timestamp", -1)])
        self.collection.create_index([("actor", 1), ("timestamp", -1)])
        self.collection.create_index([("target", 1), ("timestamp", -1)])

    def append(self, event: AuditEvent) -> None:
        """Insert one event."""
        self.collection.insert_one(event.to_dict())

    def search(
        self,
        *,
        limit: int,
        event_prefix: Optional[str] = None,
        actor: Optional[str] = None,
        target: Optional[str] = None,
        from_ts: Optional[str] = None,
        to_ts: Optional[str] = None,
        before_ts: Optional[str] = None,
        before_id: Optional[str] = None,
    ) -> list[AuditEvent]:
        """Newest first, at most ``limit``. ``event_prefix`` matches the start
        of the event name; ``actor`` and ``target`` match exactly;
        ``from_ts`` is inclusive and ``to_ts`` exclusive (canonical timestamp
        strings). Page older with the ``(before_ts, before_id)`` cursor of a
        prior page's last event."""
        clauses: list[dict] = []
        if event_prefix:
            clauses.append({"event": {"$regex": "^" + re.escape(event_prefix)}})
        if actor is not None:
            clauses.append({"actor": actor})
        if target is not None:
            clauses.append({"target": target})
        if from_ts is not None:
            clauses.append({"timestamp": {"$gte": from_ts}})
        if to_ts is not None:
            clauses.append({"timestamp": {"$lt": to_ts}})
        if before_ts is not None and before_id is not None:
            clauses.append({"$or": [
                {"timestamp": {"$lt": before_ts}},
                {"timestamp": before_ts, "_id": {"$lt": before_id}},
            ]})
        cur = (
            self.collection.find({"$and": clauses} if clauses else {})
            .sort([("timestamp", -1), ("_id", -1)])
            .limit(max(1, limit))
        )
        return [AuditEvent.from_dict(doc) for doc in cur]
```

- [ ] **Step 4: Register it**

`src/seqsetup/startup.py` — add the import after the `RunHistoryRepository` import:
```python
from .repositories.audit_event_repo import AuditEventRepository
```
add to `_REPO_REGISTRY` after `"run_history": RunHistoryRepository,`:
```python
    "audit_event": AuditEventRepository,
```
add after `get_run_history_repo`:
```python
def get_audit_event_repo() -> AuditEventRepository:
    return _get_repo("audit_event")
```
and in `get_app_context()` after `run_history_repo=get_run_history_repo(),`:
```python
        audit_event_repo=get_audit_event_repo(),
```

`src/seqsetup/context.py` — import after the `RunHistoryRepository` import:
```python
from .repositories.audit_event_repo import AuditEventRepository
```
field after `run_history_repo: Optional[RunHistoryRepository] = None`:
```python
    audit_event_repo: Optional[AuditEventRepository] = None
```

- [ ] **Step 5: Run test to verify it passes**

Run: `PYTHONPATH=src $PY -m pytest tests/integration/test_audit_event_repo.py -q -p no:cacheprovider`
Expected: `11 passed`.

---

### Task 3: Remove web-address secrets from audit events

**Files:**
- Modify: `src/seqsetup/services/audit_log.py`
- Test: `tests/unit/test_audit_redaction.py`

**Interfaces:**
- Produces: `redact_url_secrets(text: str) -> str`; `audit()` applies it to `target` and to every string inside `details` before logging (Task 4 adds storing).

- [ ] **Step 1: Write the failing test**

```python
"""Web-address secrets never reach the audit line (N-21)."""

import json
import logging

import pytest

from seqsetup.services.audit_log import audit, redact_url_secrets

REMOVED = "[address removed]"


@pytest.mark.parametrize("text,expected", [
    # scheme-relative: reaches lims.url_blocked today (measured)
    ("//svc:PASSWORD@lims.invalid/api?api_token=TOKEN", "//lims.invalid/api"),
    ("svc:PASSWORD@lims.invalid/api?api_token=TOKEN", "lims.invalid/api"),
    ("https://svc:PASSWORD@lims.invalid/api?api_token=TOKEN", "https://lims.invalid/api"),
    ("ghp_TOKEN@github.com/org/repo", "github.com/org/repo"),
    ("lims.example.com/api?api_token=TOKEN", "lims.example.com/api"),
    ("https://lims.example.com:8443/api#access_token=TOKEN", "https://lims.example.com:8443/api"),
    ("ldaps://cn=bind,dc=x:SECRET@ldap.example.com:636", "ldaps://ldap.example.com:636"),
    ("https://[::1]:8443/api?k=TOKEN", "https://[::1]:8443/api"),
    # fail closed
    ("http://[::1/api?api_token=TOKEN", REMOVED),
    ("https://svc:p@ss/w@host/api", REMOVED),
    ("https://svc:PASSWORD@", REMOVED),
    ("https://svc:PA SS@lims.invalid/api?api_token=TOKEN", f"{REMOVED} lims.invalid/api"),
    # left alone
    ("https://github.com/org/repo.git", "https://github.com/org/repo.git"),
    ("github.com/org/repo", "github.com/org/repo"),
    ("alice@example.com", "alice@example.com"),
    ("why? because.", "why? because."),
    ("run-2026-09-26_A", "run-2026-09-26_A"),
    ("Refusing to call LIMS at 'lims.internal' (127.0.0.1): address is loopback",
     "Refusing to call LIMS at 'lims.internal' (127.0.0.1): address is loopback"),
    ("", ""),
])
def test_redact_url_secrets(text, expected):
    assert redact_url_secrets(text) == expected


def test_quotes_around_an_address_are_kept():
    assert redact_url_secrets("at 'https://u:PASSWORD@h/x?t=TOKEN'.") == "at 'https://h/x'."


SECRET_TARGETS = [
    "//svc:PASSWORD@lims.invalid/api?api_token=TOKEN",
    "svc:PASSWORD@lims.invalid/api?api_token=TOKEN",
    "https://svc:PASSWORD@lims.invalid/api?api_token=TOKEN",
    "ghp_TOKEN@github.com/org/repo",
    "ldaps://cn=bind:PASSWORD@ldap.example.com:636",
]


class TestAuditLineHasNoAddressSecrets:
    """audit() cleans the target and every string in details."""

    @pytest.fixture
    def lines(self, caplog):
        caplog.set_level(logging.INFO, logger="seqsetup.audit")
        return lambda: [r.message for r in caplog.records if r.name == "seqsetup.audit"]

    @pytest.mark.parametrize("target", SECRET_TARGETS)
    def test_target(self, lines, target):
        audit("lims.url_blocked", actor="lims_client", target=target, reason="blocked")
        line = lines()[-1]
        assert "PASSWORD" not in line and "TOKEN" not in line

    def test_nested_details(self, lines):
        audit("config_sync.updated", actor="admin", target="config",
              repo_url=SECRET_TARGETS[2],
              nested={"urls": [SECRET_TARGETS[0], {"u": SECRET_TARGETS[3]}]})
        payload = json.loads(lines()[-1])
        assert payload["details"]["repo_url"] == "https://lims.invalid/api"
        assert payload["details"]["nested"]["urls"][0] == "//lims.invalid/api"
        assert payload["details"]["nested"]["urls"][1]["u"] == "github.com/org/repo"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src $PY -m pytest tests/unit/test_audit_redaction.py -q -p no:cacheprovider`
Expected: collection ERROR, `ImportError: cannot import name 'redact_url_secrets'`.

- [ ] **Step 3: Implement** — full new `src/seqsetup/services/audit_log.py` for this task (Task 4 extends it):

```python
"""Audit logging for security-sensitive operations.

Writes structured JSON lines through a dedicated ``seqsetup.audit`` logger
so an operator can route them separately from application logs (file
handler, SIEM forwarder, etc).

Callers MUST NOT pass secrets (passwords, hashes, plaintext API tokens,
LDAP bind passwords). As a backstop, every web address in ``target`` and in
string ``details`` loses its user/password part, query string and fragment
before the event is written (``redact_url_secrets``, security audit N-21).
Nothing else is scrubbed — keep the contract at the call site.

Event naming convention: ``"<area>.<verb>"`` — e.g., ``"login.success"``,
``"login.failure"``, ``"run.status.changed"``, ``"validation.approved"``.
"""

import json
import logging
import re
import time
from typing import Any
from urllib.parse import urlsplit


_audit_logger = logging.getLogger("seqsetup.audit")
# audit() writes at INFO. Without its own level this logger inherits the root
# default, WARNING, and every audit event is dropped before any handler sees
# it. Set here, where the logger is made, so no entry point can forget it.
_audit_logger.setLevel(logging.INFO)

# Quote, bracket and sentence characters that may surround an address in text.
_EDGE_CHARS = "'\"()<>[]{},;.!"
_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
_ADDRESS_REMOVED = "[address removed]"


def redact_url_secrets(text: str) -> str:
    """Remove the user/password part, query string and fragment from every
    web address in ``text``; keep scheme, host, port and path.

    A whitespace-separated piece counts as an address when it contains
    ``://``, starts with ``//``, has an ``@`` with a ``:`` before it or a
    ``/`` after it, or has a ``?`` or ``#`` after a ``/``. E-mail addresses
    and ordinary text match none of these and are returned unchanged. An
    address that cannot be parsed cleanly becomes ``[address removed]``.
    """
    out = []
    for piece in re.split(r"(\s+)", text):
        core = piece.strip(_EDGE_CHARS)
        if not core or not _looks_like_address(core):
            out.append(piece)
            continue
        start = piece.find(core)
        out.append(piece[:start] + _clean_address(core) + piece[start + len(core):])
    return "".join(out)


def _looks_like_address(token: str) -> bool:
    if "://" in token or token.startswith("//"):
        return True
    at = token.find("@")
    if at != -1 and (":" in token[:at] or "/" in token[at:]):
        return True
    slash = token.find("/")
    return slash != -1 and ("?" in token[slash:] or "#" in token[slash:])


def _clean_address(token: str) -> str:
    has_scheme = _SCHEME_RE.match(token) is not None
    relative = token.startswith("//")
    try:
        # Without a scheme or "//", urlsplit would read the host as a path.
        parts = urlsplit(token if has_scheme or relative else "//" + token)
        host = parts.hostname
        port = parts.port
    except ValueError:
        return _ADDRESS_REMOVED
    if not host:
        return _ADDRESS_REMOVED
    if ":" in host:
        host = f"[{host}]"
    prefix = f"{parts.scheme}://" if has_scheme else ("//" if relative else "")
    cleaned = prefix + host + (f":{port}" if port is not None else "") + parts.path
    # Anything odd left over (an unencoded '@' or '/' in a password, a space)
    # means the parse cannot be trusted: drop the whole address.
    if any(c in cleaned for c in "@?#") or any(c.isspace() for c in cleaned):
        return _ADDRESS_REMOVED
    return cleaned


def _redact(value):
    """``redact_url_secrets`` on every string in ``value``, walking dicts
    and lists. Keys and non-text values are left as they are."""
    if isinstance(value, str):
        return redact_url_secrets(value)
    if isinstance(value, dict):
        return {k: _redact(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(v) for v in value]
    return value


def audit(
    event: str,
    actor: str = "",
    target: str = "",
    outcome: str = "success",
    **details: Any,
) -> None:
    """Emit a single audit event.

    Args:
        event: short dotted event name (e.g. "run.status.changed")
        actor: identity that performed the action (username, "api-token:<id>", or "" for unauthenticated)
        target: identifier of the affected object (run_id, user_id, etc.)
        outcome: "success", "failure", or "denied"
        **details: small dict of non-sensitive contextual fields

    Web addresses in ``target`` and ``details`` are cleaned first (see
    ``redact_url_secrets``).

    Best-effort: a json serialization failure (e.g. caller passed bytes or
    a non-isoformat datetime) logs a warning to the application logger and
    returns. It must NEVER raise into the caller — a request handler must
    not 500 because of an audit-log call.
    """
    record: dict[str, Any] = {
        "ts": int(time.time()),
        "event": event,
        "actor": actor,
        "target": _redact(target),
        "outcome": outcome,
    }
    if details:
        record["details"] = _redact(details)
    try:
        _audit_logger.info(json.dumps(record, sort_keys=True, default=_json_fallback))
    except Exception:
        # Fall back to a minimal record and log the serialization failure.
        # This keeps the audit trail informative (event/actor/target survive)
        # without killing the request that triggered the audit.
        logging.getLogger(__name__).warning(
            "audit() serialization failed for event=%r — emitting minimal record",
            event,
            exc_info=True,
        )
        try:
            _audit_logger.info(json.dumps({
                "ts": record["ts"],
                "event": event,
                "actor": actor,
                "target": record["target"],
                "outcome": outcome,
                "details_serialization_failed": True,
            }, sort_keys=True))
        except Exception:
            # Absolutely last resort — never raise.
            pass


def _json_fallback(obj):
    """Last-chance JSON encoder hook.

    Handles datetime/date/bytes/set, then falls back to ``str()``. Anything
    that can't be stringified falls into the outer try/except in ``audit``.
    """
    from datetime import date, datetime
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, (bytes, bytearray)):
        return obj.decode("utf-8", errors="replace")
    if isinstance(obj, (set, frozenset)):
        return sorted(obj)
    return str(obj)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `PYTHONPATH=src $PY -m pytest tests/unit/test_audit_redaction.py tests/unit/test_audit_log.py tests/unit/test_audit_log_enabled.py -q -p no:cacheprovider`
Expected: `33 passed` (26 new + 4 in test_audit_log.py + 3 in test_audit_log_enabled.py, which Task 5 changes).

---

### Task 4: Store each event through a bounded, best-effort sink

**Files:**
- Modify: `src/seqsetup/services/audit_log.py`
- Modify: `src/seqsetup/app.py`
- Test: `tests/unit/test_audit_sink.py`

**Interfaces:**
- Consumes: `AuditEvent` (Task 1), `get_audit_event_repo()` (Task 2), `redact_url_secrets` (Task 3).
- Produces: `set_audit_sink(sink) -> None` (sink has `append(AuditEvent)`), `AUDIT_WRITE_TIMEOUT_S = 2.0`, module global `_audit_sink`.

- [ ] **Step 1: Write the failing test**

```python
"""audit() stores each event through the sink: same fields as the log line,
bounded in time, never raising."""

import json
import logging
import time

import pymongo
import pytest

from seqsetup.services import audit_log
from seqsetup.services.audit_log import audit


class _ListSink:
    def __init__(self):
        self.events = []

    def append(self, event):
        self.events.append(event)


class _BrokenSink:
    def append(self, event):
        raise RuntimeError("database down")


class _DeadServerSink:
    """Writes to a MongoDB address where nothing listens; the client's own
    timeouts are 30 s, like the app's socketTimeoutMS."""

    def __init__(self):
        client = pymongo.MongoClient(
            "mongodb://127.0.0.1:1/", serverSelectionTimeoutMS=30000,
            connectTimeoutMS=30000, socketTimeoutMS=30000,
        )
        self.client = client
        self.coll = client["t"]["audit_events"]

    def append(self, event):
        self.coll.insert_one(event.to_dict())


@pytest.fixture
def sink(monkeypatch):
    s = _ListSink()
    monkeypatch.setattr(audit_log, "_audit_sink", s)
    return s


class TestAuditSink:
    """The stored event matches the logged line."""

    def test_event_is_stored_with_the_logged_fields(self, sink, caplog):
        caplog.set_level(logging.INFO, logger="seqsetup.audit")
        audit("run.status.changed", actor="alice", target="run-1",
              outcome="success", to_status="ready")
        line = json.loads(
            [r.message for r in caplog.records if r.name == "seqsetup.audit"][-1])
        (stored,) = sink.events
        assert stored.event == line["event"] == "run.status.changed"
        assert stored.actor == line["actor"] == "alice"
        assert stored.target == line["target"] == "run-1"
        assert stored.outcome == line["outcome"] == "success"
        assert stored.details == line["details"] == {"to_status": "ready"}

    def test_stored_event_has_no_address_secrets(self, sink):
        audit("lims.url_blocked", actor="lims_client",
              target="//svc:PASSWORD@lims.invalid/api?api_token=TOKEN",
              reason="see svc:PASSWORD@lims.invalid/api?api_token=TOKEN")
        stored = json.dumps(sink.events[0].to_dict())
        assert "PASSWORD" not in stored and "TOKEN" not in stored
        assert sink.events[0].target == "//lims.invalid/api"

    def test_unserializable_details_are_marked(self, sink):
        class Weird:
            def __str__(self):
                raise RuntimeError("no")
        audit("x.y", actor="a", target="t", bad=Weird())
        assert sink.events[0].details == {"details_serialization_failed": True}
        assert sink.events[0].event == "x.y"

    def test_no_sink_is_fine(self, monkeypatch):
        monkeypatch.setattr(audit_log, "_audit_sink", None)
        audit("x.y", actor="a")

    def test_set_audit_sink_sets_and_clears(self, monkeypatch):
        monkeypatch.setattr(audit_log, "_audit_sink", None)
        s = _ListSink()
        audit_log.set_audit_sink(s)
        audit("x.y")
        audit_log.set_audit_sink(None)
        audit("x.z")
        assert [e.event for e in s.events] == ["x.y"]


class TestAuditSinkFailure:
    """A failed write never reaches the caller, and is not silent."""

    def test_failing_sink_does_not_raise_and_logs_an_error(self, monkeypatch, caplog):
        monkeypatch.setattr(audit_log, "_audit_sink", _BrokenSink())
        caplog.set_level(logging.ERROR, logger="seqsetup.services.audit_log")
        audit("login.success", actor="alice")
        errors = [r for r in caplog.records
                  if r.name == "seqsetup.services.audit_log" and r.levelno == logging.ERROR]
        assert len(errors) == 1
        assert "login.success" in errors[0].getMessage()

    def test_write_to_a_dead_server_is_bounded(self, monkeypatch, caplog):
        assert audit_log.AUDIT_WRITE_TIMEOUT_S == 2.0
        dead = _DeadServerSink()
        monkeypatch.setattr(audit_log, "_audit_sink", dead)
        caplog.set_level(logging.ERROR, logger="seqsetup.services.audit_log")
        start = time.monotonic()
        try:
            audit("login.success", actor="alice")
        finally:
            elapsed = time.monotonic() - start
            dead.client.close()
        assert elapsed < 5, f"audit() waited {elapsed:.1f}s"
        assert any(r.levelno == logging.ERROR for r in caplog.records
                   if r.name == "seqsetup.services.audit_log")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src $PY -m pytest tests/unit/test_audit_sink.py -q -p no:cacheprovider`
Expected: FAIL — `AttributeError: <module 'seqsetup.services.audit_log'> has no attribute '_audit_sink'` (monkeypatch raising on a missing attribute), and `AUDIT_WRITE_TIMEOUT_S` / `set_audit_sink` missing.

- [ ] **Step 3: Implement** — in `src/seqsetup/services/audit_log.py`:

Module docstring: after the first paragraph add
```
Once ``set_audit_sink`` is called at startup, every event is also stored
permanently (``audit_events``, shown on /admin/audit): best effort, at most
``AUDIT_WRITE_TIMEOUT_S`` per write, never raising.
```

Imports become:
```python
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

import pymongo

from ..models.audit_event import AuditEvent
```
(`import time` goes: the timestamp now comes from one `datetime.now`.)

After `_audit_logger.setLevel(logging.INFO)` add:
```python
# The longest one audit() call waits for the database. Past it the event
# counts as not saved (an ERROR is logged) and the request goes on.
AUDIT_WRITE_TIMEOUT_S = 2.0

# Where audit() also stores each event (an AuditEventRepository). Set at
# startup by set_audit_sink; None means events are only logged.
_audit_sink = None


def set_audit_sink(sink) -> None:
    """Store every later audit event through ``sink`` (anything with an
    ``append(AuditEvent)`` method); None stops storing."""
    global _audit_sink
    _audit_sink = sink
```

Replace the body of `audit()` (docstring gains: "The event is then stored through the sink set by ``set_audit_sink``, if any — see ``_store``."):
```python
    now = datetime.now(timezone.utc)
    record: dict[str, Any] = {
        "ts": int(now.timestamp()),
        "event": event,
        "actor": actor,
        "target": _redact(target),
        "outcome": outcome,
    }
    if details:
        record["details"] = _redact(details)
    try:
        line = json.dumps(record, sort_keys=True, default=_json_fallback)
    except Exception:
        # Fall back to a minimal record and log the serialization failure.
        # This keeps the audit trail informative (event/actor/target survive)
        # without killing the request that triggered the audit.
        logging.getLogger(__name__).warning(
            "audit() serialization failed for event=%r — emitting minimal record",
            event,
            exc_info=True,
        )
        try:
            line = json.dumps({
                "ts": record["ts"],
                "event": event,
                "actor": actor,
                "target": record["target"],
                "outcome": outcome,
                "details_serialization_failed": True,
            }, sort_keys=True)
        except Exception:
            # Absolutely last resort — never raise.
            return
    try:
        _audit_logger.info(line)
    except Exception:
        pass
    _store(json.loads(line), now)


def _store(record: dict, when: datetime) -> None:
    """Save one event through the sink. Written before audit() returns, so
    a response the user sees means the event is stored; bounded by
    AUDIT_WRITE_TIMEOUT_S. Never raises: a failure is logged as an ERROR on
    the application logger (visible on /admin/logs)."""
    sink = _audit_sink
    if sink is None:
        return
    try:
        details = record.get("details") or {}
        if record.get("details_serialization_failed"):
            details = {"details_serialization_failed": True}
        entry = AuditEvent(
            timestamp=when,
            event=record.get("event", ""),
            actor=record.get("actor", ""),
            target=record.get("target", ""),
            outcome=record.get("outcome", ""),
            details=details,
        )
        with pymongo.timeout(AUDIT_WRITE_TIMEOUT_S):
            sink.append(entry)
    except Exception:
        logging.getLogger(__name__).error(
            "Audit event %r could not be saved to the audit trail",
            record.get("event"),
            exc_info=True,
        )
```

- [ ] **Step 4: Wire it in `src/seqsetup/app.py`**

Add `from .services.audit_log import set_audit_sink` after the `setup_log_capture` import; add `get_audit_event_repo,` to the `from .startup import (` list (alphabetical, before `get_instrument_definition_repo`); then:
```python
set_instrument_definition_repo(get_instrument_definition_repo())  # Enable synced instruments
set_audit_sink(get_audit_event_repo())  # Keep every audit event; before the scheduler starts
auth_service = init_auth_service()
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `PYTHONPATH=src $PY -m pytest tests/unit/test_audit_sink.py tests/unit/test_audit_redaction.py tests/unit/test_audit_log.py -q -p no:cacheprovider`
Expected: all pass; the dead-server test takes about 2 s.

---

### Task 5: The log viewer stops keeping audit events

**Files:**
- Modify: `src/seqsetup/services/log_capture.py` (`get_log_capture_handler`)
- Modify: `tests/unit/test_audit_log_enabled.py` (test 2 changes meaning, on purpose)

**Interfaces:**
- Produces: `log_capture._not_audit_record(record) -> bool`, attached as a filter to the global capture handler.

- [ ] **Step 1: Change the test** — replace `test_audit_event_reaches_the_log_viewer_handler` with:

```python
    def test_audit_event_is_logged_but_not_kept_in_the_log_viewer(self):
        """The event is emitted on the audit logger (operators can route it),
        but the /admin/logs buffer skips it: audit events live on the Audit
        trail page, where Clear logs and the 2000-entry cap cannot reach."""
        out = _run_clean(
            "import logging\n"
            "from seqsetup.services.audit_log import audit\n"
            "from seqsetup.services.log_capture import setup_log_capture\n"
            "viewer = setup_log_capture(['seqsetup'])\n"
            "seen = []\n"
            "class H(logging.Handler):\n"
            "    def emit(self, record): seen.append(record.getMessage())\n"
            "logging.getLogger('seqsetup.audit').addHandler(H())\n"
            "audit('login.success', actor='alice')\n"
            "logging.getLogger('seqsetup.services.x').warning('app warning')\n"
            "kept = [e.message for e in viewer.get_entries()]\n"
            "print(sum('login.success' in m for m in seen), "
            "sum('login.success' in m for m in kept), "
            "sum('app warning' in m for m in kept))\n"
        )

        assert out == "1 0 1"
```

- [ ] **Step 2: Run it to verify it fails**

Run: `PYTHONPATH=src $PY -m pytest tests/unit/test_audit_log_enabled.py -q -p no:cacheprovider`
Expected: FAIL `assert '1 1 1' == '1 0 1'`.

- [ ] **Step 3: Implement** — in `src/seqsetup/services/log_capture.py`, above `get_log_capture_handler`:
```python
def _not_audit_record(record: logging.LogRecord) -> bool:
    """Audit events are kept on the Audit trail page (/admin/audit), not in
    this clearable, 2000-entry buffer."""
    return record.name != "seqsetup.audit" and not record.name.startswith("seqsetup.audit.")
```
and in `get_log_capture_handler`, after `setFormatter(...)`:
```python
        _log_capture_handler.addFilter(_not_audit_record)
```

- [ ] **Step 4: Run to verify it passes**

Run: `PYTHONPATH=src $PY -m pytest tests/unit/test_audit_log_enabled.py tests/unit/test_log_capture_scrub.py -q -p no:cacheprovider`
Expected: all pass.

---

### Task 6: The Audit trail page

**Files:**
- Create: `src/seqsetup/routes/admin/audit.py`
- Create: `src/seqsetup/templates/admin/audit.html`
- Modify: `src/seqsetup/app.py` (import `audit as admin_audit` in the `from .routes.admin import (` block; `app.include_router(admin_audit.router)` after `admin_logs.router`)
- Modify: `src/seqsetup/templates/_app_shell.html` (nav link after Logs), `src/seqsetup/templates/admin/logs.html` (pointer line), `src/seqsetup/routes/admin/__init__.py` (list `admin/audit.py`)
- Test: `tests/integration/test_audit_trail_page.py`

**Interfaces:**
- Consumes: `ctx.audit_event_repo.search(...)` (Task 2), `FIELD_CAPS` (Task 1).
- Produces: `GET /admin/audit?event=&actor=&target=&date_from=&date_to=&before_ts=&before_id=`; HTMX block `audit_page`; wrapper `id="audit-page"`.

- [ ] **Step 1: Write the failing test**

```python
"""GET /admin/audit: admin-only, newest first, filters, pages."""

import html
import re
from datetime import datetime, timedelta, timezone

from seqsetup.models.audit_event import AuditEvent

T0 = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)


def _seed(ctx, n, **kw):
    for i in range(n):
        ctx.audit_event_repo.append(AuditEvent(
            timestamp=T0 + timedelta(minutes=i),
            event=kw.get("event", "seed.event"),
            actor=kw.get("actor", "seeder"),
            target=f"{kw.get('prefix', 'tgt')}-{i:03d}",
        ))


def _older_url(page: str) -> str:
    m = re.search(r'href="(/admin/audit\?[^"]*before_ts=[^"]+)"', page)
    return html.unescape(m.group(1)) if m else ""


class TestAuditPageAccess:
    """Only admins see the trail."""

    def test_renders_for_admin(self, logged_in_client):
        r = logged_in_client.get("/admin/audit")
        assert r.status_code == 200
        assert 'id="audit-page"' in r.text
        assert "Audit trail" in r.text

    def test_htmx_gets_the_fragment(self, logged_in_client):
        r = logged_in_client.get("/admin/audit", headers={"HX-Request": "true"})
        assert r.status_code == 200
        assert "<html" not in r.text
        assert 'id="audit-page"' in r.text

    def test_standard_user_is_refused(self, logged_in_standard_client):
        assert logged_in_standard_client.get("/admin/audit").status_code == 403

    def test_anonymous_is_sent_to_login(self, client):
        r = client.get("/admin/audit", follow_redirects=False)
        assert r.status_code in (302, 303)
        assert "/login" in r.headers["location"]

    def test_admin_nav_links_to_it(self, logged_in_client):
        assert 'href="/admin/audit"' in logged_in_client.get("/admin/logs").text


class TestAuditPageFilters:
    """Each filter narrows the list; the search boxes allow the field's full length."""

    def test_event_prefix(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _seed(ctx, 2, event="kit.uploaded", prefix="kit")
        _seed(ctx, 2, event="run.deleted", prefix="run")
        page = logged_in_client.get("/admin/audit", params={"event": "kit"}).text
        assert "kit-000" in page and "run-000" not in page

    def test_actor(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _seed(ctx, 1, actor="carol", prefix="carols")
        _seed(ctx, 1, actor="dave", prefix="daves")
        page = logged_in_client.get("/admin/audit", params={"actor": "carol"}).text
        assert "carols-000" in page and "daves-000" not in page

    def test_long_target_is_found_by_exact_search(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        long_target = "https://lims.example.com/" + "p" * 275
        assert len(long_target) == 300
        ctx.audit_event_repo.append(AuditEvent(timestamp=T0, event="seed.long", target=long_target))
        page = logged_in_client.get("/admin/audit", params={"target": long_target}).text
        assert "seed.long" in page

    def test_date_range_is_inclusive(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        for day in (19, 20, 21):
            ctx.audit_event_repo.append(AuditEvent(
                timestamp=datetime(2026, 9, day, 23, 59, tzinfo=timezone.utc),
                event="seed.day", target=f"day-{day}"))
        page = logged_in_client.get(
            "/admin/audit", params={"date_from": "2026-09-20", "date_to": "2026-09-20"}).text
        assert "day-20" in page and "day-19" not in page and "day-21" not in page

    def test_bad_date_shows_a_message(self, logged_in_client):
        r = logged_in_client.get("/admin/audit", params={"date_from": "26/09/2026"})
        assert r.status_code == 200
        assert "Dates must be written like 2026-09-26." in r.text

    def test_no_match_says_so(self, logged_in_client):
        page = logged_in_client.get("/admin/audit", params={"actor": "nobody-at-all"}).text
        assert "No audit events match." in page


class TestAuditPagePaging:
    """100 per page, newest first; Older walks back without gaps."""

    def test_older_link_pages_back(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _seed(ctx, 105, actor="pager", prefix="pg")
        first = logged_in_client.get("/admin/audit", params={"actor": "pager"}).text
        assert "pg-104" in first and "pg-005" in first and "pg-004" not in first
        older = _older_url(first)
        assert "actor=pager" in older
        second = logged_in_client.get(older).text
        assert "pg-004" in second and "pg-000" in second and "pg-005" not in second
        assert _older_url(second) == ""

    def test_half_cursor_is_refused(self, logged_in_client):
        r = logged_in_client.get("/admin/audit", params={"before_ts": "2026-09-20T12:00:00"})
        assert r.status_code == 400
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src $PY -m pytest tests/integration/test_audit_trail_page.py -q -p no:cacheprovider`
Expected: FAIL — `/admin/audit` answers 404 (anonymous: redirect still passes; the rest fail on status/content).

- [ ] **Step 3: Write the route** `src/seqsetup/routes/admin/audit.py`:

```python
"""Admin audit-trail page.

GET /admin/audit — full page, or the audit_page fragment on HX-Request.

Shows the permanent audit trail (AuditEventRepository), newest first, 100
per page, narrowed by the filter form's query parameters. Read-only: nothing
here changes or deletes an event.

Admin-only via router-level require_admin_dep.
"""

import json
from datetime import datetime, timedelta
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Request
from starlette.responses import HTMLResponse, Response

from ...context import AppContext
from ...models.audit_event import FIELD_CAPS
from ...templating import render
from ..dependencies import get_ctx, is_htmx_request, require_admin_dep
from ..utils import sanitize_string


router = APIRouter(
    tags=["admin-audit"],
    dependencies=[Depends(require_admin_dep)],
)

_PAGE = 100
_CURSOR_MAX = 64


def _day_start(text: str, plus_days: int = 0) -> str:
    """'YYYY-MM-DD' -> canonical timestamp of that UTC day's start, moved by
    ``plus_days``. Raises ValueError on any other shape."""
    return (datetime.strptime(text, "%Y-%m-%d") + timedelta(days=plus_days)).isoformat()


@router.get("/admin/audit", response_class=HTMLResponse)
def admin_audit(
    request: Request,
    ctx: AppContext = Depends(get_ctx),
    event: str = "",
    actor: str = "",
    target: str = "",
    date_from: str = "",
    date_to: str = "",
    before_ts: str = "",
    before_id: str = "",
    is_htmx: bool = Depends(is_htmx_request),
) -> Response:
    """GET /admin/audit — page or fragment."""
    # Each box is cut to its field's stored length, so any stored value can
    # be searched for.
    filters = {
        "event": sanitize_string(event, FIELD_CAPS["event"]),
        "actor": sanitize_string(actor, FIELD_CAPS["actor"]),
        "target": sanitize_string(target, FIELD_CAPS["target"]),
        "date_from": sanitize_string(date_from, 10),
        "date_to": sanitize_string(date_to, 10),
    }
    before_ts = sanitize_string(before_ts, _CURSOR_MAX)
    before_id = sanitize_string(before_id, _CURSOR_MAX)
    # A keyset cursor is both-or-neither. Half a cursor is malformed input —
    # refuse it rather than silently answer with the first page.
    if bool(before_ts) != bool(before_id):
        return Response("Invalid pagination cursor", status_code=400)

    error = ""
    from_ts = to_ts = None
    try:
        if filters["date_from"]:
            from_ts = _day_start(filters["date_from"])
        if filters["date_to"]:
            to_ts = _day_start(filters["date_to"], plus_days=1)
    except ValueError:
        error = "Dates must be written like 2026-09-26."

    events = []
    if not error and ctx.audit_event_repo is not None:
        events = ctx.audit_event_repo.search(
            limit=_PAGE + 1,
            event_prefix=filters["event"] or None,
            actor=filters["actor"] or None,
            target=filters["target"] or None,
            from_ts=from_ts,
            to_ts=to_ts,
            before_ts=before_ts or None,
            before_id=before_id or None,
        )
    has_more = len(events) > _PAGE
    events = events[:_PAGE]

    older_url = ""
    if has_more:
        next_ts, next_id = events[-1].cursor()
        query = {k: v for k, v in filters.items() if v}
        query.update(before_ts=next_ts, before_id=next_id)
        older_url = "/admin/audit?" + urlencode(query)

    rows = [
        {
            "time": e.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "actor": e.actor,
            "event": e.event,
            "target": e.target,
            "outcome": e.outcome,
            "details": json.dumps(e.details, indent=1, sort_keys=True) if e.details else "",
        }
        for e in events
    ]
    ctx_dict = {"rows": rows, "filters": filters, "error": error, "older_url": older_url}
    if is_htmx:
        return render(request, "admin/audit.html", ctx_dict, block_name="audit_page")
    return render(request, "admin/audit.html", ctx_dict)
```

- [ ] **Step 4: Write the template** `src/seqsetup/templates/admin/audit.html`:

```html
{% extends "_app_shell.html" %}
{% set page_title = "Audit trail" %}
{% set active_route = "/admin/audit" %}

{% block content %}
{% block audit_page %}
<div id="audit-page" class="space-y-4">
    <div>
        <h2 class="text-2xl font-semibold">Audit trail</h2>
        <p class="text-slate-600">
            Who did what, and when. Events are kept permanently: nothing in the app changes or deletes them. Times are UTC.
        </p>
    </div>

    <form class="flex gap-3 items-end flex-wrap"
          hx-get="/admin/audit"
          hx-target="#audit-page"
          hx-swap="outerHTML">
        <div>
            <label for="event" class="block text-sm font-medium mb-1">What happened</label>
            <input type="text" name="event" id="event" value="{{ filters.event }}"
                   placeholder="e.g. login" class="border rounded px-2 py-1">
        </div>
        <div>
            <label for="actor" class="block text-sm font-medium mb-1">Who</label>
            <input type="text" name="actor" id="actor" value="{{ filters.actor }}"
                   placeholder="username" class="border rounded px-2 py-1">
        </div>
        <div class="flex-1 min-w-[200px]">
            <label for="target" class="block text-sm font-medium mb-1">On what</label>
            <input type="text" name="target" id="target" value="{{ filters.target }}"
                   placeholder="run ID, username, …" class="w-full border rounded px-3 py-1">
        </div>
        <div>
            <label for="date_from" class="block text-sm font-medium mb-1">From</label>
            <input type="date" name="date_from" id="date_from" value="{{ filters.date_from }}"
                   class="border rounded px-2 py-1">
        </div>
        <div>
            <label for="date_to" class="block text-sm font-medium mb-1">To</label>
            <input type="date" name="date_to" id="date_to" value="{{ filters.date_to }}"
                   class="border rounded px-2 py-1">
        </div>
        <button type="submit" class="bg-primary text-white rounded px-3 py-1 hover:bg-primary-hover">Search</button>
        <a href="/admin/audit"
           class="bg-slate-200 hover:bg-slate-300 text-slate-800 rounded px-3 py-1"
           hx-get="/admin/audit" hx-target="#audit-page" hx-swap="outerHTML">Clear</a>
    </form>

    {% if error %}
        <div class="bg-red-100 border border-red-400 text-red-800 rounded px-3 py-2" role="alert">{{ error }}</div>
    {% elif not rows %}
        <div class="py-16 text-center">
            <p class="text-slate-600 font-medium">No audit events match.</p>
        </div>
    {% else %}
        <div class="table-scroll">
            <table class="w-full border-collapse text-sm">
                <thead>
                    <tr class="bg-slate-100">
                        <th class="border px-2 py-1 text-left" scope="col">Time (UTC)</th>
                        <th class="border px-2 py-1 text-left" scope="col">Who</th>
                        <th class="border px-2 py-1 text-left" scope="col">What</th>
                        <th class="border px-2 py-1 text-left" scope="col">On what</th>
                        <th class="border px-2 py-1 text-left" scope="col">Result</th>
                        <th class="border px-2 py-1 text-left" scope="col">Details</th>
                    </tr>
                </thead>
                <tbody>
                    {% for row in rows %}
                    <tr>
                        <td class="border px-2 py-1 whitespace-nowrap font-mono text-xs">{{ row.time }}</td>
                        <td class="border px-2 py-1 text-xs">{{ row.actor }}</td>
                        <td class="border px-2 py-1 whitespace-nowrap text-xs">{{ row.event }}</td>
                        <td class="border px-2 py-1 text-xs break-all">{{ row.target }}</td>
                        <td class="border px-2 py-1 text-xs">{{ row.outcome }}</td>
                        <td class="border px-2 py-1"><pre class="whitespace-pre-wrap text-xs">{{ row.details }}</pre></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% if older_url %}
        <div class="flex justify-end">
            <a href="{{ older_url }}"
               class="bg-slate-200 hover:bg-slate-300 text-slate-800 rounded px-3 py-1"
               hx-get="{{ older_url }}" hx-target="#audit-page" hx-swap="outerHTML">Older</a>
        </div>
        {% endif %}
    {% endif %}
</div>
{% endblock %}
{% endblock %}
```

- [ ] **Step 5: Nav, pointer, package index, router**

`_app_shell.html`, after the Logs `<a …>Logs</a>` line:
```html
                    <a href="/admin/audit" class="nav-item{% if active_route == '/admin/audit' %} active{% endif %}"{% if active_route == '/admin/audit' %} aria-current="page"{% endif %}>Audit trail</a>
```
`admin/logs.html`, after the description `<p>…</p>`:
```html
        <p class="text-slate-600 text-sm">
            Audit events (who did what) are on the <a href="/admin/audit" class="underline">Audit trail</a> page.
        </p>
```
`routes/admin/__init__.py` docstring list: add `  - admin/audit.py` after `  - admin/logs.py`.
`app.py`: `audit as admin_audit,` first in the `from .routes.admin import (` block; `app.include_router(admin_audit.router)` after `app.include_router(admin_logs.router)`.

- [ ] **Step 6: Run to verify it passes**

Run: `PYTHONPATH=src $PY -m pytest tests/integration/test_audit_trail_page.py -q -p no:cacheprovider`
Expected: `13 passed`.

---

### Task 7: End-to-end guarantees

**Files:**
- Rewrite: `tests/integration/test_audit_trail_visible.py` (was the N-07 `/admin/logs` check)

**Interfaces:**
- Consumes: everything above; `sample_api._api_get`, `LimsUrlValidationError`.

- [ ] **Step 1: Write the tests** (full file):

```python
"""Audit events are kept for good and shown on /admin/audit.

No test here raises a logger level or sets the sink by hand: what the page
and the database show is what the app itself records.
"""

import importlib
import json
import logging
import sys

import pytest
from starlette.testclient import TestClient

from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import (
    InstrumentPlatform,
    RunCycles,
    SequencingRun,
)

from .conftest import disable_repos


ORIGIN = {"Origin": "http://testserver"}


def _events(ctx, **kw):
    return ctx.audit_event_repo.search(limit=500, **kw)


def _restart_app():
    """Build the app again against the same test database, the way a process
    restart would: fresh repositories, fresh in-memory log buffer."""
    import seqsetup.startup as startup_module
    from seqsetup.services import log_capture
    for sched in (getattr(startup_module, "_profile_sync_scheduler", None),):
        if sched is not None:
            sched.stop()
    startup_module._db = None
    startup_module._repos = {}
    startup_module._github_sync_service = None
    startup_module._profile_sync_scheduler = None
    startup_module._auth_service = None
    if log_capture._log_capture_handler is not None:
        logging.getLogger("seqsetup").removeHandler(log_capture._log_capture_handler)
        log_capture._log_capture_handler = None
    del sys.modules["seqsetup.app"]
    app_module = importlib.import_module("seqsetup.app")
    sched = getattr(startup_module, "_profile_sync_scheduler", None)
    if sched is not None:
        sched.stop()
    return app_module


class TestAuditEventsAreRecorded:
    """Real actions land in the audit trail and on the page."""

    def test_login_is_recorded(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        (event,) = _events(ctx, event_prefix="login.success")
        assert event.actor == "admin-test"
        page = logged_in_client.get("/admin/audit").text
        assert "login.success" in page and "admin-test" in page

    def test_mark_ready_is_recorded(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        run = SequencingRun(
            id="audit-visible",
            run_name="AuditVisible",
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            run_cycles=RunCycles(151, 151, 8, 8),
        )
        run.add_sample(Sample(
            sample_id="S1",
            index_pair=IndexPair(
                id="p1", name="p1",
                index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
                index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5),
            ),
        ))
        ctx.run_repo.save(run)
        logged_in_client.post(f"/runs/{run.id}/status/ready", headers=ORIGIN)
        assert ctx.run_repo.get_by_id(run.id).status.value == "ready"

        assert _events(ctx, event_prefix="run.status.changed", target="audit-visible")
        page = logged_in_client.get("/admin/audit", params={"target": "audit-visible"}).text
        assert "run.status.changed" in page

    def test_log_viewer_no_longer_lists_audit_events(self, logged_in_client):
        assert "login.success" not in logged_in_client.get("/admin/logs").text


class TestAuditEventsAreKept:
    """Neither Clear logs nor a restart removes an event."""

    def test_clear_logs_keeps_the_trail(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        assert logged_in_client.post("/admin/logs/clear", headers=ORIGIN).status_code == 200
        assert _events(ctx, event_prefix="login.success")
        assert _events(ctx, event_prefix="logs.cleared")
        assert "login.success" in logged_in_client.get("/admin/audit").text

    def test_restart_keeps_the_trail(self, logged_in_client, fresh_app, admin_user_seeded):
        _app, ctx, _db = fresh_app
        (before,) = _events(ctx, event_prefix="login.success")

        app_module = _restart_app()
        client = TestClient(app_module.app, base_url="http://testserver")
        assert client.post("/login/submit", data=admin_user_seeded, headers=ORIGIN,
                           follow_redirects=False).status_code == 303

        after = app_module._ctx.audit_event_repo.search(limit=10, event_prefix="login.success")
        assert before.id in [e.id for e in after]
        assert len(after) == 2


class TestLimsAddressSecretsAreNotKept:
    """N-21: a refused LIMS address is recorded without its password or token."""

    def test_blocked_lims_url_is_stored_clean(self, fresh_app, logged_in_client, caplog):
        from seqsetup.services.sample_api import LimsUrlValidationError, _api_get
        _app, ctx, db = fresh_app
        caplog.set_level(logging.INFO, logger="seqsetup.audit")

        with pytest.raises(LimsUrlValidationError):
            _api_get("//svc:PASSWORD@lims.invalid/api?api_token=TOKEN")

        (event,) = _events(ctx, event_prefix="lims.url_blocked")
        assert event.target == "//lims.invalid/api"
        raw = json.dumps(list(db["audit_events"].find({}, {"_id": 0})), default=str)
        assert "PASSWORD" not in raw and "TOKEN" not in raw
        lines = [r.message for r in caplog.records if r.name == "seqsetup.audit"]
        assert lines and not any("PASSWORD" in l or "TOKEN" in l for l in lines)
        page = logged_in_client.get("/admin/audit", params={"event": "lims"}).text
        assert "//lims.invalid/api" in page and "PASSWORD" not in page
```

- [ ] **Step 2: Run** — these exercise Tasks 1–6 together; they must pass. That they bite is proved by the break tests in the Final section.

Run: `PYTHONPATH=src $PY -m pytest tests/integration/test_audit_trail_visible.py -q -p no:cacheprovider`
Expected: `6 passed`.

---

### Final: verify

- [ ] Full server suite: `PYTHONPATH=src $PY -m pytest tests/unit tests/integration -q -p no:cacheprovider` → 1596 + new − 0 removed (the one replaced N-07 test keeps its count). Name every term of the difference; zero ERROR.
- [ ] Rebuild CSS (`/home/parlar_ai/dev/seqsetup/.pixi/bin/tailwindcss -i src/seqsetup/static/css/input.css -o src/seqsetup/static/css/app.css --minify`), then the browser suite → `87 passed`.
- [ ] Break tests, one at a time, restoring from a saved copy and checking with `cmp`:
  1. `_audit_sink` never set in `app.py` → Task 7 recorded/kept tests fail.
  2. `redact_url_secrets` returns its input → redaction tests and the N-21 test fail.
  3. `pymongo.timeout` removed from `_store` → the dead-server test fails (> 5 s).
  4. `_not_audit_record` filter not added → the log-viewer tests fail.
  5. target box cut at 256 in the route → the long-target page test fails.
  6. an `update_one` method added to the repository → the insert-only test fails.
- [ ] Re-run the audit's N-18 / N-21 proofs from `/home/parlar_ai/dev/seqsetup/.worktrees/sec-audit/tests/integration/security_proofs/` (copied in temporarily, removed after) and read each result.
- [ ] Look at the page in a real browser (screenshot), with a few events.
- [ ] Independent code review of the whole diff (superpowers:requesting-code-review).
- [ ] `git -C <wt> status` shows only the files in the File Structure table (plus built `app.css`, untracked and ignored).
