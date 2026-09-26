# Server-side Sessions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Logins live in a server-side list (`web_sessions`), so logout, user delete, role change and password reset end them, with a 30-minute idle limit and an 8-hour hard cap (security audit N-02, N-03, N-04, N-19).

**Architecture:** The cookie holds only a random ticket; MongoDB holds its SHA-256 and the login's facts. `AuthMiddleware` resolves the ticket on every request through `services/web_sessions.resolve`, which enforces idle / age limits and, for database users, a per-user `session_stamp` that changes with the role or password — so the account write itself revokes. Row deletion is cleanup.

**Tech Stack:** Python 3.14, FastAPI/Starlette, Jinja2, HTMX 2.0.10, pymongo 4.16 (mongomock 4.3 in tests), pytest, Playwright.

**Spec:** `docs/superpowers/specs/2026-09-27-session-revocation-design.md`

## Global Constraints

- Worktree `/home/parlar_ai/dev/seqsetup/.worktrees/sessions`, branch `fix/session-revocation`. Never `pixi run` here.
- Python: `PY=/home/parlar_ai/dev/seqsetup/.pixi/envs/default/bin/python`, run as `PYTHONPATH=src $PY -m pytest ... -p no:cacheprovider`.
- CSS for browser tests: `/home/parlar_ai/dev/seqsetup/.pixi/bin/tailwindcss -i src/seqsetup/static/css/input.css -o src/seqsetup/static/css/app.css --minify`.
- Defaults: `SEQSETUP_SESSION_MAX_AGE_SECONDS` = `28800`, `SEQSETUP_SESSION_IDLE_SECONDS` = `1800`. Clamps: max_age `[300, 86400]`, idle `[60, max_age]`, WARNING on clamp, `ValueError` on non-integer.
- Datetimes in `web_sessions` are naive UTC; values read back are treated as UTC.
- HTMX ended-login message, exact text: `Your login has ended, so this was not saved. What you typed is still on this page. Log in again in a new tab, then try again here.` — with "Log in again" a link `<a href="/login" target="_blank" rel="noopener">`.
- Admin messages: `User '{username}' updated. Their open logins were ended.` / `User '{username}' deleted. Their open logins were ended.`
- Commit trailer: `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`. Commit on the branch only.

---

### Task 1: Where a login came from, and the per-user stamp

**Files:**
- Modify: `src/seqsetup/models/user.py` (add two fields)
- Modify: `src/seqsetup/models/local_user.py` (stamp field, rotation, `to_user`)
- Modify: `src/seqsetup/services/auth.py` (yaml / ldap source)
- Test: `tests/unit/test_local_user_session_stamp.py` (new)

**Interfaces:**
- Produces: `User.source: str = ""`, `User.session_stamp: str = ""`; `LocalUser.session_stamp: str`; `LocalUser.to_user()` sets `source="local"`, `session_stamp`; yaml users `source="yaml"`, ldap users `source="ldap"`.

- [ ] **Step 1: Write the failing tests**

```python
"""A database user's session stamp changes exactly when their role or
password changes, so logins made before the change stop working."""

from unittest.mock import patch

from seqsetup.models.local_user import LocalUser
from seqsetup.models.user import UserRole


def _user(**kw):
    return LocalUser(username="alice", display_name="Alice", **kw)


class TestSessionStamp:
    """The stamp is the database user's login generation."""

    def test_new_user_gets_a_random_stamp(self):
        a, b = _user(), _user()
        assert len(a.session_stamp) == 32 and a.session_stamp != b.session_stamp

    def test_stored_stamp_is_kept(self):
        u = _user()
        again = LocalUser.from_dict(u.to_dict())
        assert again.session_stamp == u.session_stamp

    def test_missing_stamp_reads_as_empty_every_time(self):
        doc = _user().to_dict()
        del doc["session_stamp"]
        assert LocalUser.from_dict(doc).session_stamp == ""
        assert LocalUser.from_dict(doc).session_stamp == ""

    def test_set_password_changes_the_stamp(self):
        u = _user()
        before = u.session_stamp
        u.set_password("Strong-Passw0rd!")
        assert u.session_stamp != before

    def test_role_change_changes_the_stamp(self):
        u = _user(role=UserRole.ADMIN)
        before = u.session_stamp
        u.role = UserRole.STANDARD
        assert u.session_stamp != before

    def test_same_role_name_and_email_keep_the_stamp(self):
        u = _user(role=UserRole.ADMIN)
        before = u.session_stamp
        u.role = UserRole.ADMIN
        u.display_name = "Alice B"
        u.email = "a@example.com"
        assert u.session_stamp == before


class TestLoginSource:
    """Each login knows which user source it came from."""

    def test_database_user_is_local_with_stamp(self):
        u = _user()
        user = u.to_user()
        assert (user.source, user.session_stamp) == ("local", u.session_stamp)

    def test_yaml_user_is_yaml(self, tmp_path):
        import bcrypt
        from seqsetup.services.auth import AuthService
        h = bcrypt.hashpw(b"Yaml-Passw0rd!", bcrypt.gensalt(rounds=4)).decode()
        cfg = tmp_path / "users.yaml"
        cfg.write_text(f"users:\n  bob:\n    password_hash: '{h}'\n    role: standard\n")
        user = AuthService(cfg).authenticate("bob", "Yaml-Passw0rd!")
        assert (user.source, user.session_stamp) == ("yaml", "")

    def test_ldap_user_is_ldap(self, tmp_path):
        from seqsetup.models.user import User
        from seqsetup.services.auth import AuthService

        class _Cfg:
            is_ldap_enabled = True
            allow_local_fallback = False
            ldap_config = object()

        plain = User(username="carol", display_name="Carol", role=UserRole.STANDARD)
        with patch("seqsetup.services.ldap.LDAPService") as svc:
            svc.return_value.authenticate.return_value = plain
            user = AuthService(tmp_path / "none.yaml", get_auth_config=lambda: _Cfg()).authenticate("carol", "x")
        assert user.source == "ldap"
```

- [ ] **Step 2: Run to verify they fail**

Run: `PYTHONPATH=src $PY -m pytest tests/unit/test_local_user_session_stamp.py -q -p no:cacheprovider`
Expected: FAIL (`AttributeError: ... 'session_stamp'`, `source`).

- [ ] **Step 3: Implement**

`models/user.py` — add to `User` after `email`:

```python
    # Where this login came from ("local", "yaml", "ldap") and, for a
    # database user, their session stamp at login. Read by the session list.
    source: str = ""
    session_stamp: str = ""
```

`models/local_user.py` — add `import secrets`, a helper, the field (LAST in the dataclass), rotation:

```python
def _new_session_stamp() -> str:
    return secrets.token_hex(16)
```

```python
    updated_at: datetime = field(default_factory=datetime.now)
    # Changes whenever the role or password changes (see __setattr__ and
    # set_password); a login made with an older stamp is refused.
    session_stamp: str = field(default_factory=_new_session_stamp)

    def __setattr__(self, name, value):
        # Only after construction (session_stamp exists) and only on a real
        # role change: logins made under the old role must stop working.
        if (name == "role" and "session_stamp" in self.__dict__
                and self.__dict__.get("role") != value):
            object.__setattr__(self, "session_stamp", _new_session_stamp())
        object.__setattr__(self, name, value)
```

In `set_password`, after `self.password_hash = ...`: `self.session_stamp = _new_session_stamp()`.

`to_user()` adds `source="local", session_stamp=self.session_stamp`. `to_dict()` adds `"session_stamp": self.session_stamp`. `from_dict()` adds `session_stamp=data.get("session_stamp", "")`.

`services/auth.py`:
- yaml branch: `User(..., email=user_data.get("email"), source="yaml")`.
- `_authenticate_ldap`: `return dataclasses.replace(ldap_service.authenticate(username, password), source="ldap")` (add `import dataclasses`).

- [ ] **Step 4: Run to verify they pass, plus the user/auth suites**

Run: `PYTHONPATH=src $PY -m pytest tests/unit/test_local_user_session_stamp.py tests/unit -k "user or auth or ldap" -q -p no:cacheprovider`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/seqsetup/models/user.py src/seqsetup/models/local_user.py src/seqsetup/services/auth.py tests/unit/test_local_user_session_stamp.py
git commit -m "feat(auth): logins know their source; a database user's stamp changes with role or password"
```

---

### Task 2: `WebSession` model and `WebSessionRepository`

**Files:**
- Create: `src/seqsetup/models/web_session.py`
- Create: `src/seqsetup/repositories/web_session_repo.py`
- Modify: `src/seqsetup/startup.py` (registry entry `"web_session"`, `get_web_session_repo()`, `get_app_context`)
- Modify: `src/seqsetup/context.py` (field `web_session_repo`)
- Test: `tests/unit/test_web_session_model.py`, `tests/integration/test_web_session_repo.py` (new)

**Interfaces:**
- Produces: `WebSession(id, username, display_name, role, source, session_stamp, created_at, last_seen_at, email=None)`, `.to_dict()`, `.from_dict()`, `TEXT_CAP = 256`; `as_utc(dt) -> datetime` (naive UTC).
- Produces: `WebSessionRepository(db)` with `create(ws)`, `get(id) -> WebSession | None`, `touch(id, when)`, `delete(id)`, `delete_for_user(username) -> int`, `delete_expired(*, seen_before, created_before) -> int`; `startup.get_web_session_repo()`; `AppContext.web_session_repo`.

- [ ] **Step 1: Write the failing tests**

`tests/unit/test_web_session_model.py`:

```python
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
```

`tests/integration/test_web_session_repo.py`:

```python
"""The login list is a thin store: create, read, touch, delete."""

from datetime import datetime, timedelta

import mongomock
import pytest

from seqsetup.models.user import UserRole
from seqsetup.models.web_session import WebSession
from seqsetup.repositories.web_session_repo import WebSessionRepository

T0 = datetime(2026, 9, 27, 8, 0, 0)


@pytest.fixture
def repo():
    return WebSessionRepository(mongomock.MongoClient()["t"])


def _ws(i, username="alice", created=T0, seen=T0):
    return WebSession(id=f"{i:064x}", username=username, display_name=username,
                      role=UserRole.STANDARD, source="local", session_stamp="",
                      created_at=created, last_seen_at=seen)


class TestWebSessionRepository:
    """Each method does one thing."""

    def test_create_and_get(self, repo):
        repo.create(_ws(1))
        assert repo.get(f"{1:064x}").username == "alice"
        assert repo.get("nope") is None

    def test_touch_moves_forward_only(self, repo):
        repo.create(_ws(1))
        repo.touch(f"{1:064x}", T0 + timedelta(minutes=5))
        repo.touch(f"{1:064x}", T0 + timedelta(minutes=1))
        assert repo.get(f"{1:064x}").last_seen_at == T0 + timedelta(minutes=5)

    def test_delete_one(self, repo):
        repo.create(_ws(1)); repo.create(_ws(2))
        repo.delete(f"{1:064x}")
        assert repo.get(f"{1:064x}") is None and repo.get(f"{2:064x}") is not None

    def test_delete_for_user_leaves_others(self, repo):
        repo.create(_ws(1)); repo.create(_ws(2)); repo.create(_ws(3, username="bob"))
        assert repo.delete_for_user("alice") == 2
        assert repo.get(f"{3:064x}") is not None

    def test_delete_expired_both_rules(self, repo):
        repo.create(_ws(1, seen=T0 - timedelta(hours=1)))            # idle
        repo.create(_ws(2, created=T0 - timedelta(hours=9)))          # too old
        repo.create(_ws(3))                                           # live
        n = repo.delete_expired(seen_before=T0 - timedelta(minutes=30),
                                created_before=T0 - timedelta(hours=8))
        assert n == 2 and repo.get(f"{3:064x}") is not None

    def test_indexes(self, repo):
        keys = {tuple(ix["key"]) for ix in repo.collection.index_information().values()}
        assert {(("username", 1),), (("last_seen_at", 1),), (("created_at", 1),)} <= keys


def test_registered_on_app_context(fresh_app):
    _app, ctx, _db = fresh_app
    assert isinstance(ctx.web_session_repo, WebSessionRepository)
```

(`index_information()` values' `"key"` is a list of `(field, dir)` pairs; `tuple(...)` of it gives e.g. `(("username", 1),)`.)

- [ ] **Step 2: Run to verify they fail**

Run: `PYTHONPATH=src $PY -m pytest tests/unit/test_web_session_model.py tests/integration/test_web_session_repo.py -q -p no:cacheprovider`
Expected: FAIL (`ModuleNotFoundError: seqsetup.models.web_session`).

- [ ] **Step 3: Implement**

`src/seqsetup/models/web_session.py`:

```python
"""One login in the server-side login list (``web_sessions``).

The browser's cookie holds only a random ticket; this row holds the SHA-256
of that ticket as its id, so a copy of the database cannot be turned back
into working cookies. Times are naive UTC.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from .user import User, UserRole

TEXT_CAP = 256
_TEXT_FIELDS = ("username", "display_name", "email")


def as_utc(value: datetime) -> datetime:
    """Naive UTC. An aware value is converted; a naive one is taken as UTC."""
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


@dataclass
class WebSession:
    """One login."""

    id: str
    username: str
    display_name: str
    role: UserRole
    source: str
    session_stamp: str
    created_at: datetime
    last_seen_at: datetime
    email: Optional[str] = None

    def __setattr__(self, name, value):
        if name in _TEXT_FIELDS and value is not None:
            value = str(value)[:TEXT_CAP]
        elif name in ("created_at", "last_seen_at"):
            value = as_utc(value)
        object.__setattr__(self, name, value)

    def to_user(self) -> User:
        return User(username=self.username, display_name=self.display_name,
                    role=self.role, email=self.email, source=self.source,
                    session_stamp=self.session_stamp)

    def to_dict(self) -> dict:
        return {
            "_id": self.id,
            "username": self.username,
            "display_name": self.display_name,
            "email": self.email,
            "role": self.role.value,
            "source": self.source,
            "session_stamp": self.session_stamp,
            "created_at": self.created_at,
            "last_seen_at": self.last_seen_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "WebSession":
        return cls(
            id=data["_id"],
            username=data.get("username", ""),
            display_name=data.get("display_name", ""),
            email=data.get("email"),
            role=UserRole(data.get("role", "standard")),
            source=data.get("source", ""),
            session_stamp=data.get("session_stamp", ""),
            created_at=data["created_at"],
            last_seen_at=data["last_seen_at"],
        )
```

`src/seqsetup/repositories/web_session_repo.py`:

```python
"""The server-side login list. Thin: no expiry or revocation rules here —
those live in ``services/web_sessions.py``."""

from datetime import datetime
from typing import Optional

from pymongo.database import Database

from ..models.web_session import WebSession


class WebSessionRepository:
    """Manages the ``web_sessions`` collection."""

    COLLECTION = "web_sessions"

    def __init__(self, db: Database):
        self.collection = db[self.COLLECTION]
        self.collection.create_index("username")
        self.collection.create_index("last_seen_at")
        self.collection.create_index("created_at")

    def create(self, ws: WebSession) -> None:
        self.collection.insert_one(ws.to_dict())

    def get(self, session_id: str) -> Optional[WebSession]:
        doc = self.collection.find_one({"_id": session_id})
        return WebSession.from_dict(doc) if doc else None

    def touch(self, session_id: str, when: datetime) -> None:
        """Move last_seen_at forward to ``when`` (never backwards)."""
        self.collection.update_one({"_id": session_id}, {"$max": {"last_seen_at": when}})

    def delete(self, session_id: str) -> None:
        self.collection.delete_one({"_id": session_id})

    def delete_for_user(self, username: str) -> int:
        return self.collection.delete_many({"username": username}).deleted_count

    def delete_expired(self, *, seen_before: datetime, created_before: datetime) -> int:
        return self.collection.delete_many({"$or": [
            {"last_seen_at": {"$lt": seen_before}},
            {"created_at": {"$lt": created_before}},
        ]}).deleted_count
```

`touch` receives a naive-UTC datetime from the service (Task 3 passes `utcnow()`).

`startup.py`: `from .repositories.web_session_repo import WebSessionRepository`; registry `"web_session": WebSessionRepository,`; getter:

```python
def get_web_session_repo() -> WebSessionRepository:
    return _get_repo("web_session")
```

and `web_session_repo=get_web_session_repo(),` in `get_app_context()`.

`context.py`: import and `web_session_repo: Optional[WebSessionRepository] = None` after `audit_event_repo`.

- [ ] **Step 4: Run to verify they pass**

Run: same as Step 2. Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/seqsetup/models/web_session.py src/seqsetup/repositories/web_session_repo.py src/seqsetup/startup.py src/seqsetup/context.py tests/unit/test_web_session_model.py tests/integration/test_web_session_repo.py
git commit -m "feat(sessions): the web_sessions login list (model and repository)"
```

---

### Task 3: `services/web_sessions.py` — policy, start, resolve, end

**Files:**
- Create: `src/seqsetup/services/web_sessions.py`
- Test: `tests/unit/test_web_session_policy.py` (new)

**Interfaces:**
- Consumes: Task 1 `User.source/session_stamp`, `LocalUser.session_stamp`; Task 2 repo methods, `as_utc`.
- Produces:
  - `SessionPolicy(idle_seconds: int, max_age_seconds: int)` (frozen dataclass); `SessionPolicy.from_env(environ=os.environ) -> SessionPolicy`.
  - `set_policy(policy)`, `current_policy() -> SessionPolicy` (defaults `from_env()` if never set).
  - `utcnow() -> datetime` (naive UTC; tests monkeypatch `web_sessions.utcnow`).
  - `ticket_id(ticket: str) -> str`.
  - `start(sessions, user: User, now: datetime, policy: SessionPolicy) -> str` (the ticket).
  - `resolve(sessions, users, ticket: str, now: datetime, policy: SessionPolicy) -> User | None`.
  - `end(sessions, ticket: str) -> None`; `end_all_for(sessions, username: str) -> int`.

- [ ] **Step 1: Write the failing tests**

```python
"""The login rules: idle limit, hard cap, database-user stamp, hashing."""

import logging
from datetime import datetime, timedelta

import mongomock
import pytest

from seqsetup.models.local_user import LocalUser
from seqsetup.models.user import User, UserRole
from seqsetup.repositories.local_user_repo import LocalUserRepository
from seqsetup.repositories.web_session_repo import WebSessionRepository
from seqsetup.services import web_sessions as ws
from seqsetup.services.web_sessions import SessionPolicy

T0 = datetime(2026, 9, 27, 8, 0, 0)
POLICY = SessionPolicy(idle_seconds=1800, max_age_seconds=28800)


@pytest.fixture
def repos():
    db = mongomock.MongoClient()["t"]
    return WebSessionRepository(db), LocalUserRepository(db)


def _yaml_user(name="bob"):
    return User(username=name, display_name=name, role=UserRole.STANDARD, source="yaml")


def _db_user(users, name="alice", role=UserRole.ADMIN):
    u = LocalUser(username=name, display_name=name, role=role)
    users.save(u)
    return u


class TestPolicy:
    """Defaults, overrides, visible clamps, refused junk."""

    def test_defaults(self):
        assert SessionPolicy.from_env({}) == SessionPolicy(1800, 28800)

    def test_overrides(self):
        p = SessionPolicy.from_env({"SEQSETUP_SESSION_IDLE_SECONDS": "600",
                                    "SEQSETUP_SESSION_MAX_AGE_SECONDS": "3600"})
        assert p == SessionPolicy(600, 3600)

    @pytest.mark.parametrize("env,expected", [
        ({"SEQSETUP_SESSION_IDLE_SECONDS": "5"}, SessionPolicy(60, 28800)),
        ({"SEQSETUP_SESSION_IDLE_SECONDS": "99999"}, SessionPolicy(28800, 28800)),
        ({"SEQSETUP_SESSION_MAX_AGE_SECONDS": "10"}, SessionPolicy(300, 300)),
        ({"SEQSETUP_SESSION_MAX_AGE_SECONDS": "999999"}, SessionPolicy(1800, 86400)),
    ])
    def test_clamps_with_a_warning(self, env, expected, caplog):
        caplog.set_level(logging.WARNING, logger="seqsetup.services.web_sessions")
        assert SessionPolicy.from_env(env) == expected
        assert any("SEQSETUP_SESSION_" in r.getMessage() for r in caplog.records)

    def test_non_integer_is_refused(self):
        with pytest.raises(ValueError):
            SessionPolicy.from_env({"SEQSETUP_SESSION_IDLE_SECONDS": "30m"})


class TestResolve:
    """A ticket is accepted only while every rule holds."""

    def test_db_stores_the_hash_not_the_ticket(self, repos):
        sessions, _ = repos
        ticket = ws.start(sessions, _yaml_user(), T0, POLICY)
        doc = sessions.collection.find_one()
        assert doc["_id"] == ws.ticket_id(ticket) != ticket
        assert ticket not in str(doc)

    def test_unknown_ticket(self, repos):
        assert ws.resolve(*repos, "nope", T0, POLICY) is None

    @pytest.mark.parametrize("after,ok", [(1799, True), (1801, False)])
    def test_idle_limit(self, repos, after, ok):
        t = ws.start(repos[0], _yaml_user(), T0, POLICY)
        assert (ws.resolve(*repos, t, T0 + timedelta(seconds=after), POLICY) is not None) == ok

    def test_idle_refusal_removes_the_row(self, repos):
        t = ws.start(repos[0], _yaml_user(), T0, POLICY)
        ws.resolve(*repos, t, T0 + timedelta(minutes=31), POLICY)
        assert repos[0].get(ws.ticket_id(t)) is None

    def test_activity_every_29_minutes_lasts_until_the_cap(self, repos):
        t = ws.start(repos[0], _yaml_user(), T0, POLICY)
        now = T0
        while now + timedelta(minutes=29) <= T0 + timedelta(hours=8):
            now += timedelta(minutes=29)
            assert ws.resolve(*repos, t, now, POLICY) is not None, now
        assert ws.resolve(*repos, t, T0 + timedelta(hours=8, minutes=1), POLICY) is None

    def test_short_idle_with_requests_every_59_seconds(self, repos):
        p = SessionPolicy(idle_seconds=60, max_age_seconds=28800)
        t = ws.start(repos[0], _yaml_user(), T0, p)
        for i in range(1, 11):
            assert ws.resolve(*repos, t, T0 + timedelta(seconds=59 * i), p) is not None, i

    @pytest.mark.parametrize("age,ok", [(timedelta(hours=7, minutes=59), True),
                                        (timedelta(hours=8, minutes=1), False)])
    def test_hard_cap(self, repos, age, ok):
        t = ws.start(repos[0], _yaml_user(), T0, POLICY)
        repos[0].touch(ws.ticket_id(t), T0 + age)          # active until now
        assert (ws.resolve(*repos, t, T0 + age, POLICY) is not None) == ok

    def test_db_user_stamp_mismatch_is_refused(self, repos):
        sessions, users = repos
        u = _db_user(users)
        t = ws.start(sessions, u.to_user(), T0, POLICY)
        u.role = UserRole.STANDARD
        users.save(u)
        assert ws.resolve(sessions, users, t, T0, POLICY) is None
        assert sessions.get(ws.ticket_id(t)) is None

    def test_deleted_db_user_is_refused(self, repos):
        sessions, users = repos
        u = _db_user(users)
        t = ws.start(sessions, u.to_user(), T0, POLICY)
        users.delete("alice")
        assert ws.resolve(sessions, users, t, T0, POLICY) is None

    def test_db_user_details_come_from_the_current_record(self, repos):
        sessions, users = repos
        u = _db_user(users)
        t = ws.start(sessions, u.to_user(), T0, POLICY)
        u.display_name = "Alice Renamed"
        users.save(u)
        assert ws.resolve(sessions, users, t, T0, POLICY).display_name == "Alice Renamed"

    def test_unknown_source_is_refused(self, repos):
        user = User(username="x", display_name="x", role=UserRole.ADMIN, source="")
        t = ws.start(repos[0], user, T0, POLICY)
        assert ws.resolve(*repos, t, T0, POLICY) is None

    def test_start_clears_expired_rows(self, repos):
        old = ws.start(repos[0], _yaml_user("old"), T0, POLICY)
        ws.start(repos[0], _yaml_user("new"), T0 + timedelta(hours=1), POLICY)
        assert repos[0].get(ws.ticket_id(old)) is None


class TestEnd:
    """Logout ends one login; revocation ends all of a user's."""

    def test_end_one(self, repos):
        a = ws.start(repos[0], _yaml_user(), T0, POLICY)
        b = ws.start(repos[0], _yaml_user(), T0, POLICY)
        ws.end(repos[0], a)
        assert ws.resolve(*repos, a, T0, POLICY) is None
        assert ws.resolve(*repos, b, T0, POLICY) is not None

    def test_end_all_for(self, repos):
        ws.start(repos[0], _yaml_user("bob"), T0, POLICY)
        ws.start(repos[0], _yaml_user("bob"), T0, POLICY)
        keep = ws.start(repos[0], _yaml_user("eve"), T0, POLICY)
        assert ws.end_all_for(repos[0], "bob") == 2
        assert ws.resolve(*repos, keep, T0, POLICY) is not None
```

- [ ] **Step 2: Run to verify they fail**

Run: `PYTHONPATH=src $PY -m pytest tests/unit/test_web_session_policy.py -q -p no:cacheprovider`
Expected: FAIL (`ModuleNotFoundError: seqsetup.services.web_sessions`).

- [ ] **Step 3: Implement** `src/seqsetup/services/web_sessions.py`:

```python
"""The login rules (security audit N-02, N-03, N-04, N-19).

A login is a row in ``web_sessions``; the browser holds a random ticket and
the row's id is the ticket's SHA-256. A ticket is accepted while:
- the row exists (logout / revocation delete it);
- it was used within the idle limit, and is younger than the hard cap;
- for a database user, the user still exists and their ``session_stamp`` is
  the one the login was made with. The stamp changes with the role or the
  password (models/local_user.py), so the account write itself revokes —
  deleting rows is cleanup.
"""

import hashlib
import logging
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Mapping, Optional

from ..models.user import User
from ..models.web_session import WebSession

logger = logging.getLogger(__name__)

_SOURCES = ("local", "yaml", "ldap")


@dataclass(frozen=True)
class SessionPolicy:
    idle_seconds: int
    max_age_seconds: int

    @classmethod
    def from_env(cls, environ: Mapping[str, str] = os.environ) -> "SessionPolicy":
        max_age = _read(environ, "SEQSETUP_SESSION_MAX_AGE_SECONDS", 28800, 300, 86400)
        idle = _read(environ, "SEQSETUP_SESSION_IDLE_SECONDS", 1800, 60, max_age)
        return cls(idle_seconds=idle, max_age_seconds=max_age)


def _read(environ, name: str, default: int, low: int, high: int) -> int:
    raw = environ.get(name)
    value = default if raw is None or raw.strip() == "" else int(raw)
    used = max(low, min(high, value))
    if used != value:
        logger.warning("%s=%s is outside %s..%s; using %s", name, value, low, high, used)
    return used


_policy: Optional[SessionPolicy] = None


def set_policy(policy: SessionPolicy) -> None:
    global _policy
    _policy = policy


def current_policy() -> SessionPolicy:
    global _policy
    if _policy is None:
        _policy = SessionPolicy.from_env()
    return _policy


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def ticket_id(ticket: str) -> str:
    return hashlib.sha256(ticket.encode("utf-8")).hexdigest()


def start(sessions, user: User, now: datetime, policy: SessionPolicy) -> str:
    """Record a new login and return its ticket (for the cookie)."""
    sessions.delete_expired(
        seen_before=now - timedelta(seconds=policy.idle_seconds),
        created_before=now - timedelta(seconds=policy.max_age_seconds),
    )
    ticket = secrets.token_urlsafe(32)
    sessions.create(WebSession(
        id=ticket_id(ticket), username=user.username, display_name=user.display_name,
        email=user.email, role=user.role, source=user.source,
        session_stamp=user.session_stamp, created_at=now, last_seen_at=now,
    ))
    return ticket


def resolve(sessions, users, ticket: str, now: datetime,
            policy: SessionPolicy) -> Optional[User]:
    """The logged-in user for ``ticket``, or None. Database errors propagate."""
    sid = ticket_id(ticket)
    row = sessions.get(sid)
    if row is None:
        return None
    if (now - row.last_seen_at > timedelta(seconds=policy.idle_seconds)
            or now - row.created_at > timedelta(seconds=policy.max_age_seconds)
            or row.source not in _SOURCES):
        sessions.delete(sid)
        return None
    user = row.to_user()
    if row.source == "local":
        current = users.get_by_username(row.username)
        if current is None or current.session_stamp != row.session_stamp:
            sessions.delete(sid)
            return None
        user = current.to_user()
    sessions.touch(sid, now)
    return user


def end(sessions, ticket: str) -> None:
    sessions.delete(ticket_id(ticket))


def end_all_for(sessions, username: str) -> int:
    return sessions.delete_for_user(username)
```

- [ ] **Step 4: Run to verify they pass**

Run: same as Step 2. Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/seqsetup/services/web_sessions.py tests/unit/test_web_session_policy.py
git commit -m "feat(sessions): login rules — idle limit, hard cap, database-user stamp"
```

---

### Task 4: The app uses the login list (middleware, login, logout)

**Files:**
- Modify: `src/seqsetup/middleware.py` (resolve the ticket)
- Modify: `src/seqsetup/routes/auth.py` (`_login_user`, `GET /login`, `POST /logout`)
- Modify: `src/seqsetup/app.py` (policy, `SessionMiddleware(max_age=...)`, comment)
- Modify: `tests/unit/test_auth_session_fixation.py`, `tests/unit/test_auth_routes.py`
- Test: `tests/integration/test_session_revocation.py` (new; N-02, N-19, HTMX, 503, old cookie)

**Interfaces:**
- Consumes: Task 3 functions; `startup.get_web_session_repo()`, `startup.get_local_user_repo()`.
- Produces: `routes.auth._login_user(sess, user, sessions, now, policy) -> None` (sets `sess["sid"]`); `middleware.ENDED_LOGIN_MESSAGE_HTML`.

- [ ] **Step 1: Write the failing tests**

Replace the bodies of `tests/unit/test_auth_session_fixation.py` and `tests/unit/test_auth_routes.py` so they call the new signature. `test_auth_session_fixation.py`:

```python
"""Unit test for _login_user's session-fixation defense.

The defense: _login_user() calls sess.clear() before recording the new
login. Without the clear, an attacker who plants a known session on a
shared workstation would keep any keys they placed in it after a
legitimate user logs in.
"""

from datetime import datetime

import mongomock

from seqsetup.models.user import User, UserRole
from seqsetup.repositories.web_session_repo import WebSessionRepository
from seqsetup.routes.auth import _login_user
from seqsetup.services.web_sessions import SessionPolicy

NOW = datetime(2026, 9, 27, 8, 0, 0)
POLICY = SessionPolicy(1800, 28800)


def _user(name):
    return User(username=name, display_name=name, role=UserRole.ADMIN, source="yaml")


def _sessions():
    return WebSessionRepository(mongomock.MongoClient()["t"])


def test_login_user_clears_pre_planted_session_keys():
    """_login_user wipes any pre-existing session keys."""
    sess = {"attacker_planted_key": "evil_value", "csrf_token": "stale_token",
            "sid": "planted-ticket"}
    _login_user(sess, _user("alice"), _sessions(), NOW, POLICY)
    assert set(sess) == {"sid"} and sess["sid"] != "planted-ticket"


def test_login_user_starts_from_empty_session_correctly():
    """_login_user works correctly when there's nothing to clear."""
    sess = {}
    _login_user(sess, _user("bob"), _sessions(), NOW, POLICY)
    assert set(sess) == {"sid"}
```

`test_auth_routes.py`:

```python
"""Tests for the authentication route helpers (separate from AuthService)."""

from datetime import datetime

import mongomock

from seqsetup.models.user import User, UserRole
from seqsetup.repositories.web_session_repo import WebSessionRepository
from seqsetup.routes.auth import _login_user
from seqsetup.services import web_sessions
from seqsetup.services.web_sessions import SessionPolicy

NOW = datetime(2026, 9, 27, 8, 0, 0)
POLICY = SessionPolicy(1800, 28800)


class TestLoginUserSessionFixationDefence:
    """The login helper must regenerate the session contents before applying
    the authenticated user, so an attacker-planted session cannot ride a
    legitimate login on a shared workstation.
    """

    def _repo(self):
        return WebSessionRepository(mongomock.MongoClient()["t"])

    def _user(self, name, role=UserRole.STANDARD):
        return User(username=name, display_name=name, role=role, source="yaml")

    def test_login_clears_prior_session_data(self):
        sess: dict = {"attacker_planted_key": "malicious_value"}
        _login_user(sess, self._user("alice"), self._repo(), NOW, POLICY)
        assert "attacker_planted_key" not in sess

    def test_login_records_the_user_server_side(self):
        sess: dict = {}
        repo = self._repo()
        _login_user(sess, self._user("alice", UserRole.ADMIN), repo, NOW, POLICY)
        user = web_sessions.resolve(repo, None, sess["sid"], NOW, POLICY)
        assert (user.username, user.role) == ("alice", UserRole.ADMIN)

    def test_each_login_gets_a_new_ticket(self):
        repo = self._repo()
        a, b = {}, {}
        _login_user(a, self._user("alice"), repo, NOW, POLICY)
        _login_user(b, self._user("alice"), repo, NOW, POLICY)
        assert a["sid"] != b["sid"]
```

`tests/integration/test_session_revocation.py` (first part; Task 5 appends):

```python
"""Logins live server-side: logout, idle and age limits, and database-user
changes end them (security audit N-02, N-03, N-04, N-19)."""

from datetime import timedelta

import pytest
from starlette.testclient import TestClient

from seqsetup.models.sequencing_run import SequencingRun
from seqsetup.services import web_sessions

ORIGIN = {"Origin": "http://testserver"}


def _login(app, creds):
    c = TestClient(app, base_url="http://testserver")
    r = c.post("/login/submit", data=creds, headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"
    return c


def _copy(client, app):
    """A second client holding the same cookie (a copied cookie)."""
    c = TestClient(app, base_url="http://testserver")
    c.cookies.set("seqsetup_session", client.cookies.get("seqsetup_session"))
    return c


def _get(c, path, **kw):
    return c.get(path, follow_redirects=False, **kw)


@pytest.fixture
def clock(monkeypatch):
    """Move the login clock forward: clock.advance(minutes=31)."""
    class _Clock:
        now = web_sessions.utcnow()
        def advance(self, **kw):
            self.now += timedelta(**kw)
    c = _Clock()
    monkeypatch.setattr(web_sessions, "utcnow", lambda: c.now)
    return c


class TestLogout:
    """N-02: logout ends that login, everywhere it was copied."""

    def test_copied_cookie_is_refused_after_logout(self, fresh_app, admin_user_seeded):
        app, _ctx, _db = fresh_app
        c = _login(app, admin_user_seeded)
        thief = _copy(c, app)
        assert _get(thief, "/admin/users").status_code == 200
        c.post("/logout", headers=ORIGIN, follow_redirects=False)
        r = _get(thief, "/admin/users")
        assert (r.status_code, r.headers["location"]) == (303, "/login")

    def test_other_browser_of_same_user_stays(self, fresh_app, admin_user_seeded):
        app, _ctx, _db = fresh_app
        a, b = _login(app, admin_user_seeded), _login(app, admin_user_seeded)
        a.post("/logout", headers=ORIGIN, follow_redirects=False)
        assert _get(b, "/admin/users").status_code == 200


class TestLimits:
    """N-19: 30 minutes unused, 8 hours in all."""

    def test_idle_31_minutes_is_refused(self, fresh_app, admin_user_seeded, clock):
        app, _ctx, _db = fresh_app
        c = _login(app, admin_user_seeded)
        clock.advance(minutes=29)
        assert _get(c, "/").status_code == 200
        clock.advance(minutes=31)
        assert _get(c, "/").status_code == 303

    def test_active_login_ends_after_8_hours(self, fresh_app, admin_user_seeded, clock):
        app, _ctx, _db = fresh_app
        c = _login(app, admin_user_seeded)
        for _ in range(16):
            clock.advance(minutes=29)
            assert _get(c, "/").status_code == 200
        clock.advance(minutes=17)                   # 8 h 01 min
        assert _get(c, "/").status_code == 303


class TestEndedLoginResponses:
    """How an ended login is answered."""

    def test_htmx_request_keeps_the_page(self, fresh_app, admin_user_seeded):
        app, ctx, _db = fresh_app
        c = _login(app, admin_user_seeded)
        ctx.web_session_repo.delete_for_user("admin-test")
        r = c.post("/runs/new", headers={**ORIGIN, "HX-Request": "true"},
                   follow_redirects=False)
        assert r.status_code == 401
        assert r.headers["HX-Retarget"] == "#error-banner"
        assert r.headers["HX-Reswap"] == "innerHTML"
        assert "Your login has ended, so this was not saved." in r.text
        assert '<a href="/login" target="_blank" rel="noopener">Log in again</a>' in r.text

    def test_database_error_is_503_never_200(self, fresh_app, admin_user_seeded, monkeypatch):
        app, ctx, _db = fresh_app
        c = _login(app, admin_user_seeded)
        def boom(*a, **k):
            raise ConnectionError("db down")
        monkeypatch.setattr(ctx.web_session_repo, "get", boom)
        assert _get(c, "/").status_code == 503

    def test_old_style_cookie_is_refused(self, fresh_app):
        app, _ctx, _db = fresh_app
        from itsdangerous import TimestampSigner
        import base64, json
        payload = base64.b64encode(json.dumps({"user": {
            "username": "admin-test", "display_name": "x", "role": "admin",
            "email": None}}).encode())
        cookie = TimestampSigner("x" * 64).sign(payload).decode()
        c = TestClient(app, base_url="http://testserver")
        c.cookies.set("seqsetup_session", cookie)
        assert _get(c, "/").headers.get("location") == "/login"
```

- [ ] **Step 2: Run to verify they fail**

Run: `PYTHONPATH=src $PY -m pytest tests/unit/test_auth_session_fixation.py tests/unit/test_auth_routes.py tests/integration/test_session_revocation.py -q -p no:cacheprovider`
Expected: FAIL (`_login_user()` signature; copied cookie still 200; no 401).

- [ ] **Step 3: Implement**

`routes/auth.py`:

```python
from .. import startup
from ..services import web_sessions
```

```python
def _login_user(sess, user, sessions, now, policy) -> None:
    """Record the login server-side and put only its ticket in the cookie.

    Clears any prior session contents first to defeat session fixation:
    an attacker who plants a known session on a shared workstation must not
    retain it after a legitimate user logs in.
    """
    sess.clear()
    sess["sid"] = web_sessions.start(sessions, user, now, policy)
```

`login_page`:

```python
        sid = request.session.get("sid")
        if sid:
            try:
                live = web_sessions.resolve(
                    startup.get_web_session_repo(), startup.get_local_user_repo(),
                    sid, web_sessions.utcnow(), web_sessions.current_policy())
            except Exception:
                live = None
            if live is not None:
                return RedirectResponse("/", status_code=303)
        return render(request, "login.html", {"error_message": ""})
```

`login_submit` success branch:

```python
            user = auth_service.authenticate(username, password)
            _login_user(sess, user, startup.get_web_session_repo(),
                        web_sessions.utcnow(), web_sessions.current_policy())
```

`logout`:

```python
        sess = request.session
        actor = get_username(request)[:128]
        sid = sess.get("sid")
        if sid:
            web_sessions.end(startup.get_web_session_repo(), sid)
        sess.clear()
        audit("logout", actor=actor)
        return RedirectResponse("/login", status_code=303)
```

(import `get_username` from `.utils`).

`middleware.py` — replace the "Session-backed HTML routes" block:

```python
from starlette.concurrency import run_in_threadpool
from starlette.responses import HTMLResponse, PlainTextResponse, RedirectResponse

from . import startup
from .services import web_sessions

# Shown in the page's error banner when a background (HTMX) action meets an
# ended login. The page is kept, so what the user typed is not lost.
ENDED_LOGIN_MESSAGE_HTML = (
    '<div class="error-message">Your login has ended, so this was not saved. '
    'What you typed is still on this page. '
    '<a href="/login" target="_blank" rel="noopener">Log in again</a> '
    'in a new tab, then try again here.</div>'
)


def _is_htmx(request: Request) -> bool:
    return request.headers.get("HX-Request", "").lower() == "true"


def _banner(body: str, status: int) -> HTMLResponse:
    return HTMLResponse(body, status_code=status, headers={
        "HX-Retarget": "#error-banner", "HX-Reswap": "innerHTML",
        "Cache-Control": "no-store"})


def _resolve(ticket: str):
    return web_sessions.resolve(
        startup.get_web_session_repo(), startup.get_local_user_repo(), ticket,
        web_sessions.utcnow(), web_sessions.current_policy())
```

```python
        # Session-backed HTML routes: the cookie holds only a ticket; the
        # login itself lives server-side (services/web_sessions.py).
        try:
            sess = request.session
        except AssertionError:
            sess = {}

        ticket = sess.get("sid")
        try:
            user = await run_in_threadpool(_resolve, ticket) if ticket else None
        except Exception:
            logger.exception("Login check failed: database unavailable")
            if _is_htmx(request):
                return _banner('<div class="error-message">Database unavailable.</div>', 503)
            return PlainTextResponse("Database unavailable", status_code=503)

        if user is None:
            sess.clear()
            if _is_htmx(request):
                return _banner(ENDED_LOGIN_MESSAGE_HTML, 401)
            return RedirectResponse("/login", status_code=303)

        request.scope["auth"] = user
        return await call_next(request)
```

(add `import logging` / `logger = logging.getLogger(__name__)`; drop the now-unused `User` import.)

`app.py`: import `from .services import web_sessions`; replace the `_SESSION_MAX_AGE` block and comment with:

```python
# Logins live server-side (services/web_sessions.py): 30 minutes unused or
# 8 hours after login ends them, whatever the cookie says. The cookie's own
# max_age is set to the same hard cap so browsers drop it too.
# SEQSETUP_SESSION_IDLE_SECONDS / SEQSETUP_SESSION_MAX_AGE_SECONDS override.
_SESSION_POLICY = web_sessions.SessionPolicy.from_env()
web_sessions.set_policy(_SESSION_POLICY)
```

and `max_age=_SESSION_POLICY.max_age_seconds` in `SessionMiddleware`.

- [ ] **Step 4: Run to verify they pass, then the auth-related suites**

Run: `PYTHONPATH=src $PY -m pytest tests/unit/test_auth_session_fixation.py tests/unit/test_auth_routes.py tests/integration/test_session_revocation.py tests/integration -k "auth or login or logout or session or csrf" -q -p no:cacheprovider`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/seqsetup/middleware.py src/seqsetup/routes/auth.py src/seqsetup/app.py tests/unit/test_auth_session_fixation.py tests/unit/test_auth_routes.py tests/integration/test_session_revocation.py
git commit -m "fix(auth): logins are checked server-side; logout ends them (N-02, N-19)"
```

---

### Task 5: Deleting or changing a database user ends their logins

**Files:**
- Modify: `src/seqsetup/routes/local_users.py` (`edit_user`, `delete_user`)
- Test: append to `tests/integration/test_session_revocation.py`

**Interfaces:**
- Consumes: `web_sessions.end_all_for`, `ctx.web_session_repo`, Task 1 stamp rotation.

- [ ] **Step 1: Write the failing tests** (append):

```python
from seqsetup.models.user import UserRole


def _admin_edit(admin, username, **fields):
    data = {"display_name": fields.get("display_name", username),
            "email": fields.get("email", ""), "role": fields.get("role", "standard"),
            "password": fields.get("password", "")}
    return admin.post(f"/admin/users/{username}/edit", data=data, headers=ORIGIN)


@pytest.fixture
def two_admins(fresh_app, admin_user_seeded):
    """admin-test (acting) and target-admin (the one changed)."""
    app, ctx, _db = fresh_app
    from seqsetup.models.local_user import LocalUser
    u = LocalUser(username="target-admin", display_name="Target", role=UserRole.ADMIN)
    u.set_password("Target-Adm1n!")
    ctx.local_user_repo.save(u)
    target = {"username": "target-admin", "password": "Target-Adm1n!"}
    return app, ctx, _login(app, admin_user_seeded), target


class TestAccountChangesEndLogins:
    """N-03, N-04, and password reset."""

    def test_deleted_user_is_refused(self, two_admins):
        app, ctx, admin, target = two_admins
        victim = _login(app, target)
        r = admin.delete("/admin/users/target-admin", headers=ORIGIN)
        assert "Their open logins were ended." in r.text
        assert _get(victim, "/").status_code == 303

    def test_demoted_admin_is_refused_and_relogin_is_standard(self, two_admins):
        app, ctx, admin, target = two_admins
        victim = _login(app, target)
        r = _admin_edit(admin, "target-admin", role="standard")
        assert "Their open logins were ended." in r.text
        assert _get(victim, "/admin/users").status_code == 303
        again = _login(app, target)
        assert _get(again, "/admin/users").status_code == 403
        assert again.post("/admin/api-tokens/create", data={"name": "x"},
                          headers=ORIGIN).status_code == 403

    def test_password_reset_ends_logins(self, two_admins):
        app, ctx, admin, target = two_admins
        victim = _login(app, target)
        _admin_edit(admin, "target-admin", role="admin", password="Brand-N3w-Pass!")
        assert _get(victim, "/").status_code == 303

    def test_name_only_edit_keeps_logins(self, two_admins):
        app, ctx, admin, target = two_admins
        victim = _login(app, target)
        r = _admin_edit(admin, "target-admin", role="admin", display_name="Renamed")
        assert "Their open logins were ended." not in r.text
        assert _get(victim, "/").status_code == 200

    def test_audit_records_the_ending(self, two_admins):
        app, ctx, admin, target = two_admins
        _login(app, target)
        admin.delete("/admin/users/target-admin", headers=ORIGIN)
        (ev,) = ctx.audit_event_repo.search(limit=1, event_prefix="user.deleted")
        assert ev.details["sessions_ended"] is True
        assert ev.details["session_rows_removed"] == 1


class TestRaceWithLogin:
    """Review 1: a login checked just before the change is still refused."""

    @pytest.mark.parametrize("change", ["delete", "demote", "password"])
    def test_login_racing_a_change(self, two_admins, monkeypatch, change):
        app, ctx, admin, target = two_admins
        import seqsetup.startup as startup_module
        auth_service = startup_module._auth_service
        real = auth_service.authenticate

        def racing(username, password):
            user = real(username, password)          # password checked, old record read
            if change == "delete":
                admin.delete("/admin/users/target-admin", headers=ORIGIN)
            elif change == "demote":
                _admin_edit(admin, "target-admin", role="standard")
            else:
                _admin_edit(admin, "target-admin", role="admin", password="Brand-N3w-Pass!")
            return user

        monkeypatch.setattr(auth_service, "authenticate", racing)
        late = _login(app, target)
        assert _get(late, "/admin/users").status_code == 303


class TestCleanupFailure:
    """Review 2: if deleting rows fails, the logins are still refused."""

    @pytest.mark.parametrize("change", ["delete", "demote", "password"])
    def test_refused_even_when_cleanup_fails(self, two_admins, monkeypatch, change):
        app, ctx, admin, target = two_admins
        victim = _login(app, target)
        def boom(*a, **k):
            raise ConnectionError("db hiccup")
        monkeypatch.setattr(ctx.web_session_repo, "delete_for_user", boom)
        if change == "delete":
            r = admin.delete("/admin/users/target-admin", headers=ORIGIN)
        elif change == "demote":
            r = _admin_edit(admin, "target-admin", role="standard")
        else:
            r = _admin_edit(admin, "target-admin", role="admin", password="Brand-N3w-Pass!")
        assert r.status_code == 200 and "Their open logins were ended." in r.text
        assert _get(victim, "/").status_code == 303

    def test_repeated_demotion_leaves_them_refused(self, two_admins, monkeypatch):
        app, ctx, admin, target = two_admins
        victim = _login(app, target)
        monkeypatch.setattr(ctx.web_session_repo, "delete_for_user",
                            lambda *a, **k: (_ for _ in ()).throw(ConnectionError()))
        _admin_edit(admin, "target-admin", role="standard")
        _admin_edit(admin, "target-admin", role="standard")
        assert _get(victim, "/").status_code == 303
```

Note: the fixtures' `admin.post(...)` default `follow_redirects` is fine (HTMX fragment responses are 200). `/admin/api-tokens/create` form fields: check `routes/api_tokens.py` for the exact field name before running; use a valid body so a 403 cannot be a 422.

- [ ] **Step 2: Run to verify they fail**

Run: `PYTHONPATH=src $PY -m pytest tests/integration/test_session_revocation.py -q -p no:cacheprovider`
Expected: the new tests FAIL on the message text; the refusal tests already PASS via the stamp (Task 1 + 3 do the revocation) — that is expected and is itself the review-2 guarantee.

- [ ] **Step 3: Implement** in `routes/local_users.py`:

```python
import logging

from ..services import web_sessions

logger = logging.getLogger(__name__)


def _clean_up_logins(ctx, username: str):
    """Remove the user's login rows. The account write already ended them
    (session stamp changed, or the record is gone), so a failure here is
    logged, not fatal. Returns the number removed, or None on failure."""
    try:
        return web_sessions.end_all_for(ctx.web_session_repo, username)
    except Exception:
        logger.warning("Could not remove login rows for %s", username, exc_info=True)
        return None
```

`edit_user`, after `repo.save(user)`:

```python
    logins_ended = form.role != previous_role or password_changed
    removed = _clean_up_logins(ctx, username) if logins_ended else 0
    extra = {"sessions_ended": True, "session_rows_removed": removed} if logins_ended else {}
    audit(
        "user.updated",
        actor=get_username(request),
        target=username,
        from_role=previous_role.value,
        to_role=form.role.value,
        password_changed=password_changed,
        **extra,
    )
    message = f"User '{username}' updated."
    if logins_ended:
        message += " Their open logins were ended."
    return _render_page(request, ctx, message=message)
```

`delete_user`, after `repo.delete(username)`:

```python
    removed = _clean_up_logins(ctx, username)
    audit(
        "user.deleted",
        actor=get_username(request),
        target=username,
        deleted_role=deleted_role,
        sessions_ended=True,
        session_rows_removed=removed,
    )
    return _render_page(request, ctx,
                        message=f"User '{username}' deleted. Their open logins were ended.")
```

Existing message tests: grep `tests/` for `updated successfully` and `' deleted.` and update the expected text where the change now differs (edit without role/password change now reads `User 'x' updated.`; it was `updated successfully.`). That wording change is visible — list it in the final report.

- [ ] **Step 4: Run to verify they pass, plus the user-admin tests**

Run: `PYTHONPATH=src $PY -m pytest tests/integration/test_session_revocation.py tests/integration -k "user" -q -p no:cacheprovider`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/seqsetup/routes/local_users.py tests/integration/test_session_revocation.py <any message-test files updated>
git commit -m "fix(auth): deleting a user or changing their role or password ends their logins (N-03, N-04)"
```

---

### Task 6: Browser check and docs

**Files:**
- Create: `tests/browser/test_ended_login.py`
- Modify: `docs/getting-started/configuration.rst` (the two variables)

- [ ] **Step 1: Write the browser test**

```python
"""An ended login during a background action keeps the page and the typed
text; after logging in again in another tab, the same action works."""

import pytest
from playwright.sync_api import expect


@pytest.mark.browser
def test_paste_survives_an_ended_login(logged_in_page, base_url, admin_creds, app_ctx, mutable_run_id):
    page = logged_in_page
    page.goto(f"{base_url}/runs/{mutable_run_id}")
    page.wait_for_load_state("networkidle")
    page.click("summary.paste-section-summary")
    page.fill("#paste_data", "LATE-01,WGS\nLATE-02,WGS")
    url = page.url

    app_ctx.web_session_repo.delete_for_user(admin_creds["username"])
    with page.expect_response(lambda r: r.url.endswith("/samples/preview") and r.status == 401):
        page.click(".paste-form button[type=submit]")

    expect(page.locator("#error-banner")).to_contain_text("Your login has ended")
    expect(page.locator("#paste_data")).to_have_value("LATE-01,WGS\nLATE-02,WGS")
    assert page.url == url

    other = page.context.new_page()
    other.goto(f"{base_url}/login")
    other.fill('input[name="username"]', admin_creds["username"])
    other.fill('input[name="password"]', admin_creds["password"])
    other.click('button[type="submit"]')
    other.wait_for_url(f"{base_url}/")
    other.close()

    with page.expect_response(lambda r: r.url.endswith("/samples/preview") and r.status == 200):
        page.click(".paste-form button[type=submit]")
    page.click("text=Add 2 samples")
    ids = {s.sample_id for s in app_ctx.run_repo.get_by_id(mutable_run_id).samples}
    assert {"LATE-01", "LATE-02"} <= ids
```

- [ ] **Step 2: Build CSS and run it** (it must pass with Tasks 1–5 in place; if the 401 banner does not show, the HX-Retarget path in `static/js/app.js` is not being hit — investigate, do not change the test)

Run: `/home/parlar_ai/dev/seqsetup/.pixi/bin/tailwindcss -i src/seqsetup/static/css/input.css -o src/seqsetup/static/css/app.css --minify && PYTHONPATH=src $PY -m pytest tests/browser/test_ended_login.py -q -p no:cacheprovider`
Expected: PASS.

- [ ] **Step 3: Docs** — in `docs/getting-started/configuration.rst`, add two rows to the environment-variable table next to `SEQSETUP_SESSION_SECRET`, in the table's existing format:
  - `SEQSETUP_SESSION_IDLE_SECONDS` — "A login unused for this many seconds ends. Default 1800 (30 minutes). Allowed 60 up to the maximum age."
  - `SEQSETUP_SESSION_MAX_AGE_SECONDS` — "Every login ends this many seconds after it began, even while in use. Default 28800 (8 hours). Allowed 300–86400."

- [ ] **Step 4: Commit**

```bash
git add tests/browser/test_ended_login.py docs/getting-started/configuration.rst
git commit -m "test(browser): typed text survives an ended login; document the login limits"
```

---

### Final: verify

- [ ] Full server suite: `PYTHONPATH=src $PY -m pytest tests/unit tests/integration -q -p no:cacheprovider` — expect 1707 + new tests, 0 failed, 0 errors.
- [ ] Browser suite: `PYTHONPATH=src $PY -m pytest tests/browser -q -p no:cacheprovider -m browser --deselect tests/browser/test_screenshots.py` (screenshot baselines are known stale) — expect 87 + 1.
- [ ] Audit proofs, from a copy of `.worktrees/sec-audit/tests/integration/security_proofs/` run against this branch's `src`: `test_e_session_revocation.py`, `test_i_logout_cookie_replay.py`, `test_e_session_cookie_flags.py::TestSessionExpirySemantics` must now FAIL (problem gone).
- [ ] Break tests in a scratch copy, one at a time, restore with `cp` and check with `cmp`:
  skip the row lookup (return the row's user without checking it exists) · skip the idle check · skip the age check · skip the stamp check · `set_password` does not rotate · role `__setattr__` does not rotate · `_clean_up_logins` does nothing (expect ONLY the message/audit tests to fail, not the refusal tests) · `ticket_id` returns the ticket · touch only when a minute has passed.
- [ ] Independent review of the diff against the spec.
