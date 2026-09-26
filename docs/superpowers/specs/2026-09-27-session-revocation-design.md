# Server-side sessions: logout, delete and demote end logins

Date: 2026-09-27. Branch `fix/session-revocation` from main `22f6059`.
Security audit findings N-02, N-03, N-04, N-19
(`/home/parlar_ai/seqsetup-audit-run/FINDINGS.md`).

## Problem

A login is a signed cookie (Starlette `SessionMiddleware`) that carries the whole
user, role included (`routes/auth.py:_login_user` → `sess["user"] = user.to_dict()`).
`AuthMiddleware` trusts that payload (`User.from_dict(sess["user"])`) and never asks
the server. The server keeps no list of logins, so it cannot take one back:

- **N-02** — after `POST /logout`, a copy of the cookie still works (measured: 200 on
  a run page and on `/admin/users`).
- **N-04** — after `DELETE /admin/users/{name}`, that user's open browser still reads
  and writes runs.
- **N-03** — after an admin is demoted, their open session keeps `/admin/*` and can
  mint an API token. `require_admin_dep` reads the stale role from the cookie.
- **N-19** — the only expiry is itsdangerous `max_age` (8 h), counted from the last
  re-signing, and the cookie is re-signed on every response. A browser in use never
  logs out, and the idle window is 8 hours. The comment in `app.py` ("operators who
  walk away for lunch will re-auth on return") is false.

Users come from three places: MongoDB (`local_user_repo`, managed on
`/admin/users`), `users.yaml`, and LDAP. The fix must work for all three.

## Decisions (approved by the user, 2026-09-27)

1. **Server-side login list** (option A). Rejected: a per-user version number on
   `LocalUser` — it cannot cover `users.yaml` or LDAP users, and a logout would end the
   user's logins in every browser.
2. **Idle timeout 30 minutes; hard cap 8 hours from login.** Both configurable.
3. Logout ends **that** login. Deleting a user, or changing their **role** or
   **password**, ends **all** their logins. Changing only display name or email does not.
4. Database unreachable while checking a login → refuse (503). Never let a request
   through on a guess.

## Components

### 1. `models/web_session.py` — `WebSession`

Dataclass, one row per login:

| field | meaning |
|---|---|
| `id` | SHA-256 hex of the ticket (the cookie holds the ticket, the DB only this) |
| `username`, `display_name`, `email` | the user at login |
| `role` | `UserRole` at login |
| `created_at` | login time, UTC |
| `last_seen_at` | last page load that touched the row, UTC |

- `to_dict()` / `from_dict()` (`_id` = `id`); `to_user()` returns the `User`.
- Text fields are capped in `__setattr__` (username, display name, email 256) per the
  hard rule "bound every string at the model boundary".
- Datetimes are stored as UTC. Values read back from MongoDB without a timezone are
  treated as UTC.

### 2. `repositories/web_session_repo.py` — `WebSessionRepository`

Collection `web_sessions`. Thin, no rules:

- `create(ws)`, `get(id) -> WebSession | None`, `touch(id, when)`,
  `delete(id)`, `delete_for_user(username) -> int`,
  `delete_expired(*, seen_before, created_before) -> int` (removes rows with
  `last_seen_at < seen_before` OR `created_at < created_before`).
- Indexes: `username`, `last_seen_at`, `created_at`.
- Registered in `startup._REPO_REGISTRY` as `"web_session"`, with
  `get_web_session_repo()`, and on `AppContext` as `web_session_repo`.

### 3. `services/web_sessions.py` — the rules

- `SessionPolicy(idle_seconds, max_age_seconds)`, read once from the environment:
  - `SEQSETUP_SESSION_MAX_AGE_SECONDS` — hard cap from login. Default `28800` (8 h).
    Existing variable; its meaning changes from "sliding window" to "hard cap".
  - `SEQSETUP_SESSION_IDLE_SECONDS` — new. Default `1800` (30 min).
  - Clamped: `max_age` to `[300, 86400]`; `idle` to `[60, max_age]`. A clamped value
    logs a WARNING naming the variable, the given value and the value used. A value
    that is not an integer is refused at startup (`ValueError`), not silently replaced.
- `new_ticket() -> str`: `secrets.token_urlsafe(32)`.
- `ticket_id(ticket) -> str`: SHA-256 hex.
- `start(repo, user, now) -> ticket`: first `delete_expired(...)`, then `create` a row.
- `resolve(repo, ticket, now) -> User | None`:
  - no row → `None`;
  - `now - last_seen_at > idle` or `now - created_at > max_age` → `delete` the row,
    `None`;
  - otherwise, if `now - last_seen_at >= 60 s`, `touch(id, now)` (so the DB is written
    at most once a minute per login; the real idle limit is therefore between 30 and
    31 minutes); return `to_user()`.
- `end(repo, ticket)`, `end_all_for(repo, username) -> int`.

### 4. `middleware.py` — `AuthMiddleware`

- Reads `sess.get("sid")`. No ticket → not logged in.
- Calls `resolve` through `starlette.concurrency.run_in_threadpool` (a pymongo call
  must not block the event loop). The repo comes from `startup.get_web_session_repo()`.
- `None` → `sess.clear()`, then:
  - normal request → `303 /login` (as today);
  - HTMX request (`HX-Request: true`) → `401` with header `HX-Redirect: /login`, so
    the whole page goes to the login page instead of the login form being swapped
    into a table cell.
- A database error, or no repo → `503` "Database unavailable", `sess` untouched.
- A valid ticket → `request.scope["auth"] = user`, as today.
- The old `sess["user"]` payload is no longer read or written. Old cookies have no
  `sid`, so they are sent to `/login`. (Not deployed yet, so nobody is affected.)

### 5. `routes/auth.py`

- `_login_user(sess, user, repo, now)`: `sess.clear()` (fixation defence kept), then
  `sess["sid"] = start(repo, user, now)`.
- `GET /login`: redirect to `/` only when `sess["sid"]` resolves to a live login.
- `POST /logout`: the actor comes from `request.scope["auth"]` (set by the middleware);
  `end(repo, sid)`, then `sess.clear()`. Audit `logout` as today.
- The repo comes from `startup.get_web_session_repo()` (the router has no
  `AppContext`; `make_router(auth_service)` keeps its signature).

### 6. `routes/local_users.py`

- `edit_user`: after `repo.save(user)`, if the role changed or a password was set,
  `n = end_all_for(ctx.web_session_repo, username)`. The message becomes
  `User 'x' updated. Their open logins were ended (n).` when `n > 0`. Audit
  `user.updated` gains `sessions_ended=n`.
- `delete_user`: after `repo.delete`, `n = end_all_for(...)`. Message
  `User 'x' deleted. Their open logins were ended (n).` when `n > 0`. Audit
  `user.deleted` gains `sessions_ended=n`.
- An admin who demotes themself is logged out on their next click. That is the
  intended outcome.

### 7. `app.py` and docs

- `SessionMiddleware(max_age=policy.max_age_seconds)`; the false "lunch" comment is
  replaced with what is true now.
- `docs/getting-started/configuration.rst`: document both variables.

## Behaviour changes users will see

- A browser unused for 30 minutes goes to the login page on the next click.
- Everyone logs in again 8 hours after logging in, even while working.
- A deleted, demoted, promoted or password-reset user is sent to the login page on
  their next click. The admin's success message says their logins were ended.
- An expired login during a background (HTMX) action sends the whole page to login.

Nothing typed is lost: run edits are saved as they are made.

## Known limits (not in this change)

- A user disabled in LDAP, or removed from `users.yaml`, keeps an open login until it
  times out (at most 30 minutes unused, 8 hours in all). The app cannot see those
  changes.
- No "who is logged in" admin page and no "log out everywhere" button.
- One more small DB read per page load (by `_id`), and at most one write per minute
  per login.

## Testing (tests first)

- `tests/unit/test_web_session_model.py` — round trip, caps, UTC handling.
- `tests/integration/test_web_session_repo.py` — each method; `delete_for_user`
  leaves other users' rows; `delete_expired` both conditions; indexes exist.
- `tests/unit/test_web_session_policy.py` — defaults, env overrides, clamps,
  non-integer refused; `resolve` at 29:59 / 30:01 idle and 7:59 / 8:01 age (injected
  `now`); touch throttle (no write under 60 s, a write at 60 s); DB stores
  `ticket_id`, never the ticket.
- `tests/integration/test_session_revocation.py` — through the real app:
  - N-02: a cookie copied before logout gets `303 /login` after logout; a second
    browser of the same user stays logged in;
  - N-04: deleted user's cookie → `303 /login`; message and audit show
    `sessions_ended`;
  - N-03: demoted admin's cookie → `303 /login`; a fresh login gets `403` on
    `/admin/users` and cannot create an API token;
  - password change ends logins; a display-name-only edit does not;
  - N-19: idle 31 min → refused; 8 h 01 min after login while active → refused;
  - HTMX request with a dead login → `401` + `HX-Redirect: /login`;
  - DB error during the check → `503`, never `200`;
  - an old-style cookie holding only `sess["user"]` → `303 /login`.
- Update `tests/unit/test_auth_session_fixation.py` and `tests/unit/test_auth_routes.py`
  for the new `_login_user`: pre-planted keys are still wiped; a new ticket per login.
- Browser suite: a login, a click, a logout still work end to end; a new browser
  test ends the login server-side, clicks an HTMX control, and checks the whole page
  is now `/login`.
- Audit proofs `test_e_session_revocation.py`, `test_i_logout_cookie_replay.py` and
  `test_e_session_cookie_flags.py::TestSessionExpirySemantics` must now fail (the
  problem is gone), run from a copy.
- Break tests in a copy: skip the lookup, skip the idle check, skip the age check,
  skip `end_all_for` in delete / edit, store the raw ticket — each must redden the
  right test.
