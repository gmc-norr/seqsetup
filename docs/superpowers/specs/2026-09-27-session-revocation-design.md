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
   `LocalUser` *alone* — it cannot cover `users.yaml` or LDAP users, and a logout
   would end the user's logins in every browser. (A per-user stamp is still used, in
   addition, to make revocation of database users durable; see decision 3.)
2. **Idle timeout 30 minutes; hard cap 8 hours from login.** Both configurable.
3. Logout ends **that** login. Deleting a database user, or changing their **role**
   or **password**, ends **all** their logins. Changing only display name or email
   does not. For database users this is carried by the user record itself (a
   `session_stamp` that changes with the role or password, and disappears with the
   record), so it takes effect in the same single write as the account change and
   cannot be lost or raced. Deleting the login rows afterwards is only cleanup.
4. Database unreachable while checking a login → refuse (503). Never let a request
   through on a guess.
5. A background (HTMX) action that meets an ended login **keeps the page** and shows
   a message in the page's error banner, so typed input is not lost. (Revised after
   review: the first draft sent the whole page to `/login`, which would throw away
   unsaved input such as a paste not yet added.)

## Components

### 1. `models/user.py` and `models/local_user.py`

- `User` gains `source: str = ""` (`"local"`, `"yaml"` or `"ldap"`) and
  `session_stamp: str = ""`. They say where this login came from; nothing else reads
  them. `User.to_dict()` / `from_dict()` are unchanged.
- `LocalUser` gains `session_stamp: str`:
  - a new `LocalUser(...)` gets a random one (`secrets.token_hex(16)`);
  - `from_dict` reads the stored value, or `""` if absent (never a fresh random
    value, which would change on every read);
  - `to_dict` writes it;
  - **it changes whenever the password or the role changes**, at the model layer so
    no route can forget it: `set_password()` sets a new stamp, and `__setattr__`
    sets a new stamp when `role` is assigned a *different* value after
    construction;
  - `to_user()` returns `User(..., source="local", session_stamp=self.session_stamp)`.
- `services/auth.py`: the `users.yaml` branch builds `User(..., source="yaml")`;
  `_authenticate_ldap` returns the LDAP user with `source="ldap"`
  (`dataclasses.replace`).

The stamp is read from the **same record** whose password was checked, so a login
that is checked just before an admin changes the account carries the old stamp and
is refused on its first request (review finding 1).

### 2. `models/web_session.py` — `WebSession`

Dataclass, one row per login:

| field | meaning |
|---|---|
| `id` | SHA-256 hex of the ticket (the cookie holds the ticket, the DB only this) |
| `username`, `display_name`, `email` | the user at login |
| `role` | `UserRole` at login |
| `source` | `"local"`, `"yaml"` or `"ldap"` |
| `session_stamp` | the database user's stamp at login (`""` for yaml / ldap) |
| `created_at` | login time, UTC |
| `last_seen_at` | last request on this login, UTC |

- `to_dict()` / `from_dict()` (`_id` = `id`).
- Text fields are capped in `__setattr__` (username, display name, email 256) per the
  hard rule "bound every string at the model boundary".
- Datetimes are stored as UTC. Values read back from MongoDB without a timezone are
  treated as UTC.

### 3. `repositories/web_session_repo.py` — `WebSessionRepository`

Collection `web_sessions`. Thin, no rules:

- `create(ws)`, `get(id) -> WebSession | None`,
  `touch(id, when)` (`$max` on `last_seen_at`, so it never moves backwards),
  `delete(id)`, `delete_for_user(username) -> int`,
  `delete_expired(*, seen_before, created_before) -> int` (removes rows with
  `last_seen_at < seen_before` OR `created_at < created_before`).
- Indexes: `username`, `last_seen_at`, `created_at`.
- Registered in `startup._REPO_REGISTRY` as `"web_session"`, with
  `get_web_session_repo()`, and on `AppContext` as `web_session_repo`.

### 4. `services/web_sessions.py` — the rules

- `SessionPolicy(idle_seconds, max_age_seconds)`, read once from the environment:
  - `SEQSETUP_SESSION_MAX_AGE_SECONDS` — hard cap from login. Default `28800` (8 h).
    Existing variable; its meaning changes from "sliding window" to "hard cap".
  - `SEQSETUP_SESSION_IDLE_SECONDS` — new. Default `1800` (30 min).
  - Clamped: `max_age` to `[300, 86400]`; `idle` to `[60, max_age]`. A clamped value
    logs a WARNING naming the variable, the given value and the value used. A value
    that is not an integer is refused at startup (`ValueError`), not silently replaced.
- `new_ticket() -> str`: `secrets.token_urlsafe(32)`.
- `ticket_id(ticket) -> str`: SHA-256 hex.
- `start(sessions, user, now) -> ticket`: first `delete_expired(...)`, then `create`
  a row from `user` (including `source` and `session_stamp`).
- `resolve(sessions, users, ticket, now) -> User | None`, in this order:
  1. no row → `None`;
  2. `now - last_seen_at > idle` or `now - created_at > max_age` → delete the row,
     `None`;
  3. `source == "local"`: read the user record from `users` (`local_user_repo`).
     Missing, or its `session_stamp` differs from the row's → delete the row,
     `None`. Otherwise the returned `User` takes role, display name and email from
     the **current** record;
  4. any other source than `"local"`, `"yaml"`, `"ldap"` → delete the row, `None`;
  5. `touch(id, now)` — on **every** accepted request, so the idle time is measured
     from the real last request, exactly (review finding 3; the first draft wrote at
     most once a minute and could expire a login up to a minute early);
  6. return the `User`.
- `end(sessions, ticket)`, `end_all_for(sessions, username) -> int`.

### 5. `middleware.py` — `AuthMiddleware`

- Reads `sess.get("sid")`. No ticket → not logged in.
- Calls `resolve` through `starlette.concurrency.run_in_threadpool` (pymongo calls
  must not block the event loop). Repos come from `startup.get_web_session_repo()`
  and `startup.get_local_user_repo()`.
- `None` → `sess.clear()`, then:
  - normal request → `303 /login` (as today);
  - HTMX request (`HX-Request: true`) → `401` with `HX-Retarget: #error-banner`,
    `HX-Reswap: innerHTML` (the existing error-banner path in `static/js/app.js`)
    and this fragment:
    `Your login has ended, so this was not saved. What you typed is still on this
    page. <a href="/login" target="_blank" rel="noopener">Log in again</a> in a new
    tab, then try again here.`
    The page is not replaced, so unsaved input stays. After logging in in the other
    tab, the browser holds the new cookie and the retry works.
- A database error, or no repo → `503` "Database unavailable", `sess` untouched
  (an HTMX request gets the same error-banner headers).
- A valid ticket → `request.scope["auth"] = user`, as today.
- The old `sess["user"]` payload is no longer read or written. Old cookies have no
  `sid`, so they are sent to `/login`. (Not deployed yet, so nobody is affected.)

Plain (non-HTMX) form posts in the app carry no typed input — `/logout`,
`/runs/new`, and the template choice on `/runs/new/from-template` — so a `303 /login`
there loses nothing (review finding 4).

### 6. `routes/auth.py`

- `_login_user(sess, user, sessions, now)`: `sess.clear()` (fixation defence kept),
  then `sess["sid"] = start(sessions, user, now)`.
- `GET /login`: redirect to `/` only when `sess["sid"]` resolves to a live login.
- `POST /logout`: the actor comes from `request.scope["auth"]` (set by the
  middleware); `end(sessions, sid)`, then `sess.clear()`. Audit `logout` as today.
- Repos come from `startup` getters (the router has no `AppContext`;
  `make_router(auth_service)` keeps its signature).

### 7. `routes/local_users.py`

The account write is the revocation (the stamp changed, or the record is gone), so
the routes only add cleanup and a visible message:

- `edit_user`: after `repo.save(user)`, if the role changed or a password was set:
  try `n = end_all_for(ctx.web_session_repo, username)`; on any exception log a
  WARNING and set `n = None` — the logins are already refused by the stamp, so the
  request still succeeds. Message: `User 'x' updated. Their open logins were ended.`
  Audit `user.updated` gains `sessions_ended=True` and `session_rows_removed=n`.
- `delete_user`: the same after `repo.delete`. Message
  `User 'x' deleted. Their open logins were ended.`
- A retry after a failed cleanup needs nothing special: the stamp already refuses the
  old logins, and expired rows are removed at the next login (review finding 2).
- An admin who demotes themself is logged out on their next click. That is the
  intended outcome.

### 8. `app.py` and docs

- `SessionMiddleware(max_age=policy.max_age_seconds)`; the false "lunch" comment is
  replaced with what is true now.
- `docs/getting-started/configuration.rst`: document both variables.

## Behaviour changes users will see

- A browser unused for 30 minutes needs a new login.
- Everyone logs in again 8 hours after logging in, even while working.
- A deleted, demoted, promoted or password-reset database user needs a new login on
  their next click. The admin's success message says their logins were ended.
- A page load with an ended login goes to `/login`, as today.
- A background action (saving an edit, adding pasted samples) with an ended login
  keeps the page and shows: "Your login has ended, so this was not saved. What you
  typed is still on this page. Log in again in a new tab, then try again here."

## Known limits (not in this change)

- A user disabled in LDAP, or removed from `users.yaml`, keeps an open login until it
  times out (at most 30 minutes unused, 8 hours in all). The app cannot see those
  changes.
- Two admins editing the same user at the same moment can overwrite each other's
  change (the last save wins, role and stamp included). This is how user editing
  works today; not changed here.
- No "who is logged in" admin page and no "log out everywhere" button.
- Each request adds one read and one small write on `web_sessions`, plus one user
  read for database users.

## Testing (tests first)

- `tests/unit/test_web_session_model.py` — round trip, caps, UTC handling.
- `tests/unit/test_local_user_session_stamp.py` — new user gets a stamp; `from_dict`
  keeps the stored one and gives `""` when absent (same value on every read);
  `set_password` changes it; assigning a different role changes it; assigning the
  same role, a display name or an email does not.
- `tests/integration/test_web_session_repo.py` — each method; `touch` never moves
  backwards; `delete_for_user` leaves other users' rows; `delete_expired` both
  conditions; indexes exist.
- `tests/unit/test_web_session_policy.py` — defaults, env overrides, clamps with a
  WARNING, non-integer refused; `resolve` with an injected `now`:
  - idle 29:59 accepted, 30:01 refused; age 7:59 accepted, 8:01 refused;
  - requests every 29 minutes stay logged in until the 8-hour cap;
  - with `idle=60`, requests every 59 seconds for 10 minutes all pass;
  - the DB stores `ticket_id`, never the ticket;
  - local source: stamp mismatch refused, missing user refused, role taken from the
    current record; unknown source refused.
- `tests/integration/test_session_revocation.py` — through the real app:
  - N-02: a cookie copied before logout gets `303 /login` after logout; a second
    browser of the same user stays logged in;
  - N-04: deleted user's cookie → `303 /login`; message and audit say so;
  - N-03: demoted admin's cookie → `303 /login`; a fresh login gets `403` on
    `/admin/users` and cannot create an API token;
  - password change ends logins; a display-name-only edit does not;
  - **race (review 1):** `auth_service.authenticate` is wrapped so that, after the
    password check and before the login row is written, the admin deletes /
    demotes / resets the password of that user. For each of the three, the new
    login's first request gets `303 /login`;
  - **cleanup failure (review 2):** `delete_for_user` raises. Deleting, demoting and
    resetting the password still succeed and the old cookies are still refused;
    a second, no-op demotion leaves them refused;
  - N-19: idle 31 min → refused; 8 h 01 min after login while active → refused;
  - HTMX request with an ended login → `401`, `HX-Retarget: #error-banner`, the
    message above; a normal request → `303 /login`;
  - DB error during the check → `503`, never `200`;
  - an old-style cookie holding only `sess["user"]` → `303 /login`.
- Update `tests/unit/test_auth_session_fixation.py` and `tests/unit/test_auth_routes.py`
  for the new `_login_user`: pre-planted keys are still wiped; a new ticket per login.
- Browser suite:
  - a login, a click, a logout still work end to end;
  - **(review 4)** paste samples, end the login server-side, press Add: the error
    banner shows the message, the paste box still holds the text, and the URL has
    not changed; log in on a second page of the same browser, go back, press Add
    again: the samples are added.
- Audit proofs `test_e_session_revocation.py`, `test_i_logout_cookie_replay.py` and
  `test_e_session_cookie_flags.py::TestSessionExpirySemantics` must now fail (the
  problem is gone), run from a copy.
- Break tests in a copy: skip the lookup; skip the idle check; skip the age check;
  skip the stamp check; stop `set_password` or the role setter from changing the
  stamp; skip `end_all_for` (must *not* redden the refusal tests — the stamp
  carries them — only the cleanup tests); store the raw ticket; touch only once a
  minute. Each must redden the right test.

## Review changes (independent review, 2026-09-27)

1. **Login racing a revocation** — a login checked before an admin change could write
   its row after the cleanup. Fixed by the per-user `session_stamp`, read from the
   same record as the password and checked on every request.
2. **Cleanup failure left logins valid** — the account was changed first and the
   rows deleted second. Fixed: the account write itself revokes (stamp changes, or
   the record is gone); deleting rows is cleanup, and its failure is logged, not
   fatal.
3. **Throttled "last seen" expired logins early** — fixed by touching on every
   accepted request (`$max`), and tested between writes and at `idle=60`.
4. **"Nothing typed is lost" was not true** with a whole-page redirect — fixed by
   keeping the page on HTMX actions and showing a message with a log-in link that
   opens a new tab; plain form posts carry no typed input. Browser-tested.
