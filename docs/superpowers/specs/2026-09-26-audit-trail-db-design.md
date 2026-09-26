# Permanent Audit Trail in MongoDB — Design

**Date:** 2026-09-26
**Status:** Approved design (user chose "B: the database" over server log output)
**Findings closed:** N-18 (no durable sink), N-21 (URL credentials in audit events).
Security audit 2026-09, `/home/parlar_ai/seqsetup-audit-run/FINDINGS.md`.

## Problem

Since `2694574` every `audit()` call is recorded, but only in the in-memory log
viewer buffer behind `/admin/logs`:

1. a restart loses every event;
2. one admin click on **Clear logs** erases them all, including the record of
   whatever that admin did just before;
3. the buffer holds 2000 entries, so a busy day pushes out older events —
   and pushes out the warnings the log viewer is for.

Separately, six `audit()` calls pass a configured web address (LIMS URL,
GitHub repo URL, LDAP server URL). A URL like
`https://svc:PASSWORD@lims/api?api_token=TOKEN` puts the password and token in
the event (N-21). Once events are kept forever, that leak is kept forever.

## Decisions

- **Store:** a new MongoDB collection `audit_events`, one document per
  `audit()` call.
- **Add-only:** the app can add events and read them. No code path updates or
  deletes one — not "Clear logs", not deleting a run, not a restart. Keeping
  or pruning old events is the database operator's job (documented, not coded).
- **Own page:** admins read events on a new page, **Audit trail**
  (`/admin/audit`). Audit events leave the `/admin/logs` buffer, so that
  buffer holds application logs only again.
- **Never block the action:** if saving an event fails (database down), the
  action still goes through, `audit()` still does not raise (its existing
  contract), and an ERROR goes to the application log, visible on
  `/admin/logs`. Same best-effort rule as the run history.
- **Bounded, before the response:** the event is written before `audit()`
  returns — so when the user sees a response, the event is stored or an ERROR
  was logged — and the write may take at most 2 seconds (`pymongo.timeout(2)`),
  then it counts as failed.
- **Clean secrets first, without damaging names:** before an event is logged
  or saved, web addresses lose their user/password part, query string and
  fragment (scheme, host as typed, port and path stay; an address that cannot
  be parsed cleanly becomes `[address removed]`). Two levels (revised after
  review, see "Review changes"):
  - a value that **is** an address — a details key named `url`/`*_url`/`*_urls`,
    or a target wrapped in `redact_url(...)` at its call site — is cleaned
    with or without a scheme;
  - **free text** (every other target and detail) is cleaned only where an
    address is unambiguous (`://` or a leading `//`), so names that merely
    contain `@`, `:` or `#` (kit `IDT UDI:v1@2024`) are kept exactly.
  Details keys the log viewer treats as secret (`api_key`, `password`,
  `bind_password`, `secret`, …) are stored as `***`, and free text also goes
  through the log viewer's `scrub_log_message` (`api_key=…` in a sentence).

Out of scope (can be added later): CSV download, tamper-evident signatures or
hash chains, automatic retention/deletion, auditing who viewed the audit page.

## Components

### 1. `models/audit_event.py` — `AuditEvent`

A dataclass, following `models/run_history.py`:

| field | type | rule (enforced in `__setattr__`) |
|---|---|---|
| `id` | str | uuid4 by default |
| `timestamp` | datetime | UTC; stored as the same canonical ISO string as `RunHistoryEntry` (`_canonical_ts`) |
| `event` | str | cut to 128 chars |
| `actor` | str | cut to 256 chars (a failed login's username is chosen by a stranger) |
| `target` | str | cut to 1024 chars |
| `outcome` | str | cut to 32 chars |
| `details` | dict | if its BSON encoding is over 64 KiB, replaced by `{"details_omitted": true, "bytes": <n>}` |

`to_dict()` / `from_dict()` / `cursor()` (keyset cursor `(timestamp, id)`),
as `RunHistoryEntry`.

### 2. `repositories/audit_event_repo.py` — `AuditEventRepository`

Thin, insert-only, like `RunHistoryRepository`:

- `append(event)` — `insert_one`.
- `search(*, limit, event_prefix=None, actor=None, target=None,
  from_ts=None, to_ts=None, before_ts=None, before_id=None) -> list[AuditEvent]` —
  newest first, sorted `(timestamp, _id)` descending, keyset pagination.
  `event_prefix` matches the start of the event name (`login` finds
  `login.success` and `login.failure`; the text is `re.escape`d). `actor` and
  `target` match exactly. `from_ts` (inclusive) and `to_ts` (exclusive) bound
  the timestamp as canonical strings; the page turns its dates into these.
- Indexes: `(timestamp -1, _id -1)`, `(event 1, timestamp -1)`,
  `(actor 1, timestamp -1)`, `(target 1, timestamp -1)`.
- No update, replace or delete method (a test pins this).

Registered in `startup._REPO_REGISTRY` as `"audit_event"`, with
`get_audit_event_repo()` and an `AppContext.audit_event_repo` field.

### 3. `services/audit_log.py`

- `set_audit_sink(repo)` — module-level, like
  `data.instruments.set_instrument_definition_repo`.
- `audit()` builds the record as today, then:
  1. turns it into JSON types (`json.dumps(..., default=_json_fallback)` then
     `json.loads`), so a set, bytes or an exception is already text;
  2. cleans `target` and `details` with `_clean_value` (nested dicts and lists
     included); a failure here (e.g. circular details) takes the existing
     minimal-record path, so `audit()` still never raises;
  3. logs the cleaned JSON line on `seqsetup.audit`;
  4. if a sink is set, appends an `AuditEvent` built from that line inside
     `with pymongo.timeout(AUDIT_WRITE_TIMEOUT_S)` (2 seconds); any exception
     (a timeout included) is caught and logged as ERROR on the application
     logger (`seqsetup.services.audit_log`) with the cleaned line — never
     raised.
- `_clean_value(value, key)`: a non-empty text under a key in the log
  viewer's `_SENSITIVE_KEY_NAMES` → `***`; a text under an address key
  (`_ADDRESS_KEY_RE`: `url`, `urls`, `*_url`, `*_urls`) → `redact_url`; any
  other text → `scrub_log_message(redact_url_secrets(text))`.
- `redact_url(value) -> str` — for a value that IS an address. Parses it
  (with `//` in front when it has no scheme) and rebuilds scheme (if any),
  `//` (if it had it), host and port exactly as typed, and path; userinfo,
  query and fragment are dropped. **Fail closed** to `[address removed]` if
  parsing raises (bad port, bad IPv6), finds no host, the value holds an `@`
  that did not end up closing a user part (a `#`, `/` or `?` inside the
  password split it early), or the rebuilt value still holds `@`, `?`, `#`
  or whitespace. Non-text and blank values are returned as they are.
- `redact_url_secrets(text) -> str` — for free text. Splits on whitespace;
  quote and sentence characters at a piece's edges (`' " ( ) < > { } , ; . !`
  — not `[ ]`, which belong to an IPv6 host) are set aside and put back. Only
  a piece containing `://`, or starting with `//` and longer than `//`, is
  cleaned (as `redact_url` does); everything else is kept exactly.
- **Call sites.** The four `audit()` targets that are configured addresses
  (`lims.url_blocked` in `services/sample_api.py`, the three
  `config_sync.scheduled.*` events in `services/scheduler.py`) pass
  `target=redact_url(...)`. The four address details already use address
  keys (`base_url` ×2, `repo_url`, `server_url`). A test reads every
  `audit()` call in `src/` and fails if an argument whose source mentions
  `url` is neither wrapped in `redact_url(...)` nor passed under an address
  key.
- **Known limit.** A scheme-less credential address inside free text (for
  example an exception message quoting `svc:pw@host/path`) is not cleaned:
  it cannot be told apart from a name like `svc:prod@lab`. Today no call site
  produces one (`lims.url_blocked` passes `str(exc)`, which names the host
  only).
- **Why no hand-off for async callers.** 25 `audit()` calls run inside
  `async` route handlers (all of `routes/samples.py`, `update_status`, the
  template routes, `upload_index_kit`). Those same handlers already make
  blocking MongoDB calls on the event loop for their own run saves
  (`saving_run` → `run_repo.save`); nothing in the codebase offloads database
  work (`run_in_threadpool` / `to_thread` / `run_in_executor`: no uses). The
  audit write adds one more such call, capped at 2 seconds (measured:
  `pymongo.timeout(2.0)` ends a write to a dead server after 2.0 s despite the
  client's 30 s socket timeout). A background writer is not used: it would
  answer the user before the event is stored, and add a thread, ordering and
  flush-at-shutdown questions. Moving all database work off the event loop is
  a separate, codebase-wide change (see Follow-ups).

### 4. `services/log_capture.py`

The in-memory buffer handler skips records from the `seqsetup.audit` logger
(a handler filter). Propagation is unchanged, so pytest's `caplog` and any
operator-added handler still see audit records.

### 5. Wiring — `app.py`

`set_audit_sink(get_audit_event_repo())` right after
`set_instrument_definition_repo(...)`, before `init_auth_service()` and
`init_scheduler()` — so the scheduler thread's first sync is recorded.

### 6. Page — `routes/admin/audit.py` + `templates/admin/audit.html`

- `GET /admin/audit`, router-level `require_admin_dep`, full page or the
  `audit_page` block for HTMX (as `/admin/logs`).
- Filters (all optional, each clamped with `sanitize_string` to the same
  length as the stored field, so any stored value can be searched for):
  **What happened** (`event`, prefix, 128), **Who** (`actor`, exact, 256),
  **On what** (`target`, exact, 1024), **From** / **To** (`date_from`,
  `date_to`, `YYYY-MM-DD`, UTC days, inclusive; 10).
- A malformed date renders the page with a message and no results (not a
  500). A half cursor (`before_ts` without `before_id`, or the reverse)
  is a 400, as in run history.
- 100 events per page, newest first; **Older** link carries the filters and
  the cursor.
- Table: Time (UTC), Who, What, On what, Result, Details (JSON, escaped).
  Empty state: "No audit events match."
- Nav: **Audit trail** next to **Logs** in `_app_shell.html`. The Logs page
  gets one line: "Audit events are on the Audit trail page."

## Behaviour changes users will see

- A new admin page, Audit trail.
- `/admin/logs` no longer lists audit events (they were only added there in
  `2694574`, earlier today). The test `tests/integration/test_audit_trail_visible.py`
  moves its checks to `/admin/audit` and gains a check that `/admin/logs`
  no longer lists them.
- Audit events keep web addresses without passwords, tokens or query strings.

## Testing (tests first)

- Model: caps; oversize details replaced; `to_dict`/`from_dict` round trip.
- Redaction, each checked in BOTH the logged JSON line and the stored
  document: userinfo, query, fragment removed; port and path kept; the
  scheme-relative `//svc:PASSWORD@lims.invalid/api?api_token=TOKEN` (reaches
  `lims.url_blocked` today, measured); scheme-less `svc:PASSWORD@host/api?…`
  and `TOKEN@github.com/org/repo`; `host/api?api_token=…`; an LDAP URL with a
  bind password; fail-closed cases (`http://[::1/api?…`, a password holding
  `/` or a space, `https://svc:PASSWORD@`); e-mail addresses and ordinary
  text unchanged; nested details.
- Sink: `audit()` appends to the repo; a failing repo does not raise and logs
  an ERROR; a write is run under `pymongo.timeout(2)` (a repo that records the
  active timeout proves it); no sink set is fine.
- Repository: newest first; each filter; date bounds inclusive; pagination
  with ties on timestamp; no update/delete method.
- Integration (real routes, mongomock):
  - a login shows on `/admin/audit`;
  - the event is still there after the app is reloaded against the same
    database (restart);
  - **Clear logs** leaves it;
  - a standard user gets 403; an anonymous user is sent to login;
  - filters and **Older** work; a half cursor is 400; a bad date shows a
    message;
  - an exact search for a stored 300-character target finds it (the filter
    is not cut shorter than the field);
  - a blocked LIMS URL with a password and token is stored without them (N-21);
  - `/admin/logs` no longer lists audit events.
- Page smoke test, as ARCHITECTURE.md requires.

## Follow-ups (not in this change)

- Admin guide page for the Audit trail — after the docs branch
  (`docs/guide-screenshots`) is merged, so the two do not collide.
- Operator guidance: MongoDB user without delete rights on `audit_events`
  (it still needs `createIndex`, or the indexes created ahead, since the
  repository creates them at startup); retention and backup of that
  collection.
- Async route handlers make blocking MongoDB calls on the event loop (run
  saves, now also audit writes); a stalled database stalls every request.
  Codebase-wide; not part of the security audit's findings list.

## Review changes (independent review, 2026-09-27)

The first build cleaned scheme-less addresses everywhere and cleaned before
serializing. Review measured three problems, each permanent in an add-only
store: a token in a scheme- and path-less LIMS `base_url`
(`lims.example.com?api_token=…`) was stored; values turned into text by
`_json_fallback` (set, bytes, exception) skipped cleaning; and names were
rewritten (`IDT UDI:v1@2024` → `IDT 2024`, `UDI/Set#A` → `udi/Set`). Fixed by
the two-level design above (strict for address keys and wrapped targets, `://`
/ `//` only in free text, host kept as typed), cleaning after serializing,
masking secret-named keys, the call-site guard test, and fail-closed on an
`@` that is not a user part. Also: `date_to=9999-12-31` gave a 500 (now a
message); the nav-link test could pass without the nav link (now checked on
`/admin/users`); `fresh_app` left the previous test's database as the sink
(now cleared on teardown); the save-failure ERROR now carries the cleaned
line.
