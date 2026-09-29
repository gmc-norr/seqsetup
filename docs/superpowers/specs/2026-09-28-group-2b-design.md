# Group 2b: sign-in (N-17 directory part, F23, F24, F25, N-20, N-68)

Status: design approved in conversation on 2026-09-28. Branch `fix/group-2b`, from `main`
at `62706ad`. Group 2a (`fix/group-2a`) is built at the same time on its own branch.

## Why

SeqSetup is not deployed yet. Before it is, sign-in must be safe:

- **N-17 (directory part).** Directory sign-in needs a service account whose password is
  stored in MongoDB (or in `SEQSETUP_LDAP_BIND_PASSWORD`). Anyone who reads the database or
  a backup gets a directory credential.
- **F23.** The **User Group DN** setting is saved but never read. Every account the
  directory knows can sign in as a standard user.
- **F24.** Choosing Active Directory or LDAP is not enough to switch it on, and the page
  does not say so. Sign-in quietly stays local.
- **F25.** A wrong password for a database account does not stop the attempt: the same
  name is then checked in `config/users.yaml`. One name can have two working passwords.
- **N-20.** The only way to make the first admin is a hash in `config/users.yaml`, made by
  a helper that skips the password rules. `admin123` works there.
- **N-68.** The install guide published `admin` / `admin123`. The docs run already removed
  that; this change removes the file sign-in it described.

The LIMS api-key (the other half of N-17) and N-22 are group 2c, not this change.

## Decisions (made with the user)

1. **The users file goes.** SeqSetup no longer reads `config/users.yaml`. Local accounts
   live only in the database. The first admin is made with a new server command,
   `pixi run create-admin`, which uses the same password rules as Admin → Users.
2. **Two directory groups are required: Users and Admins.** In Admins → admin. In Users
   only → standard user. In neither → refused. Directory sign-in is not switched on until
   both are filled in.
3. **Both directory kinds stay: Active Directory and LDAP.** SeqSetup is open source and
   other sites may use a non-AD LDAP server. Both share one sign-in path; on Active
   Directory, groups inside groups also count.
4. **No service account.** SeqSetup signs in to the directory *as the user*, with the name
   and password they typed, and reads their own entry over that one connection.

## Directory sign-in

### Settings

`LDAPConfig` keeps:

| Setting | Notes |
|---|---|
| `server_url`, `use_ssl`, `verify_ssl_cert` | unchanged; cleartext still refused unless `SEQSETUP_LDAP_ALLOW_CLEARTEXT=1` |
| `base_dn` | required |
| `user_dn_pattern` | shown as **Sign-in name pattern**; required |
| `user_group_dn` | shown as **Users group**; required; now used |
| `admin_group_dn` | shown as **Admins group**; required |
| `group_membership_attribute` | LDAP only (default `memberOf`); hidden for Active Directory |
| `display_name_attribute`, `email_attribute` | unchanged |
| `connect_timeout`, `receive_timeout` | unchanged |

Removed: `bind_dn`, `bind_password`, `user_search_base`, `user_search_filter`,
`username_attribute`, `effective_bind_password()` and the `SEQSETUP_LDAP_BIND_PASSWORD`
env var. `from_dict` ignores these keys in an old document; `to_dict` no longer writes
them; the settings are saved with `replace_one`, so the next save drops them.

`AuthConfig.ldap_configured` is removed. `is_ldap_enabled` is computed every time from the
saved settings: the method is Active Directory or LDAP **and** `missing_settings()` is
empty.

`missing_settings()` returns, in this order, the labels of what is missing: `server URL`,
`base DN`, `sign-in name pattern`, `Users group`, `Admins group`. A pattern of the wrong
shape for the chosen method counts as missing and is listed as
`sign-in name pattern ({username}@domain for Active Directory)` or
`sign-in name pattern (a DN like uid={username},ou=people,dc=example,dc=org for LDAP)`.

### The sign-in name pattern

- It contains `{username}` exactly once. Allowed characters: the current set plus `@`.
- **Active Directory shape:** `{username}@domain`, where the domain is letters, digits,
  `.` and `-`, with at least one dot. The bind name is a user principal name (UPN).
- **LDAP shape:** a DN (contains `=`), for example `uid={username},ou=people,dc=example,dc=org`.
- Saving the connection form accepts either shape (the method is chosen in a separate
  form). Readiness checks the shape against the method.

### Names people type

- A directory sign-in name must match `^[A-Za-z0-9._-]{1,64}$`. Anything else is refused
  **before** the server is contacted (reason `bad_name`). Names with `@` are refused: people
  type `anna`, not `anna@lab.example.se`.
- The name is lower-cased before use. The user's name in SeqSetup (run records, audit,
  sessions) is that lower-cased name, so `Anna` and `anna` are one person.
- The name is put into the pattern; for the LDAP shape it also goes through `escape_rdn`
  (a no-op for the allowed characters, kept as a second guard).
- An empty password is refused before the server is contacted (an LDAP simple bind with
  a name and no password can succeed as an unauthenticated bind).

### One name limit: 64 characters (review P3)

Today the sign-in form cuts a typed name to 64 characters, while Admin → Users accepts
128. A 65-character account can never sign in, and its cut name can point at a different
account.

- The sign-in form trims spaces but **never cuts** the name. A name longer than 64 is
  refused with the normal failure message, audit reason `bad_name`, before any account or
  server is checked.
- Admin → Users and `create-admin` use one rule: `^[A-Za-z0-9._@-]{1,64}$` (was 128 on the
  Users page).

### Steps

One connection, opened with the user's own bind name and password. `auto_referrals` is off,
so the user's password is never sent to a server named in a referral.

1. **Bind.** Failure → refused, reason `directory_refused`.
2. **Read the user's own entry**, over the same connection:
   - Active Directory: search `base_dn` (subtree) for
     `(userPrincipalName=<bind name, filter-escaped>)`, reading the display-name and email
     attributes. Exactly one entry is required.
   - LDAP: read the bind DN itself (base scope), with the display-name and email
     attributes. The DN must be inside `base_dn` (see "Comparing DNs" below).
   - Anything else → refused, reason `not_found`.
3. **Groups**, over the same connection. **The server decides membership**, with its own
   DN matching rules; SeqSetup never compares group DNs itself.
   - Active Directory: for each group, search `base_dn` for
     `(&(userPrincipalName=<upn>)(memberOf:1.2.840.113556.1.4.1941:=<group DN, filter-escaped>))`
     with no attributes. A result means "member", counting groups inside groups.
   - LDAP: for each group, search the bind DN (base scope) for
     `(<group_membership_attribute>=<group DN, filter-escaped>)` with no attributes. A
     result means "member". Direct members only. (The server must provide `memberOf`;
     OpenLDAP needs its memberOf overlay.)
4. **Role.** Admins group → admin (also when in both). Users group only → standard.
   Neither → refused, reason `not_in_group`.
5. Unbind. The result is a `User` with the lower-cased name, the display name (or the name
   when the entry has none), the email, the role and `source="ldap"`.

A server that cannot be reached, a TLS failure or any other directory error → refused,
reason `server_error`. The error is logged without the password.

Every search's result is checked (plan review 1, P1). ldap3 reports a search the server did
not finish (a size limit, an access error, a referral) in `conn.result` without raising, and
may still return some entries. Anything but success → refused, reason `server_error`. So a
partial answer never makes an admin, an access error is never read as "not in the group",
and one entry from an unfinished search never passes as "exactly one".

### Comparing DNs (review P1)

The old `_normalize_dn` splits on every comma, so `cn=SeqSetup\, Admins,...` and
`cn=SeqSetup\,Admins,...` (two different groups) compare equal, and
`uid=x\,dc=example,dc=org` looks inside `dc=example,dc=org` when it is not.

- Group membership is decided by the server (step 3), never by comparing strings.
- `_dn_is_within(dn, base)` compares parsed DNs: `ldap3.utils.dn.parse_dn(..., strip=True)`
  on both (so `uid=a, dc=org` parses like `uid=a,dc=org`); attribute types lower-cased;
  values lower-cased with their escapes kept as written; the DN is inside the base when its
  last components equal the base's components, one for one. A component is a whole RDN:
  values joined by `+` (`ou=people+dc=example`) are one component, never two, so
  `uid=anna,ou=people,dc=example,dc=org` is not inside `ou=people+dc=example,dc=org`
  (plan review 1, P2). `+`-joined values written in another order count as different
  (refused). A DN that cannot be parsed is
  not inside (refused). A value written with different escapes (`\,` against `\2c`) counts
  as different, so the check fails on the safe side (refused). Probed on 2026-09-28 against
  the installed ldap3: plain, spaced and mixed-case DNs inside the base pass; an escaped
  comma, another base and an unparsable DN are refused.
- `_normalize_dn` is removed; nothing may use it for a decision.

### Local fallback

Unchanged: when directory sign-in is on and refuses, and **Allow local fallback** is on,
local (database) accounts are tried next.

### What the sign-in page says

Every failed sign-in, directory or local, shows one message:

> Sign-in failed. Check your name and password, or ask an admin whether you have access to SeqSetup.

It says nothing about which part failed. The rate-limit message is unchanged.

### Audit

- `login.failure` gains `reason`: `bad_name` (a name over 64 characters, for any sign-in;
  or a name the directory rule refuses), `directory_refused`, `not_found`, `not_in_group`,
  `server_error` (from the directory) or `local_refused`. When the
  directory refused and the local fallback was also tried and refused, `reason` is the
  directory's and `local_tried` is `true`.
- `login.success` uses the signed-in user's name (lower-cased for directory users) and
  gains `source` (`local` or `ldap`).
- `auth.ldap_config.updated` records `user_dn_pattern`, `admin_group_dn` and
  `user_group_dn` in place of `bind_dn`.

### Settings page (Admin → Authentication)

- The three method choices stay: Local, Active Directory, LDAP.
- The form loses Bind DN, Bind password, User search base, User search filter and Username
  attribute. The pattern's help text gives one example per method. **Group attribute** is
  shown for LDAP only.
- **Warning (F24).** When Active Directory or LDAP is chosen and `missing_settings()` is not
  empty, the page shows:

  > Directory sign-in is chosen but not fully set up, so everyone signs in with local accounts. Missing: <labels, joined by ", ">.

- **Test connection** opens a connection and binds nobody. On success the message states
  the transport actually used (review P4). It is decided by the same code that builds the
  connection (`_get_server`), so the message cannot disagree with the connection:
  - TLS, certificate checked:

    > The server answered over an encrypted connection (TLS), and its certificate was checked. No password was checked; use Test sign-in for that.

  - TLS, **Verify certificate** off:

    > The server answered over an encrypted connection (TLS), but its certificate was NOT checked (Verify certificate is off). No password was checked; use Test sign-in for that.

  - No TLS (only possible with `SEQSETUP_LDAP_ALLOW_CLEARTEXT=1`):

    > The server answered over an UNENCRYPTED connection (allowed by SEQSETUP_LDAP_ALLOW_CLEARTEXT). Passwords would be sent readable. No password was checked; use Test sign-in for that.

  A success still sets `ldap_tested` as today (it is not shown anywhere; F26 is later).
- **Test sign-in** runs the same steps as a real sign-in and never starts a session. It is
  rate-limited as today. When settings are missing it shows
  `Directory sign-in is not fully set up. Missing: <labels>.` On success:

  > Signed in as <name> (<email or "no email">). Role: <admin|standard>. Admins group: <yes|no>. Users group: <yes|no>.

  On refusal (the admin is testing, so it names the reason):
  - `bad_name`: `That name has characters that are not allowed. Use letters, digits, '.', '_' and '-'.`
  - `directory_refused`: `The directory refused that name and password.`
  - `not_found`: `Signed in, but could not read the account's own entry. Check the base DN and the sign-in name pattern (on Active Directory it must match the account's userPrincipalName).`
  - `not_in_group`: `The name and password are right, but the account is in neither the Users group nor the Admins group.`
  - `server_error`: `Could not reach the directory server: <error>` (as today). When the
    server was reached and ended a search with an error:
    `The directory server answered with an error: <result name> (code <n>) while <reading the account's own entry | checking the Admins group | checking the Users group>`.

  Every value in these messages is escaped by the template, as today.

### Start-up warning

If `SEQSETUP_LDAP_BIND_PASSWORD` is set, the app logs a warning at start:

> SEQSETUP_LDAP_BIND_PASSWORD is set but no longer used: SeqSetup signs in to the directory as each user, not with a service account. Remove it.

## Local accounts

### The users file is removed

- `AuthService` checks database accounts only. `config_path`, `_load_users`,
  `reload_config` and `hash_password` go. The unknown-name timing guard (the dummy bcrypt
  comparison) stays.
- `config/users.yaml` is deleted from the repository. `startup.CONFIG_PATH` goes.
- If a `config/users.yaml` file exists at start, the app logs a warning:

  > config/users.yaml is no longer read: sign-in with file accounts was removed. Make the first admin with 'pixi run create-admin'.

- `"yaml"` is removed from the session sources, so a session started by a file account is
  no longer accepted. (None exist: the shipped file is empty.)
- F25 is gone by construction: one name, one place, one password.

### `pixi run create-admin`

- A pixi task runs `python -m seqsetup.create_admin` with `PYTHONPATH=src`. In Docker:
  `docker compose exec app pixi run create-admin`.
- It connects to the same database as the app, with the same settings.
- It asks for: username (the Users page rule, `^[A-Za-z0-9._@-]{1,64}$`), display name
  (required), email (optional), password, and the password again. Passwords are read with
  `getpass` and are never printed or logged.
- It stops, changing nothing, with exit code 1 and a one-line reason, when:
  - the name breaks the rule or the display name is empty;
  - the two passwords differ;
  - the password breaks the rules (`assert_password_strong`, via `LocalUser.set_password`),
    including more than 72 bytes (plan review 1, P4; see below);
  - an account with that name already exists (it never changes or resets an account);
  - the database cannot be reached, or fails while reading.
- It reads everything it needs (the name check, the sign-in settings) before its one write.
  If the database fails during the write, the account may or may not have been saved: it
  says the outcome is not known, exits 1, and says to run it again with the same name,
  which answers "already exists" if the account was made (plan review 1, P3).
- **At most 72 bytes per password.** bcrypt reads at most 72 bytes, and bcrypt 5 raises a
  plain `ValueError` above that. The rule goes into `assert_password_strong`, with the
  message `Password must be at most 72 bytes. Most characters are 1 byte; letters like å, ä and ö are 2.`
  Admin → Users uses the same rule, so a long password there is refused instead of
  failing with an error page (a visible fix to an existing page). Sign-in is unchanged:
  its password checks already refuse such a password.
- On success it saves a `LocalUser` with role admin, records the audit event `user.created`
  (`actor="create-admin"`, target the name, `role="admin"`, `via="server command"`) in the
  audit trail, prints `Admin '<name>' created. Sign in on the web page.` and exits 0.
- If directory sign-in is on and **Allow local fallback** is off, the new admin cannot sign
  in yet. `create-admin` still saves it, then prints:

  > Directory sign-in is on and local fallback is off, so this admin cannot sign in yet. Run 'pixi run use-local-sign-in' first, or turn on local fallback.

### `pixi run use-local-sign-in` (review P2)

With directory sign-in on and local fallback off, local accounts are never tried. A broken
directory, a wrong group setting or a lost admin group then locks everyone out, and a new
local admin does not help. This server command is the way back in.

- A pixi task runs `python -m seqsetup.use_local_sign_in` with `PYTHONPATH=src`. In
  Docker: `docker compose exec app pixi run use-local-sign-in`.
- It sets the sign-in method to Local. The directory settings are kept, so switching back
  on Admin → Authentication needs no retyping.
- It records `auth.method.changed` (`actor="use-local-sign-in"`, `method="local"`,
  `via="server command"`), prints
  `Sign-in is now local only. The directory settings were kept; switch back on Admin → Authentication.`
  and exits 0. When the method is already Local it prints `Sign-in is already local only.`,
  changes nothing and exits 0. When the database cannot be reached, or fails while reading,
  it exits 1 and says nothing was changed. When it fails while saving, it says the outcome
  is not known and to run the command again, which answers "already local only" if the
  switch was saved (plan review 1, P3).

**Recovery, written in the admin guide:**
1. `pixi run use-local-sign-in`.
2. If no local admin can sign in: `pixi run create-admin` (a new name). If an old local
   admin only forgot the password, sign in as the new admin and reset it on Admin → Users.
3. Sign in, fix the directory settings, and use **Test sign-in**.
4. Switch the method back.

## Docs

- `README.md`, `docs/getting-started/installation.rst` (Docker and local): the first admin
  is made with `create-admin`; no users file.
- `docs/getting-started/configuration.rst`, `docs/getting-started/deployment.rst`: remove
  the users file and `SEQSETUP_LDAP_BIND_PASSWORD`. The **Production Checklist** gains:
  - Test sign-in once against the real directory with a member of each group and with a
    non-member.
  - No `config/users.yaml` and no `SEQSETUP_LDAP_BIND_PASSWORD` on the server.
- `docs/admin-guide/authentication.rst`: rewritten for the new settings, the two groups,
  the warning, the two test buttons and the recovery steps (`use-local-sign-in`).
- `docs/admin-guide/local-users.rst`, `docs/user-guide/authentication.rst`,
  `docs/architecture/services.rst`, `docs/development/project-structure.rst`: remove the
  users file.
- The Admin → Authentication picture is made again.

## Tests

Unit tests use a fake `ldap3` connection, like `tests/unit/test_ldap_service.py` does
today. They check:

- the bind name for both shapes; the name rule; lower-casing; an empty password refused
  before any connection;
- exactly one connection is made, with the user's own bind name and password, and
  `auto_referrals` is off;
- the own-entry read for both shapes, including zero and two AD entries and a DN outside
  `base_dn`;
- groups: the in-chain filter on Active Directory; direct `memberOf` on LDAP; admin,
  standard, both, neither;
- every refusal reason;
- `missing_settings()` and `is_ldap_enabled` for each missing piece and each wrong shape;
- `to_dict` holds no removed key; an old document with `bind_password` loads and saves
  without it;
- the start-up warnings.

Review regression tests (unit):
- P1: with Admins group `cn=SeqSetup\, Admins,...`, an account whose entry lists only
  `cn=SeqSetup\,Admins,...` is not an admin (the decision comes from the filter sent to the
  server, and SeqSetup does no DN comparison of its own); `_dn_is_within` refuses
  `uid=x\,dc=example,dc=org` inside `dc=example,dc=org`.
- P4: Test connection's message for TLS with and without the certificate check, and for
  the cleartext opt-in.

Plan review 1 regression tests:
- P1 (unit): searches ended with sizeLimitExceeded, insufficientAccessRights or a referral,
  with and without entries, on the own entry and on each group, for both shapes → refused,
  reason `server_error`.
- P2 (unit): `uid=anna,ou=people,dc=example,dc=org` is not inside
  `ou=people+dc=example,dc=org`; `uid=anna,ou=people+dc=example,dc=org` is inside it and is
  not inside `dc=example,dc=org`.
- P3 (integration): each command, with a failed read (nothing changed) and with a save
  whose answer is lost (the outcome is not known; running it again tells).
- P4: 72 bytes accepted and 73 refused, in ASCII and in two-byte letters (unit);
  `create-admin` and Admin → Users refuse a longer password with the message (integration).

Integration tests check: the sign-in page message and the audit `reason`; local fallback;
the settings page form, warning, and both test buttons; the users file is not read (an
admin in it cannot sign in); a session with source `yaml` is not accepted; `create-admin`
(success, each refusal, the audit event, nothing changed on refusal); and:
- P3: an admin made by `create-admin` signs in through `/login/submit`; a 64-character
  name works end to end; a 65-character name is refused by `create-admin`, by
  Admin → Users and at sign-in (where it is never cut to a shorter account's name).
- P2: with directory sign-in on and local fallback off, a local admin is refused; after
  `use-local-sign-in` the same admin signs in; `create-admin` prints its warning in that
  setting; `use-local-sign-in` keeps the directory settings and records its audit event.

Existing tests of removed behaviour (the users file, the service account, search-based
lookup) are removed or rewritten; the plan lists each one.

There is no real directory server here. Before clinical use, **Test sign-in** is run once
against the lab's Active Directory (see the Production Checklist).

## Not in this change

- The LIMS api-key and N-22 (group 2c).
- Showing `ldap_tested` (F26, later).
- Ending a directory user's session early when their groups change: a change takes effect
  at the next sign-in (sessions end after 30 minutes idle or 8 hours).
- Sign-in names with `@` or non-ASCII letters for directory accounts.
- A test against a real LDAP or AD server.

## Review changes

Review 1 (Astra, on `7145d38`), all four reproduced or confirmed in the code, all fixed:
- P1: string DN comparison could make one group count as another → the server decides
  membership; `_dn_is_within` parses DNs; `_normalize_dn` removed.
- P2: no way back in with the directory on and local fallback off → `use-local-sign-in`
  and written recovery steps.
- P3: 128-character names at creation, cut to 64 at sign-in → one 64 limit, never cut.
- P4: Test connection called a cleartext connection "secure" → the message states the
  transport actually used.

Plan review 1 (Astra, on the plan at `017339c`), all four reproduced, all fixed:
- P1: a search result was used without checking its result code, so a partial answer
  (sizeLimitExceeded) could make an admin and an access error read as "not in the group"
  → every search's result code is checked.
- P2: the DN comparison dropped the `+` between values, so `ou=people+dc=example,dc=org`
  looked like the parent of `ou=people,dc=example,dc=org` → components are whole RDNs.
- P3: database failures after connecting were not caught in either command → reads before
  the write say "Nothing was changed"; a failed write says the outcome is not known.
- P4: a password over 72 bytes crashed `create-admin` (and Admin → Users) → a clear
  refusal from the model's password rules.

## Merging with 2a

Both branches start at `62706ad`. They share only `tests/browser/test_docs_screenshots.py`
(different tests) and doc pictures. Whichever merges second first merges `main` into its
branch (never a rebase) and runs every suite again.

2a merged first (`add956b`, 2026-09-29). `main` was then merged into `fix/group-2b` before
the build (never a rebase), and the plan was dry-run again on `add956b`: 2351 passed, 2a's
2201 plus 2b's 150. The build starts from there.
