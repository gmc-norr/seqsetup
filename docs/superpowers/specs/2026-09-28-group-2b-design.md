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

### Steps

One connection, opened with the user's own bind name and password. `auto_referrals` is off,
so the user's password is never sent to a server named in a referral.

1. **Bind.** Failure → refused, reason `directory_refused`.
2. **Read the user's own entry**, over the same connection:
   - Active Directory: search `base_dn` (subtree) for
     `(userPrincipalName=<bind name, filter-escaped>)`, reading the display-name and email
     attributes. Exactly one entry is required.
   - LDAP: read the bind DN itself (base scope), with the display-name, email and group
     attributes. The DN must be inside `base_dn` (the existing `_dn_is_within` check).
   - Anything else → refused, reason `not_found`.
3. **Groups**, over the same connection:
   - Active Directory: for each group, search `base_dn` for
     `(&(userPrincipalName=<upn>)(memberOf:1.2.840.113556.1.4.1941:=<group DN, filter-escaped>))`
     with no attributes. A result means "member", counting groups inside groups.
   - LDAP: the entry's `group_membership_attribute` values, compared with the group DN
     after `_normalize_dn`. Direct members only. (The server must provide `memberOf`;
     OpenLDAP needs its memberOf overlay.)
4. **Role.** Admins group → admin (also when in both). Users group only → standard.
   Neither → refused, reason `not_in_group`.
5. Unbind. The result is a `User` with the lower-cased name, the display name (or the name
   when the entry has none), the email, the role and `source="ldap"`.

A server that cannot be reached, a TLS failure or any other directory error → refused,
reason `server_error`. The error is logged without the password.

### Local fallback

Unchanged: when directory sign-in is on and refuses, and **Allow local fallback** is on,
local (database) accounts are tried next.

### What the sign-in page says

Every failed sign-in, directory or local, shows one message:

> Sign-in failed. Check your name and password, or ask an admin whether you have access to SeqSetup.

It says nothing about which part failed. The rate-limit message is unchanged.

### Audit

- `login.failure` gains `reason`: `bad_name`, `directory_refused`, `not_found`,
  `not_in_group`, `server_error` (from the directory) or `local_refused`. When the
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

- **Test connection** opens a connection (TCP and TLS) and binds nobody. Success:

  > The server answered over a secure connection. No password was checked; use Test sign-in for that.

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
  - `server_error`: `Could not reach the directory server: <error>` (as today).

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
- It asks for: username (the Users page rule, `^[A-Za-z0-9._@-]{1,128}$`), display name
  (required), email (optional), password, and the password again. Passwords are read with
  `getpass` and are never printed or logged.
- It stops, changing nothing, with exit code 1 and a one-line reason, when:
  - the name breaks the rule or the display name is empty;
  - the two passwords differ;
  - the password breaks the rules (`assert_password_strong`, via `LocalUser.set_password`);
  - an account with that name already exists (it never changes or resets an account);
  - the database cannot be reached.
- On success it saves a `LocalUser` with role admin, records the audit event `user.created`
  (`actor="create-admin"`, target the name, `role="admin"`, `via="server command"`) in the
  audit trail, prints `Admin '<name>' created. Sign in on the web page.` and exits 0.
- A locked-out site makes a second admin with a new name, then fixes the old account on
  Admin → Users.

## Docs

- `README.md`, `docs/getting-started/installation.rst` (Docker and local): the first admin
  is made with `create-admin`; no users file.
- `docs/getting-started/configuration.rst`, `docs/getting-started/deployment.rst`: remove
  the users file and `SEQSETUP_LDAP_BIND_PASSWORD`. The **Production Checklist** gains:
  - Test sign-in once against the real directory with a member of each group and with a
    non-member.
  - No `config/users.yaml` and no `SEQSETUP_LDAP_BIND_PASSWORD` on the server.
- `docs/admin-guide/authentication.rst`: rewritten for the new settings, the two groups,
  the warning and the two test buttons.
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

Integration tests check: the sign-in page message and the audit `reason`; local fallback;
the settings page form, warning, and both test buttons; the users file is not read (an
admin in it cannot sign in); a session with source `yaml` is not accepted; `create-admin`
(success, each refusal, the audit event, nothing changed on refusal).

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

## Merging with 2a

Both branches start at `62706ad`. They share only `tests/browser/test_docs_screenshots.py`
(different tests) and doc pictures. Whichever merges second first merges `main` into its
branch (never a rebase) and runs every suite again.
