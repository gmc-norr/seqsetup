# Group 3a: install settings (closed port, HTTPS only, HSTS, a checked Tailwind download) — design

Date: 2026-10-11. Base: main `6484500` (later-list slices 1 and 2 merged, not pushed). Branch
`fix/group-3a`. Source: the 2026-09 security audit, N-08 (HIGH; its duplicates N-32 and N-33
are LOW) and N-25 (MEDIUM). Group 3 ("before the first install") is split in three: 3a, this
slice (install settings); 3b (library updates: N-23, N-24, N-26); 3c (app bugs: N-13,
N-14/N-15). Decisions: the user, in this brainstorm (2026-10-11).

## Why

Each point was measured on `6484500`.

1. **The app's port is open to the whole network.** `docker-compose.yml:14` publishes
   `"5001:5001"` with no address. `docker compose config` (fake `.env` values, nothing
   started) renders it with no `host_ip`, which Docker binds on every interface:

   ```
   ports:
     - mode: ingress
       target: 5001
       published: "5001"
   ```

   Anyone who can reach the server reaches the app directly, around the TLS proxy. The
   `mongodb` service in the same file has no `ports:` on purpose (its comment says why).

2. **The session cookie is not Secure unless someone remembers.** `docker-compose.yml:24`
   reads `SEQSETUP_HTTPS_ONLY=${SEQSETUP_HTTPS_ONLY:-0}`: a `.env` without the line gives
   `"0"` (measured in the same render), so the cookie goes out without `Secure` and a browser
   sends it over plain HTTP. `.env.example:23` says `1`; the two disagree. And the app reads
   the value loosely (`app.py:74`, `.lower() in ("1", "true", "yes")`), so a typo is "off"
   with no word:

   ```
   '1' -> on   'yes' -> on   'TRUE' -> on
   'on' -> off   'enabled' -> off   ' 1' -> off   '2' -> off
   ```

3. **HSTS is sent only when the app itself sees `https`.** `SecurityHeadersMiddleware`
   (`security_headers.py:75-80`) passes `is_https=request.url.scheme == "https"`. Behind a
   TLS proxy the app sees `http` unless uvicorn honours the proxy's `X-Forwarded-Proto`,
   which it does only for a proxy that connects from `127.0.0.1` (uvicorn's default
   `forwarded_allow_ips`; the audit measured both cases, N-33). So whether browsers are told
   "always use HTTPS" depends on where the proxy runs, not on what the admin set.

4. **The Tailwind build step installs and runs any file.** The `tailwind-install` task
   (`pixi.toml:18-44`; the `Dockerfile` runs it as root through `RUN pixi run css`) checks
   nothing but the version text the file itself prints. Measured with the task's own script
   in a scratch folder, `curl` replaced by a stand-in that writes a fake program:

   | case | result |
   |---|---|
   | nothing installed: the "download" is a fake | installed, run, exit 0 |
   | a fake already at `.pixi/bin/tailwindcss` that prints `tailwindcss v4.3.0` | kept, run, exit 0 |
   | a fake at `tools/vendor/tailwindcss-linux-x64` | installed, run, exit 0 |

   Whoever can change the file at that address, or put one in the way, runs code inside
   the image build. The rest of the build is checked: `pixi install --locked` pins a
   SHA-256 for every package in `pixi.lock` (204 packages, 204 `sha256:` lines).

## Design

### 1. The port opens only on the server itself (docker-compose.yml)

`docker-compose.yml:14` becomes:

```yaml
    ports:
      # Only this server can reach the app (a TLS proxy on it still can). To let a proxy on
      # another machine in, set SEQSETUP_PUBLISH_ADDRESS in .env to this server's address
      # on that network (0.0.0.0 for every interface).
      - "${SEQSETUP_PUBLISH_ADDRESS:-127.0.0.1}:5001:5001"
```

Measured with a scratch copy and fake `.env` values: without the setting the render has
`host_ip: 127.0.0.1`; with `SEQSETUP_PUBLISH_ADDRESS=0.0.0.0` it has `host_ip: 0.0.0.0`.
The setting also reaches the container through `env_file: .env` (measured: it shows in the
rendered `environment:`); the app does not read it.

Inside the container the app keeps listening on `0.0.0.0` (`app.py:185`): it must, or the
published port reaches nothing.

### 2. Compose will not start without a decision on HTTPS (docker-compose.yml)

`docker-compose.yml:24` becomes
`- SEQSETUP_HTTPS_ONLY=${SEQSETUP_HTTPS_ONLY:?must set in .env}`, like the session secret
and the Mongo passwords. Measured (scratch copy): a `.env` without the line, and one with
`SEQSETUP_HTTPS_ONLY=` (empty), both stop `docker compose config` with
`required variable SEQSETUP_HTTPS_ONLY is missing a value: must set in .env`, exit 1.

`.env.example` moves the line from "Recommended for production" to "Required", keeps `1`,
and its comment says what it does: the session cookie is marked `Secure` and browsers are
told to use only HTTPS (HSTS); `0` only for a trial over plain HTTP. It also gains a
commented `# SEQSETUP_PUBLISH_ADDRESS=` with one line on when to set it.

### 3. The app refuses a value it does not know (security_headers.py, app.py)

A new function in `security_headers.py`:

```python
def https_only_from_env() -> bool:
    """SEQSETUP_HTTPS_ONLY as a bool. Raise RuntimeError on a value it does not know."""
```

- `1`, `true`, `yes` (any case) are on.
- unset, empty, `0`, `false`, `no` (any case) are off. Unset stays off so `pixi run serve`
  on a developer's machine works as today.
- Anything else, `on` or ` 1` included, raises `RuntimeError` with this message, and the
  app stops at start:

  ```
  SEQSETUP_HTTPS_ONLY='on' is not a known value. Set it to 1 (or true, yes) when users
  reach SeqSetup over HTTPS, or to 0 (or false, no) when they do not.
  ```

  (One line in the code; the value is shown with `!r`.)

`app.py` reads it right after `check_display_zone()` (`app.py:64`), before the session
secret and the database, so a wrong value stops the start before anything connects. The
read at `app.py:74` goes; `_SESS_HTTPS_ONLY` keeps its name and is set from the new
function.

The other on/off settings (`SEQSETUP_LIMS_ALLOW_HTTP`, `SEQSETUP_LIMS_ALLOW_PRIVATE_NETS`,
`SEQSETUP_LDAP_ALLOW_CLEARTEXT`, `SEQSETUP_TRUST_FORWARDED_FOR`) keep their loose reading:
each one loosens a check, so a typo there falls to the safe side. `SEQSETUP_HTTPS_ONLY` is
the only one where a typo falls to the unsafe side.

### 4. HSTS follows "HTTPS only" (security_headers.py, app.py)

`SecurityHeadersMiddleware` takes `https_only: bool = False` and passes
`is_https=self._https_only or request.url.scheme == "https"`. `app.py` passes the same
`_SESS_HTTPS_ONLY` the session cookie uses:
`app.add_middleware(SecurityHeadersMiddleware, https_only=_SESS_HTTPS_ONLY)`.
`apply_security_headers` and the header's value (`max-age=63072000; includeSubDomains`) do
not change. The middleware wraps the whole app, `/api` included (`app.py:152` mounts it
inside).

So with "HTTPS only" on, every answer carries HSTS, wherever the proxy runs. On an answer
that reaches the browser over plain HTTP it does nothing: browsers ignore HSTS received
over plain HTTP (RFC 6797, section 8.1). With it off, nothing changes: HSTS only when the
app itself sees `https`, as today. The module docstring's "(only when served over TLS)" and
`apply_security_headers`'s docstring are corrected to say this.

The docs say what `includeSubDomains` means for the lab: once a browser has seen HSTS from
SeqSetup's host name, that name and every name under it work only over HTTPS for two years.

### 5. The Tailwind binary is checked before it is made runnable (tools/, pixi.toml)

**New file `tools/tailwind-sha256.txt`**: the SHA-256 of each standalone binary the install
supports, copied from `sha256sums.txt` on Tailwind's v4.3.0 release page:

```
# tailwindcss v4.3.0
# SHA-256 of the Tailwind CSS standalone binaries, from sha256sums.txt on the release page
# (github.com/tailwindlabs/tailwindcss/releases). tools/install-tailwind.sh refuses a binary
# that does not match. When you change tools/tailwind-version.txt, change the first line
# and replace these four lines with the new release's.
73f0e5459054e5cfaa8ab6f3b940f3fbe0f13cc7fd83bc24e7c655033c203400  tailwindcss-linux-x64
8f48dcb72be3b351c10563c5329b4638ba8516820dc3b3a1609625a166e87cbd  tailwindcss-linux-arm64
2ba252f770817091e6d0d12a84e0dd531bcc29aad1bfd9d976a3aff1a071b67a  tailwindcss-macos-x64
56b4bbc62dbdc4614a78930d9c6986423a2ec63e4e640144a59a5d95c914322e  tailwindcss-macos-arm64
```

Measured: the release's `sha256sums.txt` lists these four values (it also lists `-musl` and
Windows builds the install does not use), and the binary already installed on the
development machine (`tailwindcss v4.3.0`, installed before this work) has
`73f0e545…3400`, the linux-x64 value.

**New file `tools/install-tailwind.sh`** (`set -euo pipefail`), run from the repo root.
The `tailwind-install` task in `pixi.toml` becomes `bash tools/install-tailwind.sh`; the
`css` and `css-watch` tasks and the `Dockerfile` do not change (it already copies `tools/`).
The script:

1. Reads the version from `tools/tailwind-version.txt` and picks the platform from
   `uname -sm` as today (four platforms; any other stops it, as today).
2. Takes the expected SHA-256 for `tailwindcss-<platform>` from `tools/tailwind-sha256.txt`
   (lines not starting with `#`, second field equal to the name). Not exactly one line:
   it stops, exit 1, without downloading:
   `tools/tailwind-sha256.txt has no single SHA-256 for tailwindcss-<platform>.`
3. If `.pixi/bin/tailwindcss` exists: it hashes it **without running it**. A match: prints
   `Tailwind <version> already installed at .pixi/bin/tailwindcss`, exit 0. No match: it
   removes it and says
   `.pixi/bin/tailwindcss does not match the pinned SHA-256; removed, installing again.`
4. Gets the binary into `.pixi/bin/tailwindcss.download` (removed first if left over): a
   copy of `tools/vendor/tailwindcss-<platform>` when that exists, else `curl -fsSL` from
   `https://github.com/tailwindlabs/tailwindcss/releases/download/<version>/tailwindcss-<platform>`.
   It says which one (today's script prints "Downloading …" also for a vendored copy).
5. Hashes the new file (`sha256sum`, or `shasum -a 256` where there is no `sha256sum`). No
   match: removes it, prints the message below, exit 1. The file is never made executable
   or run.

   ```
   tailwindcss-linux-x64 from <URL or tools/vendor/tailwindcss-linux-x64> has SHA-256
   <actual>, not the <expected> that tools/tailwind-sha256.txt pins. It was not installed.
   If you changed tools/tailwind-version.txt, copy the new release's values from its
   sha256sums.txt into tools/tailwind-sha256.txt.
   ```

   (One `echo` per line; the platform and version come from steps 1 and 2.)
6. A match: `chmod +x`, moves it to `.pixi/bin/tailwindcss`, runs `--version`, exit 0.

A failed `tailwind-install` stops `pixi run css` (measured with a two-task scratch
`pixi.toml`: the failing task's dependant did not run, exit 1), so a wrong file stops
`docker build` at `RUN pixi run css`, and `pixi run serve` on a developer's machine.

### 6. Docs

- `docs/getting-started/deployment.rst`:
  - after the compose quick start (`:44`): the app answers only on the server itself;
    `SEQSETUP_PUBLISH_ADDRESS` for a proxy on another machine; `.env` must set
    `SEQSETUP_HTTPS_ONLY`.
  - the two `docker run` examples (`:68`, `:84`): `-p 127.0.0.1:5001:5001` and
    `-e SEQSETUP_HTTPS_ONLY=1`.
  - the "Production Docker Compose" example (`:159`):
    `"127.0.0.1:5001:5001"` and `SEQSETUP_HTTPS_ONLY=1`.
  - the environment table (`:95-117`): rows for `SEQSETUP_HTTPS_ONLY` (required with
    compose; the values; what on does: Secure cookie and HSTS; a value it does not know
    stops the start) and `SEQSETUP_PUBLISH_ADDRESS` (compose only; default `127.0.0.1`).
  - the reverse-proxy box (`:265-274`): it says `SEQSETUP_TRUSTED_ORIGINS` makes "the Origin
    check and security headers work". It fixes only the Origin check; HSTS now follows
    `SEQSETUP_HTTPS_ONLY`. Corrected, with the `includeSubDomains` note from section 4.
- `docs/getting-started/installation.rst`, "Local Development Setup" (`:146-148`): one note
  that `pixi run serve` listens on every network interface of the computer (see "Not
  changed"), and that its first run downloads Tailwind and checks it against
  `tools/tailwind-sha256.txt`.

## Not changed

- **The Origin check behind a proxy.** It still compares the browser's `Origin` with the
  scheme the app sees, so behind a TLS proxy that uvicorn does not trust every form post is
  refused (403) until `SEQSETUP_TRUSTED_ORIGINS` is set. That is documented
  (`deployment.rst:265-274`) and fails safe (the audit rated that half LOW for this reason).
- **`pixi run serve` without Docker** still listens on `0.0.0.0`. Changing it needs a second
  address setting next to `SEQSETUP_PUBLISH_ADDRESS`, and `env_file: .env` would hand both to
  the container, where the wrong one stops the app. The docs note it instead.
- **uvicorn's trusted proxy addresses** (`forwarded_allow_ips`): not opened. HSTS no longer
  depends on them (section 4), and opening them would let any client that reaches the port
  set the scheme.
- **Other on/off settings** keep their loose reading (section 3).

## For the later list

- `seqsetup.def` (an Apptainer recipe): it copies no `tools/`, so `pixi run serve` there
  cannot read `tools/tailwind-version.txt`; it builds no CSS; it is in no doc. Fix or remove.
- The floating base images (`pixi:latest`, `mongo:7`; the audit's base-image finding, LOW).

## Tests

All without network and without the real MongoDB (`MONGODB_URI=mongodb://127.0.0.1:1`).

- `tests/unit/test_security_headers.py`:
  - the middleware with `https_only=True` sends HSTS over `http`; with `https_only=True`
    over `https`, one HSTS header with today's value; the default (`False`) over `http`,
    none (today's test stays).
  - `https_only_from_env`: on for `1`, `TRUE`, `yes`; off for unset, ``, `0`, `false`, `No`;
    `RuntimeError` with the message for `on`, `enabled`, ` 1`, `2`.
  - the app stops at start on `SEQSETUP_HTTPS_ONLY=on`: a subprocess runs
    `import seqsetup.app`, as `tests/unit/test_clock.py:150-167` does for `TZ`; exit not 0,
    the message in stderr.
- `tests/integration/test_https_only_wiring.py`: in `seqsetup.app`'s middleware list,
  `SecurityHeadersMiddleware` gets `https_only=_SESS_HTTPS_ONLY` and `SessionMiddleware`
  gets the same value.
- `tests/unit/test_compose_defaults.py` (reads the YAML; Docker not needed): the app's
  ports are exactly `["${SEQSETUP_PUBLISH_ADDRESS:-127.0.0.1}:5001:5001"]`; its environment
  has `SEQSETUP_HTTPS_ONLY=${SEQSETUP_HTTPS_ONLY:?must set in .env}`; `mongodb` has no
  `ports`; `.env.example` sets `SEQSETUP_HTTPS_ONLY=1`.
- `tests/unit/test_install_tailwind.py`: runs `tools/install-tailwind.sh` with `bash` in a
  scratch folder holding its own `tools/tailwind-version.txt` and
  `tools/tailwind-sha256.txt` (the hash of a small fake program), with stand-ins for `uname`
  (`Linux x86_64`) and `curl` (logs its arguments, writes a given file) first on `PATH`. Each
  fake program leaves a marker file when it runs. Cases:
  - a good download: installed, executable, exit 0, `curl` asked the release URL, no
    `.download` file left.
  - a bad download: exit 1, the message, nothing at `.pixi/bin/tailwindcss`, no `.download`
    file, the bad file never ran.
  - installed and matching: exit 0, `curl` not called.
  - installed and not matching: removed without running; a good download takes its place.
  - installed and not matching, and the download bad: exit 1, nothing installed.
  - a good vendored copy: installed, `curl` not called.
  - a bad vendored copy: exit 1, `curl` not called, nothing installed.
  - no pinned SHA-256 for the platform (`uname` says `Linux aarch64`, the sums file has only
    linux-x64): exit 1, `curl` not called.
  - the repo's own `tools/tailwind-sha256.txt`: exactly the four lines above, and its first
    line is `# tailwindcss ` plus `tools/tailwind-version.txt`.
  - `pixi.toml`'s `tailwind-install` task is `bash tools/install-tailwind.sh`.

## Checks before merge

- The server suite (unit and integration in separate processes), the browser suite, and
  the docs build with `-W`.
- Break tests: each new check broken on purpose must turn a test red. At least: the
  middleware ignores `https_only`; `app.py` does not pass it; the reader takes an unknown
  value as off; the reader runs after the database; the compose port or `:?` reverted; the
  script skips the check on a download, on an installed file, on a vendored file; runs a
  file before the check; leaves a file that failed; writes straight to
  `.pixi/bin/tailwindcss`; a pinned hash changed; the task back inline.
- `docker compose config` with fake values on the branch's file: `host_ip: 127.0.0.1`; the
  two refusals of section 2.
- If this machine can build images: `docker build` runs the real download and passes the
  check; with one pinned hash changed in a scratch copy it stops at `RUN pixi run css`.
- Today's Sample Sheets: unchanged (nothing here touches them; checked anyway).
