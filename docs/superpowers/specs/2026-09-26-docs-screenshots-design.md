# SeqSetup documentation with screenshots — design

Date: 2026-09-26 · Base: `main` at `7a67538`

## Goal

Rewrite the SeqSetup **user guide** and **admin guide** so they describe the app as it is
today, with screenshots next to the text that show exactly what the text says. The
screenshots are made by a script that drives the real app, so they can be regenerated
with one command whenever the UI changes.

## Why

- `docs/user-guide/` and `docs/admin-guide/` were last written in Jan–Feb 2026, before
  the UI redesign, run templates, change history, paste preview, "fill in order", the
  kit-cycle limits, archived downloads and the `/api`. They describe an app that no
  longer exists.
- The docs contain no screenshots at all.
- The docs build has 13 errors: `.. http:get::` is used in
  `api-reference/runs.rst` (6), `api-reference/export.rst` (5) and
  `admin-guide/sample-api.rst` (2) but `sphinxcontrib-httpdomain` is not installed or
  enabled, so those sections render as error blocks.
- `getting-started/installation.rst` still publishes `admin` / `admin123` (security
  audit 2026-09, N-20).

## Readers

- **User guide:** lab staff who set up sequencing runs. Plain words, one task per
  section, numbered steps, a screenshot at each step where the screen changes.
- **Admin guide:** the people who run the app: users, login setup, index kits,
  instruments, profiles and config sync, LIMS connection, API tokens, logs.

## What gets written

User guide (rewrite; add pages where a feature has none):
dashboard; creating a run (new-run wizard); the run page and its steps; adding samples
(single, paste with preview, LIMS/worklist import); index kits and the kit picker;
assigning indexes (drag and drop, several in order, keyboard, ticked rows, "fill empty
samples in order"); lanes; override cycles; the check / validation page; Mark Ready and
back to Draft; downloads (Sample Sheet v2/v1, JSON, validation JSON/PDF; Ready and
Archived); archiving; run templates; change history; logging in.

Admin guide (rewrite): local users; login setup (LDAP/AD); index kits (upload, who may
remove); instruments; application and test profiles and config sync; LIMS (sample API)
connection; API tokens; logs.

Other pages — fix only what is wrong, no rewrite:
- `getting-started/`: remove the published weak default password; describe how the
  first admin is really created in the current code.
- `api-reference/` and `admin-guide/sample-api.rst`: rewrite the 13 `http:get` blocks
  as plain reStructuredText (heading, method + path, parameters, status codes) — no new
  dependency. Check each documented route, parameter and status code against
  `src/seqsetup/api/`.
- `architecture/`, `development/`: fix statements that are false today; leave the rest.

## How the screenshots are made

- A pytest module `tests/browser/test_docs_screenshots.py` reuses the browser test
  harness in `tests/browser/conftest.py` (app in a thread on a free 127.0.0.1 port,
  mongomock, logged-in page). It is **skipped unless `SEQSETUP_DOCS_SCREENSHOTS=1`**, so
  `pixi run smoke-browser` and the normal browser run are unchanged apart from the
  skipped tests.
- A pixi **task** (not a dependency) runs it:
  `docs-screenshots = { cmd = "SEQSETUP_DOCS_SCREENSHOTS=1 PYTHONPATH=src pytest tests/browser/test_docs_screenshots.py -q", depends-on = ["css"] }`.
- It seeds its own made-up demo data (run names like `DEMO-RUN-01`, sample ids like
  `SAMPLE-A01`, a demo index kit if needed). **No picture shows test-fixture data** (e.g.
  "Screenshot collision run", "browser-admin") and none shows anything that looks like
  a real patient identifier or a real password. The demo data is removed when the
  module ends, so running it inside a full browser session cannot change what other
  browser tests see.
- One helper does every capture: scroll the element the text talks about into view,
  draw a 3 px outline around it, take a PNG clipped to a named region around it (with
  padding), remove the outline. Viewport 1280×800, device scale 1, light theme.
  Output: `docs/_static/screenshots/<page>/<name>.png`.
- Every capture first asserts that its element exists and is visible, so a moved or
  removed control fails the run loudly instead of leaving a stale picture.
- All PNGs together stay under 15 MB (Pillow `optimize=True`).

## How the text stays true

- Every step in the text is a step the screenshot module performs. Every behavioral
  claim (what a button does, what is refused, what is required) is checked against the
  code or observed in the screenshot run. Nothing is described that the app does not
  do.
- Where the app behaves oddly or a feature is confusing, the text describes what it
  does, and the oddity is recorded for the human in the run's findings file. The app is
  not changed.
- Each figure is `.. figure::` with `:alt:` text and a caption saying what the outline
  marks.
- The docs build must pass `sphinx-build -W --keep-going -b html docs <out>` with zero
  warnings; the `docs` pixi task gains `-W --keep-going` so it stays that way.

## Not in scope

- Any change under `src/` (the app is not changed; oddities are reported instead).
- Hosting or publishing the docs site.
- The test screenshot baselines in `tests/browser/screenshots/` (they stay stale; see
  the separate note).
- New dependencies in `pixi.toml` / `pixi.lock` (a task entry is allowed).

## Done means

1. `pixi run docs-screenshots` regenerates every picture from nothing, all tests pass.
2. `sphinx-build -W --keep-going` → 0 warnings, 0 errors; every referenced image exists.
3. Normal suites unchanged: `tests/unit tests/integration` 1550 passed; `tests/browser`
   87 passed plus the docs tests skipped.
4. No change under `src/`, `tests/browser/screenshots/`, or in any existing test's
   assertions.
5. A human looks at the rendered pages and pictures before merge.
