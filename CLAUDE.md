# CLAUDE.md

## Context

SeqSetup is a **clinical-use** application for configuring Illumina DNA sequencing runs.
It generates Sample Sheets that directly control sequencer behavior. Errors in sample
identity, index assignment, or export output can lead to incorrect clinical results.

**Correctness and safety are non-negotiable. When in doubt, do less, not more.**

Technology: Python, FastAPI, Jinja2 (with jinja2-fragments), Tailwind v4,
Alpine.js, Pydantic v2, MongoDB, HTMX. Environment managed with Pixi.

## Architecture reference

This codebase follows the conventions in `ARCHITECTURE.md` (at the
repo root). Read that file before adding new routes, forms,
templates, or client-side interactions. It documents the stack
(FastAPI + Jinja2 + jinja2-fragments + Tailwind + Alpine.js + Pydantic),
naming rules, URL conventions, and the canonical reference implementations
to copy.

## What Claude Should and Should Not Do

### DO:
- Refactor for clarity
- Suggest improvements to robustness and readability
- Point out potential clinical pitfalls
- Ask clarifying questions if assumptions are unclear

### DO NOT:
- Assume clinical validity without evidence
- Introduce silent behavior changes

## Hard Rules

These rules must NEVER be violated. Each rule states the invariant and the
mechanism that enforces it; if you find yourself relying on "remembering"
to call something at every ingest point, prefer pushing the check down to
a model or service layer where it cannot be forgotten.

### Input sanitization
- **Bound every string at the model boundary.** Model fields (e.g. `Sample.sample_id`, `Run.run_name`) own their length and character constraints, validated both on construction (`__post_init__`) AND on later attribute assignment (`__setattr__` or property setter). Route handlers may use `sanitize_string(value, N)` (typically `N=256` for identifiers, `4096` for descriptions) as a fast clamp at the edge, but they MUST NOT be the only line of defense. Exception: the sample text in `SAMPLE_TEXT_LABELS` (`models/sample.py`: `sample_id`, `sample_name`, `project`, `test_id`, `worksheet_id`) is refused over `MAX_SAMPLE_TEXT` (256), never cut — a cut ID is another ID — by the model, by both parsers (naming the rows) and by the routes (`_too_long`, 400) before they call `sanitize_string`.
- **Bound every string at every ingest point.** Bulk-paste, LIMS import, and any other parser that strips cells must also clamp them — see `_MAX_CELL_LEN` / `_MAX_FIELD_LEN` (both `MAX_SAMPLE_TEXT` by name) in `services/sample_parser.py` and `services/sample_api.py` — except the sample text above and an i7 or i5 sequence, which each parser refuses over 256, rejecting the whole paste or worklist and naming its rows: a cut index is another index, and the cut could take a character that is not DNA away with it.
- Clamp all numeric inputs to valid ranges: `max(low, min(high, value))`. Apply at the model layer so re-assignment can't bypass it.
- Validate DNA sequences against `^[ACGTN]*$` after uppercasing — at the model layer, on every assignment (`Index.__setattr__` → `checked_sequence`), not only at construction. That rule (`^[ACGTN]*\Z`) is written once, `VALID_DNA_RE` in `models/index.py`, which the Index model, the paste, the LIMS import and the forms import (`tests/unit/test_dna_rule_and_bound_written_once.py` fails on another copy of it); a kit file's checks (`input_rules/kits.py`, `services/index_validator.py`) keep their own.
- Use `escape_js_string()` and `escape_html_attr()` from `utils/html.py` when embedding values in HTML or JavaScript. For JS string literals in Alpine/HTMX attributes, the project's canonical pattern is `{{ value | tojson }}` inside a single-quoted attribute (see `templates/admin/instruments.html`).
- Use `attachment_disposition()` from `routes/utils.py` to build a `Content-Disposition` value — it keeps the `filename` parameter ASCII (Starlette encodes header values as latin-1) and carries the name's own letters in `filename*`. `sanitize_filename()`, from the same module, scrubs the name that goes into it.
- Use `_escape_csv()` for all user-supplied values in SampleSheet output (BCLConvert, DRAGEN, and Cloud sections). Exception: identifiers (Sample_ID, Sample_Name, Sample_Project, LibraryName, ProjectName, RunName / Experiment Name) go through `_escape_identifier()`, which writes a value made only of `[A-Za-z0-9_-]` exactly — the formula guard's `'` prefix on a leading `-` would change the name — and falls back to `_escape_csv()` for anything else.

### Run state integrity
- Never allow mutations to a run unless it passes the `Depends(get_editable_run)` guard — DRAFT-only, raises HTTP 403 otherwise; and only for the user holding the run's edit lock, 409 otherwise (one person edits a Draft at a time; `services/edit_locks.py`, see `routes/dependencies.py`). When someone who did not hold the lock starts editing (Edit run, Take over), `routes/edit_lock.py` calls `RunRepository.mark_changed()` after writing the lock, so a change of the previous holder's already past its lock check fails the version check in `RunRepository.save`; Done editing marks nothing, so the holder's own last change is kept unless someone starts editing before it lands. `get_editable_run` must load the run before it checks the lock. A new way for someone to start editing a Draft must move its version too.
- Never expose draft runs via the API — only `ready` and `archived`.
- A run is deleted only through `RunRepository.delete_if_unchanged(run)`, which deletes the exact version that was loaded. The inherited id-only `BaseRepository.delete(item_id)` is overridden on `RunRepository` to raise, so the repository's API cannot delete a run without a version check (other repositories keep the inherited delete); `run_repo.collection` is still a raw PyMongo handle, and a `collection.delete_one({"_id": …})` on it deletes a run with no version check and no copy — that is how the browser tests clean up after themselves, and it must never appear in `src/`. A run whose `was_ready` is true is refused unless the call passes `copy_id=` — the id of the copy written for it — so a caller cannot forget the copy; `copy_id` is only checked for presence, not that it names a pending copy of this run, because proving that would put the copy store's logic inside a repository. Which runs may be deleted, and by whom, stays in the two routes that delete one: `routes/dashboard.py: delete_run` and `routes/run_templates.py: new_run_from_chosen_template`, which discards the blank draft only while it is still an empty, never-Ready draft.
- Always call `run.touch(updated_by=get_username(req))` before saving after mutations. The `saving_run(...)` context manager does this for you — prefer it over manual save calls so reviewers can grep `with saving_run(` to enumerate every mutation handler.
- Pre-generate all exports (samplesheet v2, v1, JSON, validation) when transitioning to Ready — the API serves pre-generated content, not live exports. That takes up to two minutes for a large run (the report's charts), so `update_status` is a plain `def` that Starlette runs on a side worker, not an `async def` on the event loop that serves everyone; the report draws each chart on its own `matplotlib.figure.Figure`, never through pyplot, whose current figure is shared between two people marking runs Ready at once. The UI export routes share this guarantee; they fall back to live generation only for runs created before pre-generation existed, and any new code path that mutates a Ready/Archived run must re-pre-generate.
- **Each export file is its own record, and the run names it.** Mark Ready writes the five files into `run_exports` (`repositories/run_export_repo.py`), one document each, and the run document carries only a manifest — `exports`, kind → `{"id", "sha256", "size"}`, checked on every assignment (`checked_exports`) and assigned whole, never merged into one already there. `services/run_exports.write_exports` refuses before writing anything when a file every Ready run must have came out empty (`_ALWAYS_REQUIRED`; reason `export_file_missing`) or when one record would be over 16 MiB less a margin (its own message and reason `export_file_too_large`), then inserts each and reads it straight back, hashing the returned bytes: a run never goes Ready naming a file that cannot be served, or missing one. Every file written is logged with the run id and the file ids — whether the write finished or failed part way — and every refusal after it **that writes an audit row** names those ids in it (`_files_left`); the two `ConflictError` paths (the run was deleted, or the version check failed) write no audit row at all, so for those the log line is the record. The files a refused attempt left are referenced by nothing and are never pruned. The collection is **insert-only** — `RunExportRepository` is deliberately not a `BaseRepository` (whose `save` upserts and whose `delete` removes by id), nothing in `src/` updates or deletes a record, and records of a failed Mark Ready or a deleted run's copy look unreferenced but must never be pruned. The five `generated_*` fields stay only for runs stored before this change; a run marked Ready by this release sets them all to None.
- **One function reads a stored export: `read_export(ctx, run, kind)`** (`services/run_exports.py`). For a run with a manifest the manifest is the only source: it hashes the bytes it is about to serve and compares them with the length and SHA-256 the run names (not the record's own fields, which a hand edit of the content leaves untouched), and raises `ExportDamaged` — 500 naming the file, audited `run.export.damaged`, never "try again" — for a record that is missing, of another run or another kind, bytes that do not add up, or a required kind the manifest does not name (v2, json, validation_json, validation_pdf always; v1 when the instrument writes one and `samplesheet_v1_withheld` is empty). It never reads a legacy field and never generates a file afresh for such a run. Only a run with no manifest is served from its own document, with the UI's live fallback. Every reader goes through it — the five UI downloads (`routes/export.py`, which re-raise `ExportDamaged` ahead of their catch-all), the five API endpoints (`api/app.py`), the API Exports pages (`routes/served_runs.py`, which show a damaged file on its own row), and `tools/check_broken_samplesheets.py` — and `tests/unit/test_no_legacy_export_reads.py` fails if any file but `models/sequencing_run.py` so much as names a `generated_*` field.
- READY→DRAFT clears the manifest and the legacy fields so a subsequent re-promotion never adopts files from before the edit cycle; the file records themselves stay (insert-only), so an archived run or a deleted run's copy that still names one never loses it. READY→ARCHIVED retains the manifest — archived runs serve those bytes via the API.
- Enforce state machine transitions via `check_status_transition()`: DRAFT→READY, READY→DRAFT, READY→ARCHIVED. ARCHIVED is terminal.
- Exports are only available for READY and ARCHIVED runs — enforce via `Depends(get_exportable_run)` (`routes/dependencies.py`).
- Transition to READY runs validation in real time via `ValidationService.validate_run()` and refuses if `error_count > 0`.
- Mark Ready refuses while a config sync's writes are unfinished. MongoDB here is a single server, so a sync's deletes and writes are not one step: before `GitHubSyncService.sync` deletes the application profiles, test profiles or instrument settings it notes that collection (`ProfileSyncConfigRepository.mark_writing()`, its own `settings` document, so a save of the sync settings cannot drop it), and only after the whole sync and the cache clears does `written()` strike off the collections it wrote — what a stopped sync left incomplete stays noted until a sync writes it again. Syncs run one at a time (`_SYNC_LOCK`, which holds because the app is one process). `update_status` checks the note before the checks and again just before saving, and also refuses when `validation_inputs_version()` changed in between (a sync that started and finished inside one Mark Ready). Because a sync deletes before it writes, it measures every kit, profile and instrument where it builds it (`_too_large_to_store` in `services/github_sync.py`, the export files' 16 MiB less a margin): one MongoDB could not store is a refused file, so nothing it would replace is deleted -- a kit file under the 10 MiB download cap can be over 16 MiB stored.

### Authentication and authorization
- All non-public routes require authentication — never add unprotected routes.
- Admin routes must use `require_admin_dep` (from `routes/dependencies.py`) as a router-level dependency — it raises HTTP 403 for non-admin users.
- Index kit upload requires admin — standard users cannot upload index kits.
- API routes require Bearer token auth — tokens stored as bcrypt hashes, never log or expose plaintext.
- Access the authenticated user via `req.scope.get("auth")`, API token via `req.scope.get("api_token")`.

### Data integrity
- **One clock.** Store every time with `utcnow()` (naive, meaning UTC) from `utils/clock.py`; show it with `{{ value | localtime }}` in templates, or `local_time()` / `local_date()` in Python, which convert to the `TZ` zone and add its name. Never read the local clock (`datetime.now()`) or format a stored time with `strftime` in a template — `tests/unit/test_one_clock.py` fails on both.
- **One Sample Sheet v2 writer.** `SampleSheetV2Exporter.export` requires both profile repositories and writes every application section, BCLConvert included, from the profiles a sample's test names (`services/sheet_plan.py`). A second writer for the case where they were not given -- hard-coded settings, another column order, and a global `OverrideCycles` line in `[BCLConvert_Settings]` -- ran only in tests, so 55 of 74 sheet assertions proved nothing about the sheet a lab gets (review TH-1); it is gone, with `_write_bclconvert_settings`, `_write_bclconvert_data` and the DRAGEN writers that only it used. A test that needs a sheet calls `tests/sheet_through_profiles.py: sheet(run)`, and an integration test that needs a run the checks let through calls `seed_profiles(ctx)` (`tests/integration/conftest.py`) instead of nulling the profile repositories.
- Validation services are **read-only** — they must never mutate run state.
- Repositories contain **no business logic** — they are thin data access layers.
- Models are **self-validating on every assignment, not just construction**, for any non-trivial invariant they declare. `Sample.__setattr__` enforces `barcode_mismatches_*` (clamp 0–2, the values BCL Convert accepts), `index*_cycles` (clamp >=1), `lanes` (filter to positive non-bool ints, each kept once, in first-seen order — a lane twice would put the sample's row in the sheet twice), `sample_id` (refused when its text is made only of zeros, whether it arrives as a string or as the JSON number `0` — a LIMS may use 0 for an empty well), `override_cycles` (regex), the sample text in `SAMPLE_TEXT_LABELS` (refused over 256, never cut; also on load, so a stored longer value makes its run unreadable), `index_kit_name` (256-char cap), `description` (4096), and the index slots -- `index1` takes only an i7 and `index2` only an i5 (`checked_index_slot` in `models/index.py`, which `IndexPair.__setattr__` shares), and `index_pair` only an `IndexPair`: the sheet writes Index from the first and Index2 from the second, so an index of the other kind there would misroute every read of that sample. `Index.__setattr__` holds its sequence to `VALID_DNA_RE` the same way, and refuses anything but text (a stored `null` or number used to open the run and fail later as a bare 500). A stored `override_cycles`, read or index override pattern the rule refuses makes the run **unreadable**, as a stored over-long sample text does -- `Sample.from_dict` used to drop it to None with a log line, and the sheet then carried a value worked out from the indexes instead of the one the document held. `SequencingRun.__setattr__` clamps `run_name` (256, no CR/LF), `run_description` (4096), and `barcode_mismatches_*`. When adding a model field whose validity is anything more than "any string of any length", enforce it in `__setattr__` (or a property setter) so the rule survives direct attribute writes from route handlers — `__post_init__` alone is insufficient. Routes still call `sanitize_string` at the boundary for trim semantics and visible 400s on oversize input; the model is the load-bearing backstop.
- **Validation cache coherence:** `ValidationService` memoizes results by `(run.id, run.updated_at, _VALIDATION_INPUT_VERSION)` — the version counter is bumped by `clear_validation_cache()`. Any mutation that changes validation *inputs* without bumping `run.updated_at` (GitHub config sync, index-kit save/delete, instrument enable/disable, etc.) MUST call `clear_validation_cache()`. See `services/validation.py` and existing call sites in `services/github_sync.py`, `routes/indexes.py`, `routes/admin/instruments.py`.
- **A change from a page that is out of date is refused, not applied.** The edit
  lock is held per user, so two tabs of one person both pass it, and
  `get_editable_run` reloads the run on every request, so `RunRepository.save`'s
  version check only catches a write landing inside one request. Every action
  that changes samples must therefore send what the page showed **for the field
  it changes**, one entry per targeted row in the order the rows are sent; the route
  compares each with the stored value **before it writes anything** and refuses
  409 with nothing written, naming the samples (`_changed_rows_refusal`), when one
  has moved. A request that sends no shown value is refused 400
  (no real client sends one: `/js/app.js?v=<content hash>` cannot be stale against
  the HTML), and a targeted sample the run no longer has is refused 409
  (`_targets_or_refusal`; the per-row box route answers its own 404 "Sample not
  found") — never skipped without a word. Covered so far: the four
  index routes (`target_indexes`, from `data-i7`/`data-i5`; outside review of
  f490536, F8), the lane panel's Apply (`target_lanes`, from `data-lanes`) and
  the rest of the bulk panel — `set-mismatches` (`target_mismatches`, the two
  boxes' `defaultValue`, and only the column the request writes is compared),
  `set-override-cycles` (`target_override_cycles`) and `set-test-id`
  (`target_tests`, from `data-test-id`/`data-test-version`; the Check page's fix
  boxes keep their own `only_if` check instead and send none). A field whose row
  box saves without redrawing the row (F3) is read from the box, never from a
  `data-*` that would be stale. The two deletes take the same `target_indexes`
  as the index routes (the row's `x` sends it in the query string: htmx 2 puts a
  DELETE's `hx-vals` there) and refuse a row whose index has moved, or a sample
  the run no longer has, rather than deleting it or answering as if it had. The
  per-row Override Cycles and MM boxes send `target_setting`, the box's own
  `defaultValue`, added in `htmx:configRequest` so a save waiting in the row's
  queue names what the save before it stored — and the box takes that stored
  value in an `htmx:afterRequest` listener, which htmx fires before it resumes
  the row's queue (F3's own XHR listener runs later still and does the rest).
  All four steps are built: `docs/design/2026-10-17-stale-page-checks-design.md`.
  No route changes a sample's ID, name or project: `update_sample`, which no
  page sent, was removed. `tests/unit/test_every_sample_change_checks_the_page.py`
  reads the routes from `routes/samples.py`'s router (however they were added)
  and fails on any that answers POST, PUT, PATCH or DELETE without reading one
  of its `SHOWN_VALUE_FIELDS` (`target_indexes`, `target_lanes`,
  `target_mismatches`, `target_override_cycles`, `target_tests`,
  `target_setting`), unless its `NEED_NO_SHOWN_VALUE` names the route and why
  (it only adds rows, saves nothing, or is held to a previewed plan's
  signature) — a new route must take the check or a reason.
- **Partial updates update only what was submitted.** Handlers serving per-field HTMX inputs (e.g. `update_sample_settings`) MUST check `field in form` before writing — defaulting missing fields to empty and writing them back silently destroys sibling values.
- **Several indexes dropped at once fill the rows in panel order.** `assign_indexes_bulk` sorts the dropped indexes into the kit's own list order (`_panel_position`, the order the index panel shows them) before it fills rows, and `app.js` sends them in that order (`inPanelOrder`, which the keyboard's one-index assign also uses); click order once gave the first sample the last-clicked index, a swap no check can see. A drop mixing index kinds or kits has no one order and is refused.
- **A kit's name and version mean one content.** `IndexKit.fingerprint()` is a sha256 of everything in the kit but its description, comments, owner and source, which reach no sample or sheet. Every index chip carries it (`data-kit-fingerprint`), `app.js` sends it with every drop and keyboard assign, and `_find_index` in `routes/samples.py` refuses (409) a drop whose fingerprint is not the stored kit's, or that sends none; the fill's plan signature holds it too. A sync refuses a kit file that keeps a stored synced kit's name and version with another fingerprint, and every file of a name and version two files give (`_refuse_changed_or_repeated_kits` in `services/github_sync.py`); the stored kit stays. A kit whose file left the repository is removed, so a later sync can bring its name and version back changed, as an upload after a delete can; a page loaded before still cannot assign from it. A drop from a page loaded before its kit changed once gave the sample sequences its chip never showed.
- **No page gives a sample no lane.** A new sample always gets a lane (paste and LIMS import need one, a sample added by hand gets lane 1); only an older sample, or a copy of one, can have none. `set_lanes_bulk` refuses an empty lane list ("Tick at least one lane."): with a `Lane` column, as in the shipped profile, no lane is a Check error (`lanes_not_picked`), and without one it means every lane. Apply with no lane ticked, and the old Clear, once saved it without a word. The lane panel's **All lanes** only ticks every lane box (`tickAllBulkLanes` in `app.js`), as the paste's does, so Apply lists every lane.
- **A Draft's flow cell and reagent kit are ones its instrument offers.** A flow cell the instrument does not list counts as one lane (`get_lanes_for_flowcell_by_name`), so every lane check and the sheet would see a one-lane run: Mark Ready once passed a run on a renamed 10B with lane 1 only and no lanes question. `ValidationService._validate_flowcell_offered` makes it an error on a Draft (`flowcell_not_offered`, `reagent_kit_not_offered`), and `update_flowcell` / `update_reagent_kit` refuse such a value (400, nothing saved).
- **A template holds a run's setup only.** `save_as_template` (`routes/run_templates.py`) saves the setup only when `scaffold_sample_ids` is missing or one empty JSON list; a non-empty list is refused (400, "A template holds a run's setup only…"), and anything else — not a list, sent twice, too deep to read — is refused as invalid (400). The page never sent any, but the route stored them, indexes and all, to copy into every run made from the template — a way to copy indexes that the index safety net (`tests/integration/test_index_safety_net.py`) does not drive. A template stored with samples before still makes its run with them.
- **A cycle change never replaces an Override Cycles typed by hand.** Every change to a run's cycle counts goes through `_set_run_cycles` (`routes/runs.py`: the cycle fields, Continue / Back to Run, and a reagent kit pick, which resets the counts to the kit's defaults). It changes nothing when the counts are the run's, and otherwise raises `TypedOverrideCyclesRefused` inside `saving_run` (nothing is saved; each route answers a plain-text 400 naming the samples, which `app.js` writes into the error banner) while `CycleCalculator.samples_with_typed_override_cycles(run)` lists any — a stored value that is not `calculate_override_cycles` for the sample and the old counts (typed by hand, or left by a cleared index), or, on a run with no counts, any stored value — because `update_all_sample_override_cycles` rebuilds every value from the indexes and the kit's read patterns. A UMI or skip typed by hand was once replaced with no word, and the new value fits the run, so Mark Ready could not see it. The same holds for the bulk panel: `set-override-cycles` rebuilds values only when it is told `mode=auto` (its Auto button); a request that does not say is an Apply, and an Apply with nothing typed is refused (400) -- it once acted as Auto (`tests/integration/test_override_apply_needs_a_value.py`), and `tests/unit/test_typed_override_cycles_in_sheet.py` holds that a typed value is the sheet's cell.
- **A paste never guesses an index column.** Without a header row `services/sample_parser.py` reads only the sample ID and the test (`_HEADERLESS_FIELDS`) and refuses a paste with anything in a third column; with a header row, a column whose name looks like an index or a lane (`_looks_like_index_or_lane`) but is not one it reads by name refuses the whole paste, naming it — the first column too, when it is read as the sample ID only because no column names one — and so does data in a column with no header name. Guessing once stored an i5 as the i7, and an unknown name such as `Index 2` dropped the index without a word. The LIMS import follows the same rules: `services/sample_api.parse_api_samples` refuses a worklist with a field that looks like an index or a lane but is not one it reads, or with two names for one index (`_INDEX_FIELDS`), and its samples go to the lanes picked on the import (`_picked_lanes` in `routes/samples.py`), which are part of the plan the import compares with its preview — never lane 1 unseen.
- **A settings file is read through `input_rules`, and only its checked value is used.** The reader (`input_rules/reader.py`) takes one plain spelling per value -- a whole number is plain digits, yes/no is `true`/`false`, a decimal or a date must be quoted -- and refuses YAML tags, anchors, merge keys and a key given twice (also two spellings of one key, `1:` and `true:`). The rulebook (`StrictRules` in `input_rules/base.py`) refuses an unknown key, converts nothing, and gives every whole number the range its consumers accept unchanged; a fact that changes a sheet or a check must be written out. Every problem keeps its file, line, column and place; a sync's problems reach the Config Sync page and its audit row, each cut to a byte budget that keeps the counts (`bounded_report`), and `pixi run check-settings <folder>` runs the same rules with no database. Built so far: instrument files, synced and local (`input_rules/instruments.py`); application and test profiles (`input_rules/profiles.py`; the keys inside `Settings` and `Data` stay open, their shape is checked; `services/profile_validator.py` is gone; a test lists the instrument's profiles under `TestApplicationProfiles` > `OnInstrument`, and an application profile whose `ApplicationType` is not `Dragen` is skipped as one for other tools, unless it names an Illumina application, which is refused: `docs/design/2026-10-19-lab-profile-layout-design.md`; a sample's test names its test profile by **TestName**, exactly, so several tests may share a TestType and a version, and one file per TestName and version is the repeat rule; a TestName that begins or ends with a space or holds a hidden character is refused (`ExactName256` in `input_rules/base.py`), as every page trims what is picked: `docs/design/2026-10-21-tests-by-name-design.md`); and **index kit files in every format** (`input_rules/kits.py`: one canonical kit rulebook, with each of the five shapes' own adapter in `services/index_parser.py` keeping its own refusals, and `input_rules/table.py` refusing a CSV column name given twice before any row is read). A kit's name and version are never invented: both are required in a synced file, and an upload takes them from the file or from the Kit name / Kit version boxes, which go through the same rules (`check_form_boxes`) and are refused rather than cut; a CSV, which carries neither, needs both boxes. The mode picked on the upload still wins and a file naming a different one is refused (`KitModeDiffers`). `services/index_validator.py` stays an ingest check on the built kit (semantic versions, the cycles equal to every index's length), and `_refuse_changed_or_repeated_kits` stays in the sync. **`config/mongodb.yaml`** is checked as the one **sensitive** input (`input_rules/database.py`, `check_yaml(..., sensitive=True)`): both `uri` and `database` are required, `uri` must begin `mongodb://` or `mongodb+srv://` (without a scheme pymongo reads the value as a host and connects with no authentication), `database` is at most 63 **bytes** and holds none of the characters MongoDB refuses, and `services/database.py: _load_config` raises one `ValueError` naming the file, the line and the place where a misspelt key meant `mongodb://localhost:27017` with no word. No message quotes a value of that file: the rulebook's own messages name no value, `check_yaml` masks a key the rulebook does not define, **and** it scrubs the file's own strings out of every message. `MONGODB_URI`/`MONGODB_DATABASE` keep their meaning and their values go through the same rules. **No test may reach the real database**: `tests/conftest.py`'s autouse `no_real_database` fixture points the suite at `mongodb://127.0.0.1:1`, replaces `services/database.py`'s `MongoClient` with a stub that raises, and resets `_client`/`_db` around every test (`tests/unit/test_no_test_reaches_a_real_database.py` also fails if any other file in `src/` builds a `MongoClient`). **Pasted samples and LIMS worklists are measured, not moved**: they are already the strictest inputs the app has, so `tests/unit/test_paste_and_worklist_outcomes.py` records what `read_pasted_samples` and `parse_api_samples` do with 132 paste texts, 97 worklist payloads and 4 read with a LIMS field mapping -- the samples field by field (every field of `ParsedSample`, taken from the dataclass), or the refusal's own exception type and words -- with a case for every column and field name either reader looks for and for three samples each carrying its own i7 and i5, so an index exchanged between two rows is seen, and for every immediate-against-deferred fault pair in both orders and on one row — today's refusals come in three stages and the precedence of two classes flips depending on whether they share a row. A change to either reader either keeps every line of it or is not made. The LIMS field table is the **read-only** module constant `services/sample_api.py: ALIAS_NAMES`, so the guard can walk it and nothing can rewire which field becomes a sample ID. The per-row checks do not move onto a rulebook (the user's word of 2026-10-20, `docs/design/2026-10-18-input-rules-design.md`, step 5); the record changed once since, on that word: an index sequence over 256 is refused, not cut. `tests/unit/test_input_rules_guard.py` fails on a rulebook that is not strict (a loosened config or field, a float, a `Literal` of numbers, a set, `Any`, or a validator that runs before the type check); a new instrument, profile or kit key needs its rulebook field and its line in the admin guide (`tests/unit/test_instruments_docs_keys.py`, `tests/unit/test_profiles_docs_keys.py`, `tests/unit/test_kits_docs_keys.py`).
- **Never silently discard rows.** Parsers that receive a worklist (`services/sample_parser.parse_pasted_samples`, `services/sample_api.parse_api_samples`) MUST raise `ValueError` listing the source line numbers of any row with content but no `sample_id`, and, separately, of any row whose `sample_id` is made only of zeros (`ZERO_SAMPLE_ID_RULE` in `models/sample.py` — a LIMS may use 0 for an empty well). Reject-the-whole-import is the clinical default — silently dropping a row routes that patient's reads into the Undetermined bucket. The bulk-paste route renders the parser's message in a banner; the worklist-import route surfaces it as an error message.
- Never silently discard data. If input is invalid, reject it (raise `HTTPException(400)` or let model `ValueError` propagate) or clamp it visibly.

### External API safety
- The LIMS API client (`services/sample_api.py`) uses SSL certificate verification via `ssl.create_default_context()`.
- **URLs are validated before fetching.** Hostnames are DNS-resolved and any resolved IP that is loopback, link-local, RFC1918 private, multicast, reserved, or unspecified is refused — this blocks SSRF pivots into the host's own networks. An operator whose LIMS lives on a private corporate network lists the networks it may be on in `SEQSETUP_LIMS_ALLOWED_NETS` (comma-separated CIDR); an address is allowed when it is public or lies inside a listed network. Link-local (`169.254.0.0/16`, `fe80::/10` — cloud instance metadata), multicast, unspecified and reserved addresses stay refused however they are listed, and a list that is not valid CIDR or that overlaps one of those ranges at all stops start-up (`check_lims_allowed_nets` in `services/sample_api.py`, called from `app.py`). Loopback is the one exception to that overlap rule: a network wholly inside `127.0.0.0/8` or `::1/128` may be listed (Python reads `::1` as reserved, so there is no narrower network to list), and loopback is refused whenever it is not listed. The removed `SEQSETUP_LIMS_ALLOW_PRIVATE_NETS` stops start-up while it is set at all. Plain HTTP is separately gated by `SEQSETUP_LIMS_ALLOW_HTTP=1`; production uses HTTPS exclusively so the api-key is not sent in clear.
- API responses are size-limited (10 MB) to prevent memory exhaustion.

## Conventions

### Route handler pattern (follow this order)

See `ARCHITECTURE.md` for the canonical patterns. Quick reference for
run-editing handlers:

```python
from typing import Annotated
from fastapi import Depends, Form
from .dependencies import get_editable_run, saving_run
from ..models.sequencing_run import SequencingRun

@router.post("/runs/{run_id}/samples", response_class=HTMLResponse)
def add_sample(
    request: Request,
    form: Annotated[AddSampleForm, Form()],
    run: SequencingRun = Depends(get_editable_run),
    ctx: AppContext = Depends(get_ctx),
):
    # 1. Pydantic Form() already validated + sanitized the inputs
    # 2. get_editable_run loaded the run AND raised 403 if not editable
    # 3. Mutate the model, then touch+save inside the CM:
    with saving_run(run, ctx, request):
        run.add_sample(form.to_sample())
    # 4. Return the rendered fragment (block_name="..." for HTMX swap):
    return render(request, "runs/edit.html", {...}, block_name="sample_table")
```

For admin-only routes, attach the dep at router level:
`router = APIRouter(dependencies=[Depends(require_admin_dep)])`.


### Models
- Python `@dataclass` with `to_dict()` / `from_dict()` for MongoDB serialization
- Validation and normalization in `__post_init__`
- Use `field(default_factory=...)` for mutable defaults (lists, datetimes)

### Tests
- Run with `pixi run test`
- Group by feature using test classes with docstrings
- Descriptive names: `test_verb_expected_behavior`
- Always test both valid and invalid inputs
- Test edge cases around security boundaries (draft vs ready, admin vs user)

## Working Style

- **Do not add features, refactoring, or "improvements" beyond what is asked.** This is clinical software — unnecessary changes increase risk.
- **Do not add comments, docstrings, or type annotations to code you didn't change.**
- **Read code before modifying it.** Understand the existing pattern before touching it.
- **Run tests after changes.** Do not assume correctness — verify it.
- **Ask before making architectural changes.** The existing patterns exist for reasons.
- **Design notes go in `docs/design/`** as `YYYY-MM-DD-<topic>-design.md` (see its README), not in `docs/superpowers/`. Implementation plans are not kept in the repository.

## Project Structure

```
src/seqsetup/
├── app.py              # FastAPI app creation, route registration
├── startup.py          # Repo initialization, service factories, DI setup
├── middleware.py        # AuthMiddleware (Starlette BaseHTTPMiddleware) — session + redirect on unauthenticated
├── context.py          # AppContext dataclass (dependency injection)
├── templating.py        # Jinja2 environment + render() helper
├── csrf.py              # OriginCheckMiddleware (state-changing requests)
├── rate_limit.py        # Token-bucket login limiter
├── security_headers.py  # CSP/X-Frame-Options/etc. response headers
├── body_limit.py        # Caps each request body by path (413)
├── exception_handlers.py # HTML/HTMX-aware HTTPException + 422 handlers
├── api/                 # FastAPI sub-app for /api/* (Bearer-auth JSON API + Swagger)
├── forms/               # Pydantic Form() validators (shared across routes)
├── templates/           # Jinja2 templates
│   ├── admin/           # Admin pages (auth, config-sync, instruments, logs, sample-api, users, api-tokens)
│   ├── runs/            # Edit-run page + per-section partials
│   ├── validation/      # Validation page + tab content partials
│   ├── wizard/          # New-run wizard + add-samples wizard partials
│   ├── indexes/         # Index kits list/import/detail
│   └── _app_shell.html, _base.html, _messages.html, etc.
├── models/              # Dataclasses — self-validating, with to_dict/from_dict
├── repositories/        # MongoDB access — thin, no business logic
│   └── base.py          # BaseRepository[T], SingletonConfigRepository[C]
├── routes/              # Request handlers — follow the pattern above
│   ├── utils.py         # Guards: check_status_transition, get_username, sanitize_*
│   └── dependencies.py  # get_editable_run, get_exportable_run, require_admin_dep, saving_run
├── services/            # Business logic — validation, export, LDAP, LIMS API
│   ├── validation.py    # Read-only validation orchestrator
│   ├── sample_api.py    # External LIMS API client (SSL verified, SSRF protected)
│   └── database.py      # MongoDB connection (timeout + health check on init)
├── input_rules/         # Reads and checks every settings file (strict Pydantic rulebooks, `pixi run check-settings`)
├── data/
│   └── instruments.py   # Instrument definitions (YAML + synced DB)
├── utils/
│   └── html.py          # escape_js_string, escape_html_attr
└── static/              # CSS, JS, images
```

## Key Files

| File | Purpose |
|------|---------|
| `routes/utils.py` | `check_status_transition()`, `get_username()`, `sanitize_string()`, `sanitize_filename()` (scrubs a download name), `attachment_disposition()` (builds the `Content-Disposition` value) |
| `routes/dependencies.py` | `get_ctx`, `get_editable_run`, `get_draft_run` (a Draft whoever holds its lock: only the four `/edit-lock` routes), `require_edit_lock`, `get_exportable_run`, `get_archivable_run`, `require_admin_dep`, `saving_run`, `is_htmx_request` |
| `utils/html.py` | `escape_js_string()`, `escape_html_attr()` — use these for all user data in HTML/JS |
| `models/sequencing_run.py` | `SequencingRun`, `RunStatus`, `RunCycles` — central data model |
| `models/sample.py` | `Sample` — DNA sequences validated here |
| `services/validation.py` | Index collision, color balance, application profile validation |
| `services/samplesheet_v2_exporter.py` | Sample Sheet v2 generation with `_escape_csv()` for all user data |
| `services/sample_api.py` | LIMS API client with SSL, SSRF protection, size limits |
| `services/database.py` | MongoDB connection with timeout and health check |
| `startup.py` | Application initialization, repository registry, `get_app_context()` |
| `context.py` | `AppContext` — all repos and service factories in one dataclass |
| `repositories/base.py` | `BaseRepository[T]` and `SingletonConfigRepository[C]` base classes |
| `csrf.py` | `OriginCheckMiddleware` — Origin/Host check on POST/PUT/PATCH/DELETE |

## Commands

```bash
pixi install          # Install the default environment (what the Docker image ships)
pixi install --all    # ... and the dev environment (pytest, playwright, sphinx, furo)
pixi run serve        # Run the application (localhost:5001)
pixi run test         # Run the unit and integration suites (pytest)
pixi run smoke-browser  # Run the browser suite (Playwright)
pixi run mock-api     # Start mock LIMS API server (localhost:8100)
pixi add <pkg>        # Add dependency
pixi add --feature dev <pkg>  # Add dev dependency
```

To point the app at the mock LIMS in dev, set both opt-ins (production must
not set either):

```bash
export SEQSETUP_LIMS_ALLOW_HTTP=1                     # mock LIMS speaks plain HTTP
export SEQSETUP_LIMS_ALLOWED_NETS=127.0.0.1/32        # mock LIMS lives on localhost
```

On a host whose `localhost` resolves to `::1` (Fedora/RHEL and macOS
defaults, and many container images), list IPv6 loopback too —
`SEQSETUP_LIMS_ALLOWED_NETS=127.0.0.1/32,::1/128` — or write `127.0.0.1`
in the LIMS URL instead of `localhost`.

## Run Status State Machine

```
Draft ──→ Ready ──→ Archived (terminal)
            │
            └──→ Draft (back to editing)
```

- **Draft**: Editable. Validation not required.
- **Ready**: Locked. All exports pre-generated. Accessible via API.
- **Archived**: Read-only historical record. Accessible via API. No transitions out.

Transition to Ready runs `ValidationService.validate_run()` inline and refuses if any errors are present. Export generation follows on success. Transition is enforced by `check_status_transition()` in `routes/utils.py`.
