# Sample Sheet Follow-ups Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** No profile value, mismatch value, invisible character or local instrument setting reaches a Sample Sheet unchecked or changed (spec `docs/superpowers/specs/2026-09-29-sheet-followups-design.md`).

**Architecture:**
- `services/sheet_text.py` stays the one source of the text rules: invisible format characters (Unicode Cf) join the hidden characters, and the mismatch rule is added there.
- `services/profile_validator.py` refuses the risky profile values at sync; `models/application_profile.py` reads an empty section as "none"; `services/samplesheet_v2_exporter.py` checks the same things again for a profile already in the database.
- `Sample`, `SequencingRun` and `RunTemplate` refuse a mismatch value that is not a whole number.
- `data/instruments.py` checks the local instruments file at start with the sync's own check.

**Tech Stack:** Python, FastAPI, pytest (mongomock in integration tests), PyYAML, Sphinx.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-09-29-sheet-followups-design.md` (commit `2e6b665`). The spec wins over this plan where they disagree; record each case.
- Worktree `.worktrees/sheet-followups` (under the main checkout), branch `fix/sheet-followups`. It holds `main` at `97dc047` plus the spec and this plan. **Base for every diff and review: `97dc047`.** Run everything from the worktree root.
- `PY=../../.pixi/envs/default/bin/python` (the main checkout's Pixi env).
  - Tests: `PYTHONPATH=src $PY -m pytest <paths> -q -p no:cacheprovider`.
  - Never `pixi run` in the worktree, and no `-n`.
- A Bash call is cut at 600 s. The server suite runs as 13 parts at once (below, "the server suite"); about 3 minutes.
- CSS for browser tests (`app.css` is gitignored): `../../.pixi/bin/tailwindcss -i src/seqsetup/static/css/input.css -o src/seqsetup/static/css/app.css --minify`. No template changes in this plan.
- Docs: `$PY -m sphinx -W --keep-going -q -b html docs <a scratch dir outside the repo>`; judge by the exit code.
- Baseline at `97dc047`: server **2362 passed** (unit 1713, integration 649); browser **102 passed, 54 skipped**. Task 0 measures them.
- Clinical: tests first and seen failing; no silent behaviour change. When in doubt, do less.
- Never `git stash`, `checkout --`, `restore`, `reset --hard`, `clean`, `--amend`, rebase. To undo your own edit, edit it back.
- Stage named paths only: never `git add -A` or `git add .`. A tool writes an untracked `graft/` index into checkouts.
- Committed files carry **no absolute home paths**. The repo is public.
- Not changed: `config/` (every shipped file must pass the new checks as it is), templates, routes, `static/`, screenshot baselines, doc pictures, the JSON export, the API, `validate_instrument_yaml` itself.
- Messages, exactly:
  - sync, a decimal value: `Field '<Settings|Data>' value for '<key>' is a number with a decimal point, which YAML may have changed (4.10 is read as 4.1). Put the value in quotes, for example "4.10".`
  - sync, a mapping or list value: `Field '<Settings|Data>' value for '<key>' is a <mapping|list>; a value must be text, a whole number or true/false.`
  - sync, an empty value: `Field '<Settings|Data>' value for '<key>' is empty. Write '' if it should be empty.`
  - sync, a decimal version: `Field '<name>' is a number with a decimal point, which YAML may have changed (1.10 is read as 1.1). Put the version in quotes, for example "1.10".` (`<name>`: `ApplicationProfileVersion`, `Version`, or `ApplicationProfiles[<i>].ApplicationProfileVersion`)
  - sync, an empty required field: the existing `Field '<name>' must not be empty` and `ApplicationProfiles[<i>]: '<name>' must not be empty`.
  - sync, mismatch: `Field 'Settings' value for '<key>' fills <column> and must be 0, 1 or 2 (BCL Convert allows at most 2 mismatches): <repr>` / `Field 'Data' value for '<key>' fills <column> and must be 0, 1, 2, blank or na (BCL Convert allows at most 2 mismatches): <repr>`
  - sync, no Sample_ID column: `The data section has no Sample_ID column. Add Sample_ID to DataFields (or to Data when DataFields is missing or empty).`
  - writer: `A profile value must be text, a whole number or true/false, not <repr>` / `<column> in the profile's Settings must be 0, 1 or 2: <repr>` / `<column> in the profile's Data must be 0, 1, 2, blank or na: <repr>` / `The <ApplicationName>_Data section has no Sample_ID column`
  - models: `<field> must be a whole number, not <repr>`
  - Mark Ready, added at the end of the hidden-character message: `If you cannot see it, delete the text and type it again.` (`them` for several characters)
  - instruments file: `<file name> has errors, so SeqSetup will not start: <problem>; <problem>; ...`, a problem being `<instrument>: <the check's own error text>`, `<instrument>: could not be checked: <error>`, `<instrument>: must be a mapping`, `cannot be read as YAML: <error>`, `must be a mapping at the top level` or `'instruments' must be a mapping`.
- Commit trailer: `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`.

**The server suite** (use this wherever a step says "run the server suite"):

```bash
LOGS=<a scratch dir outside the repo>; mkdir -p "$LOGS"; rm -f "$LOGS"/*.log
PYTHONPATH=src $PY -m pytest tests/unit -q -p no:cacheprovider > "$LOGS/unit.log" 2>&1 &
for k in 0 1 2 3 4 5 6 7 8 9 10 11; do
  PYTHONPATH=src $PY -m pytest $(ls tests/integration/test_*.py | sort | awk -v k=$k 'NR%12==k') \
    -q -p no:cacheprovider > "$LOGS/int$k.log" 2>&1 &
done
wait
grep -h -E "^[0-9]+ (passed|failed)|^=+ .*(passed|failed|error)" "$LOGS"/*.log
grep -l -E "[0-9]+ (failed|error)" "$LOGS"/*.log || echo "no failures"
```

Add up the `passed` numbers of the 13 logs. A part that ends with no summary line was killed (the machine is shared): run that part again on its own. The integration parts run in separate processes on purpose (each test builds a fresh app; mongomock and per-test temporary paths keep them apart).

## Plan-level decisions (spec clarifications; record, do not re-decide)

1. **The v2 sheet writes no sample name.** Its safety-net tests use the run name (written in `[Header]`) and a sample ID in `[Cloud_Data]` (through `_write_cloud_sections`). The v1 test uses a sample name.
2. **An instrument problem is the check's own text**, `<field>: <message> (got: '<value>')` (`ValidationError.__str__`, the same text a sync logs), after the instrument's name. The spec's `(<value>)` is this.
3. **The Sample_ID rule skips a profile whose `Data`, `DataFields` or `Translate` has the wrong shape**: that is already reported, and the columns cannot be worked out.
4. **The writer checks a profile mismatch value after `_escape_config_cell`**, so a line break or a leading `[` is still reported with its existing message (existing tests expect those).
5. **A `Data` mismatch default is checked where it is used**: for a sample with no value of its own. A sample's own value is written as before (the model keeps it a whole number 0-2).
6. **The start code at the bottom of `data/instruments.py` moves into `_initialize_at_start()`**, called at the same place, doing the same thing, so a missing file at start can be tested.
7. **Existing tests changed by the new rules:** `test_numbers_booleans_and_empty_values_are_accepted` asserted that `None` and `1.5` pass; it becomes `test_numbers_and_booleans_are_accepted`. `VALID_NON_DRAGEN_PROFILE` and `TestApplicationNameCharacters.BASE` gain `DataFields: [Sample_ID]`: without a Sample_ID column they are refused now.
8. **A run stored with `true` as a mismatch value** fails while it is loaded, before any route code runs. The app has no handler for that `ValueError`, so the test client raises it; the test checks that, and that the stored document did not change.
9. **What the sync logs is read with a handler on the `seqsetup.services.github_sync` logger**, not `caplog`: once an app has started in the test session, the log viewer's filter sits on the root handlers and can rewrite records.

## How this plan was checked

Before this plan was committed, every step of Tasks 1-8 was applied, as printed, to a
scratch copy of `2e6b665` by a script (each Find had to match exactly once), and the tests
were run there:
- every step fitted the code it names;
- each red step failed exactly as stated (Task 1: 12 failed, 5 passed; Task 2: 32 failed,
  11 passed; Task 3: 27 failed, 17 passed; Task 4: 4 failed, 1 passed, with the
  `None.items()` error; Task 5: 22 failed, 3 passed; Task 6: 31 failed, 16 passed; Task 7:
  the import error), and each green step passed with the numbers stated;
- after Task 8 the server suite gave **2559 passed**, 0 failed (unit 1713 → 1903,
  integration 649 → 656), and the docs built with `-W` (exit 0);
- all 25 break tests turned red. Two rows of the table were corrected from what the dry
  run showed (3: the stored-profile sync tests go red too; 20: the `text-1` cases go red
  too), and the break-test steps now say `PYTHONDONTWRITEBYTECODE=1` (see Task 9).

The browser suite was not run in the dry run: no template, route or script changes.

## File map

| File | What changes |
|---|---|
| `src/seqsetup/services/sheet_text.py` | Cf counts as hidden; `MISMATCH_COLUMNS`, `is_allowed_mismatch` |
| `src/seqsetup/services/validation.py` | the hidden-character message gains one sentence |
| `src/seqsetup/services/profile_validator.py` | value kinds, decimal versions, empty required fields, mismatch range, Sample_ID column |
| `src/seqsetup/models/application_profile.py` | empty sections read as `{}` / `[]`; docstring example `1.0.0` |
| `src/seqsetup/services/samplesheet_v2_exporter.py` | the safety net |
| `src/seqsetup/models/sample.py`, `sequencing_run.py`, `run_template.py` | `checked_mismatches` |
| `src/seqsetup/data/instruments.py` | `InstrumentConfigError`, `load_checked_instrument_file`, `_initialize_at_start` |
| `tests/unit/test_instrument_file_check.py`, `tests/integration/test_sheet_followups.py` | new |
| six existing unit test files | new test classes; three fixtures/tests changed (decision 7) |
| `docs/admin-guide/profiles.rst`, `docs/admin-guide/instruments.rst`, `docs/user-guide/validation.rst` | Task 8 |

---

### Task 0: Set up and record the baseline

**Files:** none changed.

- [ ] **Step 1: Check the tree and build CSS**

```bash
git branch --show-current            # fix/sheet-followups
git log --oneline -4                 # the plan commit, 2e6b665, 9412424 (or the spec commits), b0387f2 (merge of main)
PYTHONPATH=src ../../.pixi/envs/default/bin/python -c "import seqsetup; print(seqsetup.__file__)"
# must print a path under .worktrees/sheet-followups/src/
../../.pixi/bin/tailwindcss -i src/seqsetup/static/css/input.css -o src/seqsetup/static/css/app.css --minify
```

- [ ] **Step 2: Run the server suite and the browser suite**

Expected: **2362 passed** (unit 1713, integration 649). Browser (`PYTHONPATH=src $PY -m pytest tests/browser -q -p no:cacheprovider`): **102 passed, 54 skipped**. Write down what you measure. Any other number: find out why before Task 1.

---

### Task 1: Invisible characters (spec §3)

**Files:**
- Modify: `src/seqsetup/services/sheet_text.py` (`hidden_characters`)
- Modify: `src/seqsetup/services/validation.py` (`_hidden_character_message`)
- Test: `tests/unit/test_sheet_text.py`, `tests/unit/test_sample_text_validation.py`, `tests/unit/test_samplesheet_v1_exporter.py`, `tests/unit/test_samplesheet_v2_exporter.py`, `tests/integration/test_sheet_followups.py` (create)

**Interfaces:**
- Produces: `hidden_characters(text)` also returns Unicode category Cf characters. `tests/integration/test_sheet_followups.py` with `ORIGIN` (later tasks add to it).

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_sheet_text.py`:

```python
class TestInvisibleFormatCharacters:
    """Unicode format characters (category Cf) cannot be seen, and the
    direction marks and overrides can change the order a name is shown in,
    so they count as hidden (spec 2026-09-29 Sample Sheet follow-ups, §3)."""

    @pytest.mark.parametrize("char", [
        pytest.param("​", id="ZERO-WIDTH-SPACE"),
        pytest.param("﻿", id="BYTE-ORDER-MARK"),
        pytest.param("­", id="SOFT-HYPHEN"),
        pytest.param("‎", id="LEFT-TO-RIGHT-MARK"),
        pytest.param("‮", id="RIGHT-TO-LEFT-OVERRIDE"),
    ])
    def test_format_character_is_hidden(self, char):
        assert hidden_characters(f"a{char}b") == [char]

    @pytest.mark.parametrize("text", [
        pytest.param("Plain text 1-2_3", id="plain"),
        pytest.param("no break", id="NO-BREAK-SPACE"),
        pytest.param("Åsa Öberg", id="latin"),
        pytest.param("Ωμέγα", id="greek"),
        pytest.param("试验", id="cjk"),
    ])
    def test_visible_text_is_not(self, text):
        assert hidden_characters(text) == []
```

Append to `tests/unit/test_sample_text_validation.py`:

```python
class TestInvisibleCharactersInText:
    """A zero-width space or another invisible format character is a hidden
    character too, and the message says how to remove what cannot be seen
    (spec 2026-09-29 Sample Sheet follow-ups, §3)."""

    def test_zero_width_space_in_sample_name_is_an_error(self):
        run = _run_with(Sample(sample_id="S1", sample_name="A​B"))

        errors = _errors(run, "hidden_character_in_text")

        assert [e.message for e in errors] == [
            "Sample 'S1' has a hidden character in its sample name: U+200B. Hidden "
            "characters can break the Sample Sheet. Remove it before marking the run "
            "ready. If you cannot see it, delete the text and type it again."
        ]

    def test_several_characters_are_called_them(self):
        run = _run_with(Sample(sample_id="S1", project="P​﻿"))

        errors = _errors(run, "hidden_character_in_text")

        assert len(errors) == 1
        assert errors[0].message.endswith(
            "Remove them before marking the run ready. If you cannot see them, "
            "delete the text and type it again."
        )

    def test_direction_override_in_run_name_is_an_error(self):
        run = _run_with(Sample(sample_id="S1"))
        run.run_name = "Run‮1"

        errors = _errors(run, "hidden_character_in_text")

        assert len(errors) == 1
        assert errors[0].message.startswith(
            "The run has a hidden character in its name: U+202E."
        )
```

Append to `tests/unit/test_samplesheet_v1_exporter.py`:

```python
class TestInvisibleCharacters:
    """The v1 writer refuses a zero-width space like any hidden character
    (spec 2026-09-29 Sample Sheet follow-ups, §3)."""

    def test_zero_width_space_in_sample_name_is_refused(self, sample_run):
        sample_run.samples[0].sample_name = "Sample​One"

        with pytest.raises(ValueError, match="U\\+200B"):
            SampleSheetV1Exporter.export(sample_run)
```

In `tests/unit/test_samplesheet_v2_exporter.py`, find:

```python
from pathlib import Path

import pytest
```

Replace with:

```python
from io import StringIO
from pathlib import Path

import pytest
```

and append to the same file:

```python
class TestInvisibleCharacters:
    """The v2 writer refuses a zero-width space like any hidden character. It
    writes no sample name: the run name reaches [Header], and each sample ID
    reaches [Cloud_Data] (spec 2026-09-29 Sample Sheet follow-ups, §3)."""

    def test_zero_width_space_in_run_name_is_refused(self, sample_run):
        sample_run.run_name = "Run​1"

        with pytest.raises(ValueError, match="U\\+200B"):
            SampleSheetV2Exporter.export(sample_run)

    def test_zero_width_space_in_cloud_data_is_refused(self, sample_run):
        sample_run.samples[0].sample_id = "S​1"

        with pytest.raises(ValueError, match="U\\+200B"):
            SampleSheetV2Exporter._write_cloud_sections(StringIO(), sample_run)
```

Create `tests/integration/test_sheet_followups.py`:

```python
"""Sample Sheet follow-ups through the real routes and a real config sync
(spec 2026-09-29 Sample Sheet follow-ups)."""

from .conftest import disable_repos
from .test_sheet_safety import _seed_draft

ORIGIN = {"Origin": "http://testserver"}


class TestInvisibleCharacterStopsMarkReady:
    """A zero-width space in a sample's description keeps the run in Draft,
    with the message (spec §3)."""

    def test_zero_width_space_in_description_is_refused(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        run_id = _seed_draft(ctx, "zw-desc")
        run = ctx.run_repo.get_by_id(run_id)
        run.samples[0].description = "Tube​7"
        ctx.run_repo.save(run)

        resp = logged_in_client.post(f"/runs/{run_id}/status/ready", headers=ORIGIN)

        assert resp.headers.get("HX-Retarget") == "#ready-message"
        assert "U+200B" in resp.text
        assert "If you cannot see it, delete the text and type it again." in resp.text
        stored = ctx.run_repo.get_by_id(run_id)
        assert stored.status.value == "draft"
        assert not stored.generated_samplesheet_v2
```

- [ ] **Step 2: Run them and see them fail**

```bash
PYTHONPATH=src $PY -m pytest tests/unit/test_sheet_text.py::TestInvisibleFormatCharacters \
  tests/unit/test_sample_text_validation.py::TestInvisibleCharactersInText \
  tests/unit/test_samplesheet_v1_exporter.py::TestInvisibleCharacters \
  tests/unit/test_samplesheet_v2_exporter.py::TestInvisibleCharacters \
  tests/integration/test_sheet_followups.py -q -p no:cacheprovider
```

Expected: **12 failed, 5 passed**. The 5 that pass are the visible-text guards; every other test fails because a Cf character is not hidden yet.

- [ ] **Step 3: Implement**

In `src/seqsetup/services/sheet_text.py`, find:

```python
def hidden_characters(text: str | None) -> list[str]:
    """The distinct hidden characters in ``text``, in order of first
    appearance: control characters (Unicode category Cc) and the Unicode
    line and paragraph separators."""
    return [
        c for c in dict.fromkeys(text or "")
        if unicodedata.category(c) == "Cc" or c in _SEPARATORS
    ]
```

Replace with:

```python
def hidden_characters(text: str | None) -> list[str]:
    """The distinct hidden characters in ``text``, in order of first
    appearance: control characters (Unicode category Cc), format characters
    (Cf: the zero-width space, byte-order mark, soft hyphen, and the
    direction marks and overrides, which can change the order a name is
    shown in) and the Unicode line and paragraph separators."""
    return [
        c for c in dict.fromkeys(text or "")
        if unicodedata.category(c) in ("Cc", "Cf") or c in _SEPARATORS
    ]
```

In `src/seqsetup/services/validation.py`, find:

```python
        many = len(chars) > 1
        return (
            f"{subject} has {'hidden characters' if many else 'a hidden character'} "
            f"in its {' and '.join(fields)}: {describe(chars)}. Hidden characters "
            f"can break the Sample Sheet. Remove {'them' if many else 'it'} before "
            f"marking the run ready."
        )
```

Replace with:

```python
        many = len(chars) > 1
        pronoun = "them" if many else "it"
        return (
            f"{subject} has {'hidden characters' if many else 'a hidden character'} "
            f"in its {' and '.join(fields)}: {describe(chars)}. Hidden characters "
            f"can break the Sample Sheet. Remove {pronoun} before marking the run "
            f"ready. If you cannot see {pronoun}, delete the text and type it again."
        )
```

- [ ] **Step 4: Run them and the files around them**

Run the Step 2 command: **17 passed**. Then:

```bash
PYTHONPATH=src $PY -m pytest tests/unit/test_sheet_text.py tests/unit/test_sample_text_validation.py \
  tests/unit/test_samplesheet_v1_exporter.py tests/unit/test_samplesheet_v2_exporter.py \
  tests/unit/test_profile_validator.py tests/integration/test_sheet_safety.py \
  tests/integration/test_mark_ready_sample_text_line_breaks.py -q -p no:cacheprovider
```

Expected: no failures (the shipped profiles hold no Cf character; checked while planning).

- [ ] **Step 5: Commit**

```bash
git add src/seqsetup/services/sheet_text.py src/seqsetup/services/validation.py \
  tests/unit/test_sheet_text.py tests/unit/test_sample_text_validation.py \
  tests/unit/test_samplesheet_v1_exporter.py tests/unit/test_samplesheet_v2_exporter.py \
  tests/integration/test_sheet_followups.py
git commit -m "fix(sheet): invisible format characters count as hidden (Sample Sheet follow-ups §3)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Profile values YAML changed, empty values, versions (spec §1)

**Files:**
- Modify: `src/seqsetup/services/profile_validator.py`
- Test: `tests/unit/test_profile_validator.py`, `tests/integration/test_sheet_followups.py`

**Interfaces:**
- Produces (in `profile_validator.py`): `_is_empty(value) -> bool`, `_decimal_version(field_path: str) -> str`, `_value_kind_problem(field: str, key, value) -> str | None`. In `tests/unit/test_profile_validator.py`: `APP`, `TEST`, `_errors(data) -> list[str]`, `_test_profile_errors(data) -> list[str]`, `_with(field, **entries) -> dict` (Tasks 3 and 4 use them). In `tests/integration/test_sheet_followups.py`: `_sync(ctx, monkeypatch, app_profile_files) -> (ok, message, count)`, `_app_profile_yaml(name, software_version) -> str`.

- [ ] **Step 1: Write the failing tests**

In `tests/unit/test_profile_validator.py`, find:

```python
    def test_numbers_booleans_and_empty_values_are_accepted(self):
        validate_application_profile_yaml({
            **self.BASE,
            "Settings": {"Threads": 8, "Trim": True, "Empty": None},
            "Data": {"Extra": 1.5},
        })
```

Replace with (decision 7: `None` and `1.5` are refused now, below):

```python
    def test_numbers_and_booleans_are_accepted(self):
        validate_application_profile_yaml({
            **self.BASE,
            "Settings": {"Threads": 8, "Trim": True, "Empty": ""},
            "Data": {"Extra": 2},
        })
```

Append to the same file:

```python
# --- Sample Sheet follow-ups (spec 2026-09-29) ---

APP = {
    "ApplicationProfileName": "P",
    "ApplicationProfileVersion": "1.0.0",
    "ApplicationName": "BCLConvert",
    "ApplicationType": "Custom",
    "Settings": {"SoftwareVersion": "4.3.6"},
    "Data": {"Sample_ID": ""},
}
TEST = TestValidateTestProfile.VALID_TEST_PROFILE
DECIMAL_VALUE = (
    "is a number with a decimal point, which YAML may have changed (4.10 is read "
    'as 4.1). Put the value in quotes, for example "4.10".'
)
DECIMAL_VERSION = (
    "is a number with a decimal point, which YAML may have changed (1.10 is read "
    'as 1.1). Put the version in quotes, for example "1.10".'
)


def _errors(data: dict) -> list[str]:
    """The application-profile check's messages; [] when it passes."""
    try:
        validate_application_profile_yaml(data)
    except ProfileValidationError as e:
        return e.errors
    return []


def _test_profile_errors(data: dict) -> list[str]:
    """The test-profile check's messages; [] when it passes."""
    try:
        validate_test_profile_yaml(data)
    except ProfileValidationError as e:
        return e.errors
    return []


def _with(field: str, **entries) -> dict:
    """APP with more entries in its Settings or Data."""
    return {**APP, field: {**APP[field], **entries}}


class TestProfileValueKinds:
    """A Settings or Data value is written into the Sample Sheet with str().
    YAML has already changed a decimal number (4.10 is read as 4.1), an empty
    value is None, and a mapping or a list would be written as Python text,
    so these are refused. Text, whole numbers and true/false pass, as today
    (spec 2026-09-29 Sample Sheet follow-ups, §1)."""

    @pytest.mark.parametrize("field", ["Settings", "Data"])
    @pytest.mark.parametrize("value", [
        pytest.param(4.1, id="4.10"),
        pytest.param(1.0, id="1.0"),
        pytest.param(float("inf"), id="inf"),
        pytest.param(float("nan"), id="nan"),
    ])
    def test_decimal_number_is_refused(self, field, value):
        assert _errors(_with(field, Extra=value)) == [
            f"Field '{field}' value for 'Extra' {DECIMAL_VALUE}"
        ]

    @pytest.mark.parametrize("field", ["Settings", "Data"])
    @pytest.mark.parametrize("value,kind", [
        pytest.param({"SoftwareVersion": "4.10"}, "mapping", id="mapping"),
        pytest.param(["a", "b"], "list", id="list"),
    ])
    def test_mapping_or_list_is_refused(self, field, value, kind):
        assert (
            f"Field '{field}' value for 'Extra' is a {kind}; a value must be text, "
            "a whole number or true/false."
        ) in _errors(_with(field, Extra=value))

    def test_a_mapping_holding_a_decimal_is_refused_as_a_mapping(self):
        # Astra review P6: it was written as "{'SoftwareVersion': 4.1, 'Unset': None}".
        assert _errors(_with("Data", Options={"SoftwareVersion": 4.1, "Unset": None})) == [
            "Field 'Data' value for 'Options' is a mapping; a value must be text, "
            "a whole number or true/false."
        ]

    @pytest.mark.parametrize("field", ["Settings", "Data"])
    def test_empty_value_is_refused(self, field):
        assert _errors(_with(field, Extra=None)) == [
            f"Field '{field}' value for 'Extra' is empty. Write '' if it should be empty."
        ]

    @pytest.mark.parametrize("value", [
        pytest.param("4.10", id="quoted-4.10"),
        pytest.param("", id="empty-text"),
        pytest.param(8, id="8"),
        pytest.param(0, id="0"),
        pytest.param(True, id="true"),
        pytest.param(False, id="false"),
    ])
    def test_text_whole_numbers_and_true_false_pass(self, value):
        data = {
            **APP,
            "Settings": {**APP["Settings"], "Extra": value},
            "Data": {**APP["Data"], "Extra": value},
        }
        assert _errors(data) == []


class TestProfileVersions:
    """A version YAML read as a decimal number may have changed (1.10 is read
    as 1.1), so two versions could collide; it must be quoted (spec
    2026-09-29 Sample Sheet follow-ups, §1)."""

    def test_application_profile_version_is_refused(self):
        assert _errors({**APP, "ApplicationProfileVersion": 1.1}) == [
            f"Field 'ApplicationProfileVersion' {DECIMAL_VERSION}"
        ]

    def test_test_profile_version_is_refused(self):
        assert _test_profile_errors({**TEST, "Version": 1.1}) == [
            f"Field 'Version' {DECIMAL_VERSION}"
        ]

    def test_reference_version_is_refused(self):
        refs = [{"ApplicationProfileName": "P", "ApplicationProfileVersion": 1.1}]
        assert _test_profile_errors({**TEST, "ApplicationProfiles": refs}) == [
            f"Field 'ApplicationProfiles[0].ApplicationProfileVersion' {DECIMAL_VERSION}"
        ]

    def test_unquoted_1_10_and_1_1_can_no_longer_collide(self):
        # Astra review P1: both were stored as the version "1.1".
        first = yaml.safe_load("v: 1.10")["v"]
        second = yaml.safe_load("v: 1.1")["v"]
        assert first == second == 1.1
        assert _errors({**APP, "ApplicationProfileVersion": first})
        assert _errors({**APP, "ApplicationProfileVersion": second})

    @pytest.mark.parametrize("version", [
        pytest.param("1.10", id="quoted"),
        pytest.param("1.0.0", id="three-part"),
        pytest.param(2, id="whole-number"),
    ])
    def test_quoted_and_whole_versions_pass(self, version):
        assert _errors({**APP, "ApplicationProfileVersion": version}) == []
        assert _test_profile_errors({**TEST, "Version": version}) == []


class TestEmptyRequiredFields:
    """A required field left empty is None to YAML, and passed as the text
    "None" (spec 2026-09-29 Sample Sheet follow-ups, §1)."""

    @pytest.mark.parametrize("field", [
        "ApplicationProfileName", "ApplicationProfileVersion", "ApplicationName", "ApplicationType",
    ])
    def test_application_profile_field(self, field):
        assert f"Field '{field}' must not be empty" in _errors({**APP, field: None})

    @pytest.mark.parametrize("field", ["TestType", "TestName", "Description", "Version"])
    def test_test_profile_field(self, field):
        assert f"Field '{field}' must not be empty" in _test_profile_errors({**TEST, field: None})

    @pytest.mark.parametrize("key", ["ApplicationProfileName", "ApplicationProfileVersion"])
    def test_reference_field(self, key):
        ref = {"ApplicationProfileName": "P", "ApplicationProfileVersion": "~=1.0.0", key: None}
        assert (
            f"ApplicationProfiles[0]: '{key}' must not be empty"
            in _test_profile_errors({**TEST, "ApplicationProfiles": [ref]})
        )
```

In `tests/integration/test_sheet_followups.py`, find:

```python
from .conftest import disable_repos
from .test_sheet_safety import _seed_draft
```

Replace with:

```python
import logging

from .conftest import disable_repos
from .test_sheet_safety import _seed_draft
```

and append to the same file:

```python
_SYNC_LOGGER = logging.getLogger("seqsetup.services.github_sync")

TEST_PROFILE_YAML = (
    "TestType: WGS\n"
    "TestName: WGS\n"
    "Description: Whole genome\n"
    'Version: "1.0.0"\n'
    "ApplicationProfiles:\n"
    "  - ApplicationProfileName: GuardProfile\n"
    '    ApplicationProfileVersion: "1.0.0"\n'
)


def _app_profile_yaml(name: str, software_version: str) -> str:
    """An application profile file. ``software_version`` is written as is:
    '"4.10"' is quoted, '4.10' is not."""
    return (
        f"ApplicationProfileName: {name}\n"
        'ApplicationProfileVersion: "1.0.0"\n'
        "ApplicationName: BCLConvert\n"
        "ApplicationType: BclConvert\n"
        "Settings:\n"
        f"  SoftwareVersion: {software_version}\n"
        "DataFields:\n"
        "  - Sample_ID\n"
    )


class _Messages(logging.Handler):
    """Collects what the sync logs (decision 9)."""

    def __init__(self):
        super().__init__()
        self.messages: list[str] = []

    def emit(self, record):
        self.messages.append(record.getMessage())


def _sync(ctx, monkeypatch, app_profile_files: dict[str, str]):
    """Run one config sync with only the GitHub fetches replaced: the folder
    listing and the file text. The real parse, check and save run. The
    test-profile folder always holds TEST_PROFILE_YAML."""
    config = ctx.profile_sync_config_repo.get()
    config.github_repo_url = "https://github.com/example/config"
    config.sync_instruments_enabled = False
    config.sync_index_kits_enabled = False
    ctx.profile_sync_config_repo.save(config)
    folders = {
        config.application_profiles_path.strip("/"): app_profile_files,
        config.test_profiles_path.strip("/"): {"Wgs.yaml": TEST_PROFILE_YAML},
    }
    texts = {}

    def listing(owner, repo, branch, path):
        path = path.strip("/")
        entries = []
        for name, text in folders[path].items():
            url = f"https://raw.githubusercontent.com/example/config/main/{path}/{name}"
            texts[url] = text
            entries.append({"type": "file", "name": name, "path": f"{path}/{name}", "download_url": url})
        return entries

    service = ctx.get_github_sync_service()
    monkeypatch.setattr(service, "_fetch_directory_contents", listing)
    monkeypatch.setattr(service, "_fetch_file_content", lambda url: texts[url])
    return service.sync()


class TestSyncRefusesRiskyValues:
    """Through a real config sync (spec 2026-09-29 Sample Sheet follow-ups, §1)."""

    def test_unquoted_4_10_is_skipped_and_logged(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        handler = _Messages()
        _SYNC_LOGGER.addHandler(handler)
        try:
            ok, message, _count = _sync(ctx, monkeypatch, {
                "Good.yaml": _app_profile_yaml("Good", '"4.3.6"'),
                "Bad.yaml": _app_profile_yaml("Bad", "4.10"),
            })
        finally:
            _SYNC_LOGGER.removeHandler(handler)

        assert ok, message
        assert [p.name for p in ctx.app_profile_repo.list_all()] == ["Good"]
        assert any(
            "Bad.yaml" in m and "'SoftwareVersion' is a number with a decimal point" in m
            for m in handler.messages
        ), handler.messages

    def test_quoted_4_10_is_stored_as_typed(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app

        ok, message, _count = _sync(ctx, monkeypatch, {"P.yaml": _app_profile_yaml("P", '"4.10"')})

        assert ok, message
        (profile,) = ctx.app_profile_repo.list_all()
        assert profile.settings["SoftwareVersion"] == "4.10"


class TestSyncIntoStoredProfiles:
    """A refused file when profiles are already stored (Astra review P7): the
    sync replaces them with the ones that passed, unless none passed; then it
    stops and keeps the old ones."""

    def test_a_refused_profile_is_gone_and_blocks_mark_ready(
        self, fresh_app, logged_in_client, monkeypatch
    ):
        _app, ctx, _db = fresh_app
        good = _app_profile_yaml("Good", '"4.3.6"')
        first = _sync(ctx, monkeypatch, {
            "Good.yaml": good, "GuardProfile.yaml": _app_profile_yaml("GuardProfile", '"4.3.6"'),
        })
        assert first[0], first[1]

        ok, message, _count = _sync(ctx, monkeypatch, {
            "Good.yaml": good, "GuardProfile.yaml": _app_profile_yaml("GuardProfile", "4.10"),
        })

        assert ok, message
        assert [p.name for p in ctx.app_profile_repo.list_all()] == ["Good"]
        run_id = _seed_draft(ctx, "sync-gone", test_id="WGS")
        resp = logged_in_client.post(f"/runs/{run_id}/status/ready", headers=ORIGIN)
        assert resp.headers.get("HX-Retarget") == "#ready-message"
        assert "GuardProfile" in resp.text and "not found" in resp.text
        assert ctx.run_repo.get_by_id(run_id).status.value == "draft"

    def test_when_every_profile_is_refused_the_old_ones_stay(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        first = _sync(ctx, monkeypatch, {
            "GuardProfile.yaml": _app_profile_yaml("GuardProfile", '"4.3.6"'),
        })
        assert first[0], first[1]

        ok, message, _count = _sync(ctx, monkeypatch, {
            "GuardProfile.yaml": _app_profile_yaml("GuardProfile", "4.10"),
        })

        assert not ok
        assert "Refusing to replace 1 existing application profiles with 0 fetched items" in message
        (profile,) = ctx.app_profile_repo.list_all()
        assert profile.settings["SoftwareVersion"] == "4.3.6"
```

- [ ] **Step 2: Run them and see them fail**

```bash
PYTHONPATH=src $PY -m pytest "tests/unit/test_profile_validator.py::TestProfileValuesHiddenCharacters::test_numbers_and_booleans_are_accepted" \
  tests/unit/test_profile_validator.py::TestProfileValueKinds \
  tests/unit/test_profile_validator.py::TestProfileVersions \
  tests/unit/test_profile_validator.py::TestEmptyRequiredFields \
  tests/integration/test_sheet_followups.py::TestSyncRefusesRiskyValues \
  tests/integration/test_sheet_followups.py::TestSyncIntoStoredProfiles -q -p no:cacheprovider
```

Expected: **32 failed, 11 passed**:
- unit 29 failed: every decimal, mapping/list, empty-value, decimal-version and empty-required-field test, and the 1.10/1.1 collision test;
- integration 3 failed: the unquoted `4.10` is stored today, so nothing is refused or stops;
- passing (guards): the 6 text/number/true-false values, the 3 quoted/whole versions, the changed `test_numbers_and_booleans_are_accepted`, and the quoted `"4.10"` sync.

- [ ] **Step 3: Implement**

In `src/seqsetup/services/profile_validator.py`, find (in `validate_test_profile_yaml`):

```python
        elif not str(yaml_data[field]).strip():
            errors.append(f"Field '{field}' must not be empty")

    # Validate Version is PEP 440 compliant
    version_val = yaml_data.get("Version")
    if version_val is not None and str(version_val).strip():
        try:
            Version(str(version_val))
        except InvalidVersion:
            errors.append(f"Field 'Version' is not a valid PEP 440 version: '{version_val}'")
```

Replace with:

```python
        elif _is_empty(yaml_data[field]):
            errors.append(f"Field '{field}' must not be empty")

    # Validate Version is PEP 440 compliant
    version_val = yaml_data.get("Version")
    if version_val is not None and str(version_val).strip():
        try:
            Version(str(version_val))
        except InvalidVersion:
            errors.append(f"Field 'Version' is not a valid PEP 440 version: '{version_val}'")
    if isinstance(version_val, float):
        errors.append(_decimal_version("Version"))
```

Find:

```python
            if "ApplicationProfileName" not in entry:
                errors.append(f"ApplicationProfiles[{i}]: missing 'ApplicationProfileName'")
            elif not str(entry["ApplicationProfileName"]).strip():
                errors.append(f"ApplicationProfiles[{i}]: 'ApplicationProfileName' must not be empty")

            if "ApplicationProfileVersion" not in entry:
                errors.append(f"ApplicationProfiles[{i}]: missing 'ApplicationProfileVersion'")
            elif not str(entry["ApplicationProfileVersion"]).strip():
                errors.append(f"ApplicationProfiles[{i}]: 'ApplicationProfileVersion' must not be empty")
            else:
                _validate_version_constraint(
                    str(entry["ApplicationProfileVersion"]),
                    f"ApplicationProfiles[{i}].ApplicationProfileVersion",
                    errors,
                )
```

Replace with:

```python
            if "ApplicationProfileName" not in entry:
                errors.append(f"ApplicationProfiles[{i}]: missing 'ApplicationProfileName'")
            elif _is_empty(entry["ApplicationProfileName"]):
                errors.append(f"ApplicationProfiles[{i}]: 'ApplicationProfileName' must not be empty")

            if "ApplicationProfileVersion" not in entry:
                errors.append(f"ApplicationProfiles[{i}]: missing 'ApplicationProfileVersion'")
            elif _is_empty(entry["ApplicationProfileVersion"]):
                errors.append(f"ApplicationProfiles[{i}]: 'ApplicationProfileVersion' must not be empty")
            else:
                _validate_version_constraint(
                    str(entry["ApplicationProfileVersion"]),
                    f"ApplicationProfiles[{i}].ApplicationProfileVersion",
                    errors,
                )
                if isinstance(entry["ApplicationProfileVersion"], float):
                    errors.append(
                        _decimal_version(f"ApplicationProfiles[{i}].ApplicationProfileVersion")
                    )
```

Find:

```python
    return list(dict.fromkeys(parts))


def validate_application_profile_yaml(yaml_data: dict, source_file: str = "") -> None:
```

Replace with:

```python
    return list(dict.fromkeys(parts))


def _is_empty(value) -> bool:
    """A required field left empty. YAML reads an empty field as None, which
    str() would turn into the text "None"."""
    return value is None or not str(value).strip()


def _decimal_version(field_path: str) -> str:
    return (
        f"Field '{field_path}' is a number with a decimal point, which YAML may have "
        'changed (1.10 is read as 1.1). Put the version in quotes, for example "1.10".'
    )


def _value_kind_problem(field: str, key, value) -> str | None:
    """Why a Settings or Data value cannot be written as it is, or None. The
    sheet writer writes a value with str(): YAML has already changed a
    decimal number (4.10 is read as 4.1), an empty value is None, and a
    mapping or a list would be written as Python text. Text, whole numbers
    and true/false are written as they are (spec 2026-09-29 Sample Sheet
    follow-ups, §1)."""
    where = f"Field '{field}' value for {str(key)!r}"
    if isinstance(value, float):
        return (
            f"{where} is a number with a decimal point, which YAML may have changed "
            '(4.10 is read as 4.1). Put the value in quotes, for example "4.10".'
        )
    if isinstance(value, (dict, list)):
        kind = "mapping" if isinstance(value, dict) else "list"
        return f"{where} is a {kind}; a value must be text, a whole number or true/false."
    if value is None:
        return f"{where} is empty. Write '' if it should be empty."
    return None


def validate_application_profile_yaml(yaml_data: dict, source_file: str = "") -> None:
```

Find (in `validate_application_profile_yaml`):

```python
    for field in ("ApplicationProfileName", "ApplicationProfileVersion", "ApplicationName", "ApplicationType"):
        if field not in yaml_data:
            errors.append(f"Missing required field '{field}'")
        elif not str(yaml_data[field]).strip():
            errors.append(f"Field '{field}' must not be empty")
```

Replace with:

```python
    for field in ("ApplicationProfileName", "ApplicationProfileVersion", "ApplicationName", "ApplicationType"):
        if field not in yaml_data:
            errors.append(f"Missing required field '{field}'")
        elif _is_empty(yaml_data[field]):
            errors.append(f"Field '{field}' must not be empty")
```

Find:

```python
    for field, key, value in values:
        if value is not None and starts_a_section(str(value)):
            errors.append(
                f"Field '{field}' value for {str(key)!r} cannot start with '[': {str(value)!r}"
            )
```

Replace with:

```python
    for field, key, value in values:
        if value is not None and starts_a_section(str(value)):
            errors.append(
                f"Field '{field}' value for {str(key)!r} cannot start with '[': {str(value)!r}"
            )

    # The writer writes each value with str(): refuse what YAML has already
    # changed, and what would be written as Python text.
    for field, key, value in values:
        problem = _value_kind_problem(field, key, value)
        if problem:
            errors.append(problem)
```

Find:

```python
            errors.append(
                f"Field 'ApplicationProfileVersion' is not a valid PEP 440 version: '{version_val}'"
            )
```

Replace with:

```python
            errors.append(
                f"Field 'ApplicationProfileVersion' is not a valid PEP 440 version: '{version_val}'"
            )
    if isinstance(version_val, float):
        errors.append(_decimal_version("ApplicationProfileVersion"))
```

- [ ] **Step 4: Run them and the files around them**

Run the Step 2 command: **43 passed**. Then:

```bash
PYTHONPATH=src $PY -m pytest tests/unit/test_profile_validator.py tests/unit/test_sync_name_rules.py \
  tests/unit/test_samplesheet_v2_exporter.py tests/integration/test_sheet_followups.py \
  tests/integration/test_scheduled_sync_instrument_cache.py -q -p no:cacheprovider
```

Expected: no failures.

- [ ] **Step 5: Commit**

```bash
git add src/seqsetup/services/profile_validator.py tests/unit/test_profile_validator.py \
  tests/integration/test_sheet_followups.py
git commit -m "fix(profiles): refuse decimal, empty, mapping and list values and decimal versions at sync (Sample Sheet follow-ups §1)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Mismatch values and the Sample_ID column at sync (spec §1)

**Files:**
- Modify: `src/seqsetup/services/sheet_text.py` (add `MISMATCH_COLUMNS`, `is_allowed_mismatch`)
- Modify: `src/seqsetup/services/profile_validator.py`
- Test: `tests/unit/test_profile_validator.py`

**Interfaces:**
- Consumes: `APP`, `_errors`, `_with` (Task 2).
- Produces (in `sheet_text.py`): `MISMATCH_COLUMNS = ("BarcodeMismatchesIndex1", "BarcodeMismatchesIndex2")`; `is_allowed_mismatch(value, per_sample: bool) -> bool` (Task 5 uses both).

- [ ] **Step 1: Write the failing tests, and give two existing fixtures a Sample_ID column (decision 7)**

In `tests/unit/test_profile_validator.py`, find:

```python
    VALID_NON_DRAGEN_PROFILE = {
        "ApplicationProfileName": "CustomApp",
        "ApplicationProfileVersion": "1.0.0",
        "ApplicationName": "CustomApp",
        "ApplicationType": "Custom",
    }
```

Replace with:

```python
    VALID_NON_DRAGEN_PROFILE = {
        "ApplicationProfileName": "CustomApp",
        "ApplicationProfileVersion": "1.0.0",
        "ApplicationName": "CustomApp",
        "ApplicationType": "Custom",
        "DataFields": ["Sample_ID"],
    }
```

Find:

```python
    BASE = {
        "ApplicationProfileName": "P",
        "ApplicationProfileVersion": "1.0.0",
        "ApplicationName": "BCLConvert",
        "ApplicationType": "Custom",
    }
```

Replace with:

```python
    BASE = {
        "ApplicationProfileName": "P",
        "ApplicationProfileVersion": "1.0.0",
        "ApplicationName": "BCLConvert",
        "ApplicationType": "Custom",
        "DataFields": ["Sample_ID"],
    }
```

Append to the same file:

```python
class TestMismatchValues:
    """BCL Convert allows at most 2 mismatches. A Settings entry takes 0, 1 or
    2; a Data default may also be blank or na: Illumina's DRAGEN sample sheet
    guide says a per-sample setting that does not apply "must be blank or na"
    (spec 2026-09-29 Sample Sheet follow-ups, §1)."""

    @staticmethod
    def _settings_error(key, column, value):
        return (
            f"Field 'Settings' value for '{key}' fills {column} and must be 0, 1 or 2 "
            f"(BCL Convert allows at most 2 mismatches): {value!r}"
        )

    @staticmethod
    def _data_error(key, column, value):
        return (
            f"Field 'Data' value for '{key}' fills {column} and must be 0, 1, 2, blank or na "
            f"(BCL Convert allows at most 2 mismatches): {value!r}"
        )

    @pytest.mark.parametrize("column", ["BarcodeMismatchesIndex1", "BarcodeMismatchesIndex2"])
    @pytest.mark.parametrize("value", [
        pytest.param(3, id="3"),
        pytest.param(-1, id="minus-1"),
        pytest.param("3", id="text-3"),
        pytest.param(True, id="true"),
        pytest.param("na", id="na"),
        pytest.param("", id="blank"),
    ])
    def test_settings_value_outside_0_to_2_is_refused(self, column, value):
        assert _errors(_with("Settings", **{column: value})) == [
            self._settings_error(column, column, value)
        ]

    @pytest.mark.parametrize("column", ["BarcodeMismatchesIndex1", "BarcodeMismatchesIndex2"])
    @pytest.mark.parametrize("value", [
        pytest.param(3, id="3"),
        pytest.param("3", id="text-3"),
        pytest.param(True, id="true"),
        pytest.param("NA", id="upper-NA"),
        pytest.param(" 1", id="space-1"),
    ])
    def test_data_default_outside_the_allowed_values_is_refused(self, column, value):
        assert _errors(_with("Data", **{column: value})) == [
            self._data_error(column, column, value)
        ]

    def test_a_translated_data_column_is_checked(self):
        data = {**_with("Data", Mm1=3), "Translate": {"Mm1": "BarcodeMismatchesIndex1"}}
        assert _errors(data) == [self._data_error("Mm1", "BarcodeMismatchesIndex1", 3)]

    @pytest.mark.parametrize("value", [0, 1, 2, "0", "1", "2"])
    def test_settings_0_1_2_pass(self, value):
        assert _errors(_with("Settings", BarcodeMismatchesIndex1=value)) == []

    @pytest.mark.parametrize("value", [0, 2, "1", "", "na"])
    def test_data_0_1_2_blank_and_na_pass(self, value):
        assert _errors(_with("Data", BarcodeMismatchesIndex2=value)) == []


class TestSampleIdColumn:
    """Every data row names its sample in the Sample_ID column. The columns
    are found the way the sheet writer finds them: DataFields when it has
    entries, else the Data keys, each renamed by Translate (spec 2026-09-29
    Sample Sheet follow-ups, §1)."""

    MESSAGE = (
        "The data section has no Sample_ID column. Add Sample_ID to DataFields "
        "(or to Data when DataFields is missing or empty)."
    )
    BARE = {key: value for key, value in APP.items() if key != "Data"}

    @pytest.mark.parametrize("sections", [
        pytest.param({}, id="no-data-no-datafields"),
        pytest.param({"Data": {"Extra": "x"}}, id="data-without-sample-id"),
        pytest.param({"Data": {"Sample_ID": ""}, "DataFields": ["Extra"]}, id="datafields-without-sample-id"),
        pytest.param({"Data": {"Sample_ID": ""}, "Translate": {"Sample_ID": "Name"}}, id="renamed-by-translate"),
    ])
    def test_no_sample_id_column_is_refused(self, sections):
        assert _errors({**self.BARE, **sections}) == [self.MESSAGE]

    @pytest.mark.parametrize("sections", [
        pytest.param({"Data": {"Sample_ID": ""}}, id="data-keys"),
        pytest.param({"Data": {"Sample_ID": ""}, "DataFields": None}, id="datafields-empty"),
        pytest.param({"Data": {"Sample_ID": ""}, "DataFields": []}, id="datafields-empty-list"),
        pytest.param({"DataFields": ["Sample_ID"]}, id="datafields"),
        pytest.param({"DataFields": ["SampleID"], "Translate": {"SampleID": "Sample_ID"}}, id="reached-by-translate"),
    ])
    def test_sample_id_column_passes(self, sections):
        assert _errors({**self.BARE, **sections}) == []

    def test_dragen_empty_sections_are_still_refused(self):
        # Decision 7 of the spec: only a non-DRAGEN profile reads an empty
        # section as "none".
        data = {
            **TestValidateApplicationProfile.VALID_DRAGEN_PROFILE,
            "Settings": None, "Data": None, "DataFields": None,
        }
        errors = _errors(data)
        assert "Field 'Settings' must be a mapping" in errors
        assert "Field 'Data' must be a mapping" in errors
        assert "Field 'DataFields' must be a list" in errors
```

- [ ] **Step 2: Run them and see them fail**

```bash
PYTHONPATH=src $PY -m pytest tests/unit/test_profile_validator.py::TestMismatchValues \
  tests/unit/test_profile_validator.py::TestSampleIdColumn -q -p no:cacheprovider
```

Expected: **27 failed, 17 passed**: every out-of-range value (12 Settings, 10 Data, the translated column) and the four missing-column profiles fail; the 11 allowed values, the 5 profiles with a Sample_ID column and the DRAGEN test pass.

- [ ] **Step 3: Implement**

Append to `src/seqsetup/services/sheet_text.py`:

```python


# The two columns BCL Convert reads the number of index mismatches from, as
# a Settings entry and per sample.
MISMATCH_COLUMNS = ("BarcodeMismatchesIndex1", "BarcodeMismatchesIndex2")


def is_allowed_mismatch(value, per_sample: bool) -> bool:
    """True for a mismatch value BCL Convert accepts: 0, 1 or 2, as a whole
    number or as text. A per-sample value (a profile's Data default) may also
    be blank or ``na``: Illumina's DRAGEN sample sheet guide says a setting
    that does not apply to a sample "must be blank or na". ``true`` and
    ``false`` are refused: Python counts true as 1."""
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return value in (0, 1, 2)
    if isinstance(value, str):
        return value in ("0", "1", "2") or (per_sample and value in ("", "na"))
    return False
```

In `src/seqsetup/services/profile_validator.py`, find:

```python
from .sheet_text import PLAIN_NAME_RE, describe, hidden_characters, starts_a_section
```

Replace with:

```python
from .sheet_text import (
    MISMATCH_COLUMNS,
    PLAIN_NAME_RE,
    describe,
    hidden_characters,
    is_allowed_mismatch,
    starts_a_section,
)
```

Find:

```python
        elif yaml_data["DataFields"] is None:
            errors.append("Field 'DataFields' must be a list")

    if errors:
        raise ProfileValidationError(errors, source_file)
```

Replace with:

```python
        elif yaml_data["DataFields"] is None:
            errors.append("Field 'DataFields' must be a list")

    errors += _mismatch_problems(settings, data, translate)
    errors += _sample_id_column_problems(data, data_fields, translate)

    if errors:
        raise ProfileValidationError(errors, source_file)


def _mismatch_problems(settings, data, translate) -> list[str]:
    """BCL Convert allows at most 2 mismatches. A Settings entry takes 0, 1 or
    2; a Data default, which fills a sample's cell, may also be blank or na.
    A Data entry is checked under the column it becomes: its own name, or
    the name Translate gives it (spec 2026-09-29 Sample Sheet follow-ups, §1)."""
    problems = []
    if isinstance(settings, dict):
        for key, value in settings.items():
            if key in MISMATCH_COLUMNS and not is_allowed_mismatch(value, per_sample=False):
                problems.append(
                    f"Field 'Settings' value for {str(key)!r} fills {key} and must be 0, 1 or 2 "
                    f"(BCL Convert allows at most 2 mismatches): {value!r}"
                )
    if isinstance(data, dict):
        names = translate if isinstance(translate, dict) else {}
        for key, value in data.items():
            column = names.get(key, key)
            if column in MISMATCH_COLUMNS and not is_allowed_mismatch(value, per_sample=True):
                problems.append(
                    f"Field 'Data' value for {str(key)!r} fills {column} and must be 0, 1, 2, "
                    f"blank or na (BCL Convert allows at most 2 mismatches): {value!r}"
                )
    return problems


def _sample_id_column_problems(data, data_fields, translate) -> list[str]:
    """Every data row names its sample in the Sample_ID column. The columns
    are found the way the sheet writer finds them: the DataFields list when
    it has entries, else the Data keys, each renamed by Translate. A section
    of the wrong shape is already reported, so it is not checked here."""
    shapes = ((data, dict), (data_fields, list), (translate, dict))
    if any(value is not None and not isinstance(value, kind) for value, kind in shapes):
        return []
    names = translate or {}
    fields = data_fields or list((data or {}).keys())
    columns = [names.get(f, f) if isinstance(f, str) else f for f in fields]
    if "Sample_ID" in columns:
        return []
    return [
        "The data section has no Sample_ID column. Add Sample_ID to DataFields "
        "(or to Data when DataFields is missing or empty)."
    ]
```

- [ ] **Step 4: Run them and the files around them**

Run the Step 2 command: **44 passed**. Then:

```bash
PYTHONPATH=src $PY -m pytest tests/unit/test_profile_validator.py tests/unit/test_sync_name_rules.py \
  tests/unit/test_sheet_text.py tests/unit/test_samplesheet_v2_exporter.py \
  tests/integration/test_sheet_followups.py -q -p no:cacheprovider
```

Expected: no failures. Every shipped profile has a Sample_ID column and no mismatch entry (checked while planning).

- [ ] **Step 5: Commit**

```bash
git add src/seqsetup/services/sheet_text.py src/seqsetup/services/profile_validator.py \
  tests/unit/test_profile_validator.py
git commit -m "fix(profiles): mismatch values 0-2 (blank or na per sample) and a Sample_ID column at sync (Sample Sheet follow-ups §1)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: An empty section means "none" (spec §1)

**Files:**
- Modify: `src/seqsetup/models/application_profile.py`
- Test: `tests/unit/test_profile_validator.py`, `tests/unit/test_samplesheet_v2_exporter.py`

**Interfaces:**
- Consumes: `APP` (Task 2).
- Produces: `ApplicationProfile.from_yaml` / `from_dict` never leave `settings`, `data`, `data_fields` or `translate` as `None`. In `tests/unit/test_samplesheet_v2_exporter.py`: `_export_stored_profile(profile) -> str`.

- [ ] **Step 1: Write the failing tests**

In `tests/unit/test_profile_validator.py`, find:

```python
import yaml

from seqsetup.services.profile_validator import (
```

Replace with:

```python
import yaml

from seqsetup.models.application_profile import ApplicationProfile
from seqsetup.services.profile_validator import (
```

Append to the same file:

```python
STORED = {
    "_id": "p1", "name": "P", "version": "1.0.0", "application_type": "Dragen",
    "application_name": "DragenGermline", "settings": {"A": "b"},
    "data": {"Sample_ID": ""}, "data_fields": ["Sample_ID"], "translate": {"X": "Y"},
}


class TestEmptySections:
    """An empty Settings:, Data: or Translate: means none ({}), and an empty
    DataFields: means none ([]): for a non-DRAGEN profile read from YAML, and
    for any profile read from the database. Mark Ready used to fail on
    None.items() (spec 2026-09-29 Sample Sheet follow-ups, §1)."""

    def test_from_yaml_reads_empty_sections_as_none(self):
        data = {**APP, "Settings": None, "DataFields": None, "Translate": None}
        profile = ApplicationProfile.from_yaml(data)
        assert (profile.settings, profile.data_fields, profile.translate) == ({}, [], {})

    def test_from_yaml_reads_an_empty_data_as_none(self):
        data = {**APP, "Data": None, "DataFields": ["Sample_ID"]}
        assert ApplicationProfile.from_yaml(data).data == {}

    def test_from_dict_reads_empty_sections_as_none(self):
        profile = ApplicationProfile.from_dict({
            **STORED, "settings": None, "data": None, "data_fields": None, "translate": None,
        })
        assert (profile.settings, profile.data, profile.data_fields, profile.translate) == (
            {}, {}, [], {}
        )

    def test_from_dict_keeps_what_is_there(self):
        profile = ApplicationProfile.from_dict(STORED)
        assert (profile.settings, profile.data, profile.data_fields, profile.translate) == (
            {"A": "b"}, {"Sample_ID": ""}, ["Sample_ID"], {"X": "Y"}
        )
```

Append to `tests/unit/test_samplesheet_v2_exporter.py`:

```python
def _export_stored_profile(profile) -> str:
    """Export one indexed sample (test WGS) through ``profile``."""
    run = SequencingRun(
        instrument_platform=InstrumentPlatform.NOVASEQ_X,
        flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8),
        samples=[Sample(
            sample_id="S1",
            test_id="WGS",
            index_pair=IndexPair(
                id="p1", name="p1",
                index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
                index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5),
            ),
        )],
    )
    tp = TestProfile(
        test_type="WGS", test_name="WGS", version="1.0.0",
        application_profiles=[ApplicationProfileReference(
            profile_name=profile.name, profile_version=profile.version,
        )],
    )
    return SampleSheetV2Exporter.export(
        run,
        _StubTestProfileRepo({"WGS": tp}),
        _StubAppProfileRepo({(profile.name, profile.version): profile}),
    )


class TestEmptyProfileSections:
    """A profile stored with an empty Settings: (None) stopped Mark Ready with
    None.items(); it now writes an empty section (spec 2026-09-29 Sample
    Sheet follow-ups, §1)."""

    def test_stored_profile_with_empty_sections_exports(self):
        profile = ApplicationProfile.from_dict({
            "_id": "p1", "name": "P", "version": "1.0.0", "application_type": "Dragen",
            "application_name": "DragenGermline", "settings": None, "data": None,
            "data_fields": ["Sample_ID"], "translate": None,
        })

        output = _export_stored_profile(profile)

        assert "[DragenGermline_Settings]\n\n[DragenGermline_Data]\nSample_ID\nS1\n" in output
```

- [ ] **Step 2: Run them and see them fail**

```bash
PYTHONPATH=src $PY -m pytest tests/unit/test_profile_validator.py::TestEmptySections \
  tests/unit/test_samplesheet_v2_exporter.py::TestEmptyProfileSections -q -p no:cacheprovider
```

Expected: **4 failed, 1 passed** (`test_from_dict_keeps_what_is_there` is a guard; the export fails with `AttributeError: 'NoneType' object has no attribute 'items'`).

- [ ] **Step 3: Implement**

In `src/seqsetup/models/application_profile.py`, find:

```python
@dataclass
class ApplicationProfile:
```

Replace with:

```python
def _or_empty(value, empty):
    """An empty YAML section (``Settings:`` with nothing under it) is None; it
    means "none" (spec 2026-09-29 Sample Sheet follow-ups, §1). Mark Ready
    used to fail on ``None.items()``."""
    return empty if value is None else value


@dataclass
class ApplicationProfile:
```

Find:

```python
            settings=data.get("settings", {}),
            data=data.get("data", {}),
            data_fields=data.get("data_fields", []),
            translate=data.get("translate", {}),
```

Replace with:

```python
            settings=_or_empty(data.get("settings"), {}),
            data=_or_empty(data.get("data"), {}),
            data_fields=_or_empty(data.get("data_fields"), []),
            translate=_or_empty(data.get("translate"), {}),
```

Find:

```python
            settings=yaml_data.get("Settings", {}),
            data=yaml_data.get("Data", {}),
            data_fields=yaml_data.get("DataFields", []),
            translate=yaml_data.get("Translate", {}),
```

Replace with:

```python
            settings=_or_empty(yaml_data.get("Settings"), {}),
            data=_or_empty(yaml_data.get("Data"), {}),
            data_fields=_or_empty(yaml_data.get("DataFields"), []),
            translate=_or_empty(yaml_data.get("Translate"), {}),
```

Find (the `from_yaml` docstring example; the new rule refuses an unquoted `1.0`):

```python
            ApplicationProfileVersion: 1.0
```

Replace with:

```python
            ApplicationProfileVersion: 1.0.0
```

- [ ] **Step 4: Run them and the files around them**

Run the Step 2 command: **5 passed**. Then:

```bash
PYTHONPATH=src $PY -m pytest tests/unit/test_profile_validator.py tests/unit/test_samplesheet_v2_exporter.py \
  tests/unit/test_version_resolver.py tests/unit/test_models.py \
  tests/integration/test_smoke_bootstrap.py -q -p no:cacheprovider
```

Expected: no failures.

- [ ] **Step 5: Commit**

```bash
git add src/seqsetup/models/application_profile.py tests/unit/test_profile_validator.py \
  tests/unit/test_samplesheet_v2_exporter.py
git commit -m "fix(profiles): an empty profile section means none, from YAML and from the database (Sample Sheet follow-ups §1)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: The sheet writer's safety net (spec §1)

**Files:**
- Modify: `src/seqsetup/services/samplesheet_v2_exporter.py`
- Test: `tests/unit/test_samplesheet_v2_exporter.py`, `tests/integration/test_sheet_followups.py`

**Interfaces:**
- Consumes: `MISMATCH_COLUMNS`, `is_allowed_mismatch` (Task 3); `_export_with_profile` (existing test helper).
- Produces: `SampleSheetV2Exporter._require_profile_mismatch(value, column: str, section: str) -> None`, `SampleSheetV2Exporter._profile_mismatch_cell(value, column: str) -> str`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_samplesheet_v2_exporter.py`:

```python
class TestProfileSafetyNet:
    """A profile already in the database is checked again by the writer,
    which raises rather than write what the sync now refuses. These profiles
    are built directly, not through the sync check (spec 2026-09-29 Sample
    Sheet follow-ups, §1)."""

    FIELDS = ["Sample_ID", "Index", "Index2", "Extra"]
    WRONG_KIND = [
        pytest.param(4.1, id="decimal"),
        pytest.param(None, id="empty"),
        pytest.param({"SoftwareVersion": "4.10"}, id="mapping"),
        pytest.param(["a"], id="list"),
    ]
    KIND_ERROR = "A profile value must be text, a whole number or true/false"

    @pytest.mark.parametrize("value", WRONG_KIND)
    def test_setting_value_of_the_wrong_kind_is_refused(self, value):
        with pytest.raises(ValueError, match=self.KIND_ERROR):
            _export_with_profile({"Extra": value}, {"Extra": "x"}, self.FIELDS, {})

    @pytest.mark.parametrize("value", WRONG_KIND)
    def test_data_default_of_the_wrong_kind_is_refused(self, value):
        with pytest.raises(ValueError, match=self.KIND_ERROR):
            _export_with_profile({}, {"Extra": value}, self.FIELDS, {})

    @pytest.mark.parametrize("value", [
        pytest.param(3, id="3"),
        pytest.param("3", id="text-3"),
        pytest.param(True, id="true"),
        pytest.param("na", id="na"),
        pytest.param("", id="blank"),
    ])
    def test_setting_mismatch_outside_0_to_2_is_refused(self, value):
        with pytest.raises(
            ValueError, match="BarcodeMismatchesIndex1 in the profile's Settings must be 0, 1 or 2"
        ):
            _export_with_profile({"BarcodeMismatchesIndex1": value}, {}, ["Sample_ID"], {})

    @pytest.mark.parametrize("value", [
        pytest.param(3, id="3"),
        pytest.param("3", id="text-3"),
        pytest.param(True, id="true"),
        pytest.param("NA", id="upper-NA"),
    ])
    def test_data_mismatch_default_outside_the_allowed_values_is_refused(self, value):
        # The sample's own value must be None, or the default is never used
        # (a new sample's own value is 1).
        with pytest.raises(
            ValueError,
            match="BarcodeMismatchesIndex2 in the profile's Data must be 0, 1, 2, blank or na",
        ):
            _export_with_profile(
                {}, {"BarcodeMismatchesIndex2": value},
                ["Sample_ID", "BarcodeMismatchesIndex2"], {},
                barcode_mismatches_index2=None,
            )

    def test_a_translated_mismatch_default_is_checked(self):
        with pytest.raises(ValueError, match="BarcodeMismatchesIndex1 in the profile's Data"):
            _export_with_profile(
                {}, {"Mm1": 3}, ["Sample_ID", "Mm1"], {"Mm1": "BarcodeMismatchesIndex1"},
                barcode_mismatches_index1=None,
            )

    def test_na_default_is_written(self):
        output = _export_with_profile(
            {}, {"BarcodeMismatchesIndex2": "na"}, ["Sample_ID", "BarcodeMismatchesIndex2"], {},
            barcode_mismatches_index2=None,
        )

        assert "S1,na" in output.split("\n")

    def test_the_samples_own_value_is_written(self):
        # Decision 5: the default is checked only where it is used.
        output = _export_with_profile(
            {}, {"BarcodeMismatchesIndex1": 3}, ["Sample_ID", "BarcodeMismatchesIndex1"], {},
            barcode_mismatches_index1=2,
        )

        assert "S1,2" in output.split("\n")

    @pytest.mark.parametrize("fields,data,translate", [
        pytest.param([], {}, {}, id="no-columns"),
        pytest.param(["Extra"], {"Sample_ID": ""}, {}, id="datafields-without-sample-id"),
        pytest.param(["Sample_ID"], {}, {"Sample_ID": "Name"}, id="renamed-by-translate"),
    ])
    def test_data_section_without_sample_id_is_refused(self, fields, data, translate):
        with pytest.raises(ValueError, match="The BCLConvert_Data section has no Sample_ID column"):
            _export_with_profile({}, data, fields, translate)

    def test_whole_numbers_and_true_false_are_written_as_today(self):
        output = _export_with_profile(
            {"Threads": 8, "KeepFastq": True, "BarcodeMismatchesIndex1": 0},
            {"Extra": 2}, self.FIELDS, {},
        )

        lines = output.split("\n")
        assert "Threads,8" in lines
        assert "KeepFastq,True" in lines
        assert "BarcodeMismatchesIndex1,0" in lines
        assert "S1,ATTACTCG,TATAGCCT,2" in lines
```

In `tests/integration/test_sheet_followups.py`, find:

```python
import logging

from .conftest import disable_repos
from .test_sheet_safety import _seed_draft
```

Replace with:

```python
import logging

from seqsetup.data import instruments as instruments_module
from seqsetup.services.validation import clear_validation_cache

from .conftest import disable_repos
from .test_sheet_safety import _assert_validation_passes, _seed_draft, _seed_synced_profile
```

and append to the same file:

```python
class TestStoredProfileMismatchStopsMarkReady:
    """A stored profile whose Settings say BarcodeMismatchesIndex1: 3 (written
    straight into the database, past the sync check) stops Mark Ready at the
    writer; the run stays Draft (spec §1)."""

    def test_a_setting_of_3_stops_mark_ready(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        try:
            _seed_synced_profile(ctx, "GuardApp", settings={
                "SoftwareVersion": "4.3.6", "BarcodeMismatchesIndex1": 3,
            })
            run_id = _seed_draft(ctx, "mm-profile", test_id="GUARD_T")
            _assert_validation_passes(ctx, run_id)

            resp = logged_in_client.post(f"/runs/{run_id}/status/ready", headers=ORIGIN)

            assert resp.status_code == 500
            assert "Failed to generate exports" in resp.text
            run = ctx.run_repo.get_by_id(run_id)
            assert run.status.value == "draft"
            assert run.generated_samplesheet_v2 is None
        finally:
            instruments_module.clear_synced_instruments_cache()
            clear_validation_cache()
```

- [ ] **Step 2: Run them and see them fail**

```bash
PYTHONPATH=src $PY -m pytest tests/unit/test_samplesheet_v2_exporter.py::TestProfileSafetyNet \
  tests/integration/test_sheet_followups.py::TestStoredProfileMismatchStopsMarkReady -q -p no:cacheprovider
```

Expected: **22 failed, 3 passed**. The 3 that pass are guards: `na` written, the sample's own value, whole numbers and true/false. (The list value fails today too, but with the `'['` message instead of the new one.)

- [ ] **Step 3: Implement**

In `src/seqsetup/services/samplesheet_v2_exporter.py`, find:

```python
from .sheet_text import (
    PLAIN_NAME_RE,
    PLAIN_VERSION_RE,
    refuse_hidden_characters,
    starts_a_section,
)
```

Replace with:

```python
from .sheet_text import (
    MISMATCH_COLUMNS,
    PLAIN_NAME_RE,
    PLAIN_VERSION_RE,
    is_allowed_mismatch,
    refuse_hidden_characters,
    starts_a_section,
)
```

Find:

```python
    @classmethod
    def _escape_config_cell(cls, value) -> str:
        """Escape a value taken from an application profile (a setting value,
        a default value). Quoting a line break still leaves a new line for a
        line-oriented reader, so every hidden character — tab and line breaks
        included — is refused before ``_escape_csv``. So is a value starting
        with '[': first on its line, it would start a new section."""
        text = str(value)
```

Replace with:

```python
    @classmethod
    def _escape_config_cell(cls, value) -> str:
        """Escape a value taken from an application profile (a setting value,
        a default value). Quoting a line break still leaves a new line for a
        line-oriented reader, so every hidden character — tab and line breaks
        included — is refused before ``_escape_csv``. So is a value starting
        with '[': first on its line, it would start a new section. So is a
        decimal number, an empty value, a mapping or a list: str() would write
        what YAML changed (4.10 as 4.1), the word None, or Python text. The
        sync refuses them; this is the backstop for a profile already in the
        database (spec 2026-09-29 Sample Sheet follow-ups, §1)."""
        if value is None or isinstance(value, (float, dict, list)):
            raise ValueError(
                f"A profile value must be text, a whole number or true/false, not {value!r}"
            )
        text = str(value)
```

Find:

```python
    @classmethod
    def _require_plain(cls, value: str, pattern, what: str) -> str:
```

Replace with:

```python
    @classmethod
    def _require_profile_mismatch(cls, value, column: str, section: str) -> None:
        """A mismatch value from a profile's Settings (0, 1 or 2) or Data
        default (also blank or na). The sync refuses others; this is the
        backstop for a profile already in the database (spec 2026-09-29
        Sample Sheet follow-ups, §1)."""
        per_sample = section == "Data"
        if not is_allowed_mismatch(value, per_sample=per_sample):
            allowed = "0, 1, 2, blank or na" if per_sample else "0, 1 or 2"
            raise ValueError(f"{column} in the profile's {section} must be {allowed}: {value!r}")

    @classmethod
    def _profile_mismatch_cell(cls, value, column: str) -> str:
        """The cell for a sample with no mismatch value of its own: the
        profile's Data default, checked like any profile value first."""
        cell = cls._escape_config_cell(value)
        cls._require_profile_mismatch(value, column, "Data")
        return cell

    @classmethod
    def _require_plain(cls, value: str, pattern, what: str) -> str:
```

Find:

```python
        for key, value in profile.settings.items():
            name = cls._require_plain(key, PLAIN_NAME_RE, "Setting name")
            output.write(f"{name},{cls._escape_config_cell(value)}\n")
```

Replace with:

```python
        for key, value in profile.settings.items():
            name = cls._require_plain(key, PLAIN_NAME_RE, "Setting name")
            cell = cls._escape_config_cell(value)
            if name in MISMATCH_COLUMNS:
                cls._require_profile_mismatch(value, name, "Settings")
            output.write(f"{name},{cell}\n")
```

Find:

```python
        translate = profile.translate or {}
        columns = [(field, translate.get(field, field)) for field in data_fields]
```

Replace with:

```python
        translate = profile.translate or {}
        columns = [(field, translate.get(field, field)) for field in data_fields]
        if not any(col == "Sample_ID" for _, col in columns):
            raise ValueError(f"The {app_name}_Data section has no Sample_ID column")
```

Find:

```python
                elif col == "BarcodeMismatchesIndex1":
                    val = sample.barcode_mismatches_index1
                    row.append(
                        str(val) if val is not None
                        else cls._escape_config_cell(profile.data.get(field, ""))
                    )
                elif col == "BarcodeMismatchesIndex2":
                    val = sample.barcode_mismatches_index2
                    row.append(
                        str(val) if val is not None
                        else cls._escape_config_cell(profile.data.get(field, ""))
                    )
```

Replace with:

```python
                elif col == "BarcodeMismatchesIndex1":
                    val = sample.barcode_mismatches_index1
                    row.append(
                        str(val) if val is not None
                        else cls._profile_mismatch_cell(profile.data.get(field, ""), col)
                    )
                elif col == "BarcodeMismatchesIndex2":
                    val = sample.barcode_mismatches_index2
                    row.append(
                        str(val) if val is not None
                        else cls._profile_mismatch_cell(profile.data.get(field, ""), col)
                    )
```

- [ ] **Step 4: Run them and the files around them**

Run the Step 2 command: **25 passed**. Then:

```bash
PYTHONPATH=src $PY -m pytest tests/unit/test_samplesheet_v2_exporter.py tests/unit/test_check_broken_samplesheets.py \
  tests/unit/test_validation.py tests/integration/test_sheet_safety.py \
  tests/integration/test_sheet_followups.py -q -p no:cacheprovider
```

Expected: no failures. Every shipped profile still exports (`test_shipped_application_profiles_export`).

- [ ] **Step 5: Commit**

```bash
git add src/seqsetup/services/samplesheet_v2_exporter.py tests/unit/test_samplesheet_v2_exporter.py \
  tests/integration/test_sheet_followups.py
git commit -m "fix(sheet): the v2 writer refuses stored profile values the sync now refuses (Sample Sheet follow-ups §1)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: Mismatch values of samples, runs and templates are whole numbers (spec §2)

**Files:**
- Modify: `src/seqsetup/models/sample.py`, `src/seqsetup/models/sequencing_run.py`, `src/seqsetup/models/run_template.py`
- Test: `tests/unit/test_model_validation.py`, `tests/integration/test_sheet_followups.py`

**Interfaces:**
- Produces: `checked_mismatches(name: str, value) -> int` in `models/sample.py` (raises `ValueError` for anything but a whole number; clamps to 0-2).

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_model_validation.py`:

```python
BAD_MISMATCHES = [
    pytest.param(True, id="true"),
    pytest.param(False, id="false"),
    pytest.param(1.5, id="1.5"),
    pytest.param("1", id="text-1"),
]
MISMATCH_OWNERS = [
    pytest.param(Sample, id="sample"),
    pytest.param(SequencingRun, id="run"),
    pytest.param(RunTemplate, id="template"),
]


class TestMismatchIsAWholeNumber:
    """A mismatch value must be a whole number: the Sample Sheet writers write
    True or 1.5 as they are. Every page and route passes a whole number, so
    only a value written into the database directly gets here (spec
    2026-09-29 Sample Sheet follow-ups, §2)."""

    @pytest.mark.parametrize("value", BAD_MISMATCHES)
    @pytest.mark.parametrize("model", MISMATCH_OWNERS)
    def test_construction_refuses_it(self, model, value):
        with pytest.raises(ValueError, match="barcode_mismatches_index1 must be a whole number, not "):
            model(barcode_mismatches_index1=value)

    @pytest.mark.parametrize("value", BAD_MISMATCHES)
    @pytest.mark.parametrize("model", MISMATCH_OWNERS)
    def test_assignment_refuses_it(self, model, value):
        owner = model()
        with pytest.raises(ValueError, match="barcode_mismatches_index2 must be a whole number, not "):
            owner.barcode_mismatches_index2 = value

    @pytest.mark.parametrize("value", [True, 1.5])
    @pytest.mark.parametrize("load", [
        pytest.param(
            lambda v: Sample.from_dict({"id": "s", "sample_id": "S1", "barcode_mismatches_index1": v}),
            id="sample",
        ),
        pytest.param(
            lambda v: SequencingRun.from_dict({"id": "r", "barcode_mismatches_index1": v}),
            id="run",
        ),
        pytest.param(
            lambda v: RunTemplate.from_dict({"id": "t", "barcode_mismatches_index1": v}),
            id="template",
        ),
    ])
    def test_loading_refuses_it(self, load, value):
        with pytest.raises(ValueError, match="barcode_mismatches_index1 must be a whole number"):
            load(value)

    @pytest.mark.parametrize("value,kept", [(0, 0), (1, 1), (2, 2), (5, 2), (-1, 0)])
    @pytest.mark.parametrize("model", MISMATCH_OWNERS)
    def test_whole_numbers_are_clamped_as_before(self, model, value, kept):
        assert model(barcode_mismatches_index1=value).barcode_mismatches_index1 == kept

    def test_a_samples_none_is_kept(self):
        assert Sample(barcode_mismatches_index1=None).barcode_mismatches_index1 is None
```

In `tests/integration/test_sheet_followups.py`, find:

```python
import logging

from seqsetup.data import instruments as instruments_module
```

Replace with:

```python
import logging

import pytest

from seqsetup.data import instruments as instruments_module
```

and append to the same file:

```python
class TestStoredMismatchOfTheWrongKind:
    """A run stored with true as a sample's mismatch value (written straight
    into the database) cannot be loaded, so it cannot be marked ready
    (spec §2; plan decision 8)."""

    def test_a_run_stored_with_true_cannot_be_marked_ready(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        run_id = _seed_draft(ctx, "mm-true")
        ctx.run_repo.collection.update_one(
            {"_id": run_id}, {"$set": {"samples.0.barcode_mismatches_index1": True}}
        )

        with pytest.raises(ValueError, match="barcode_mismatches_index1 must be a whole number, not True"):
            logged_in_client.post(f"/runs/{run_id}/status/ready", headers=ORIGIN)

        doc = ctx.run_repo.collection.find_one({"_id": run_id})
        assert doc["status"] == "draft"
        assert not doc.get("generated_samplesheet_v2")
        assert doc["samples"][0]["barcode_mismatches_index1"] is True
```

- [ ] **Step 2: Run them and see them fail**

```bash
PYTHONPATH=src $PY -m pytest tests/unit/test_model_validation.py::TestMismatchIsAWholeNumber \
  tests/integration/test_sheet_followups.py::TestStoredMismatchOfTheWrongKind -q -p no:cacheprovider
```

Expected: **31 failed, 16 passed**: every refusal fails (`"1"` fails with a `TypeError` from `min()`, the others are kept as given); the 15 clamping cases and the sample's `None` pass.

- [ ] **Step 3: Implement**

In `src/seqsetup/models/sample.py`, find:

```python
_VALID_OVERRIDE_PATTERN_RE = re.compile(r'^[YIUN0-9*]*\Z')
```

Replace with:

```python
_VALID_OVERRIDE_PATTERN_RE = re.compile(r'^[YIUN0-9*]*\Z')


def checked_mismatches(name: str, value: Any) -> int:
    """A barcode mismatch value: a whole number, clamped to 0-2 (the values
    BCL Convert accepts). True, 1.5 or "1" is refused, not guessed: the
    Sample Sheet writers would write it as it is. Every page and route
    passes a whole number; only a value written into the database directly
    gets here (spec 2026-09-29 Sample Sheet follow-ups, §2)."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be a whole number, not {value!r}")
    return max(0, min(2, value))
```

Find:

```python
          - ``barcode_mismatches_index1`` / ``barcode_mismatches_index2``
            clamped to [0, 2] — the values BCL Convert accepts.
```

Replace with:

```python
          - ``barcode_mismatches_index1`` / ``barcode_mismatches_index2``
            whole numbers, clamped to [0, 2] — the values BCL Convert accepts.
```

Find:

```python
            if name in ("barcode_mismatches_index1", "barcode_mismatches_index2"):
                value = max(0, min(2, value))
```

Replace with:

```python
            if name in ("barcode_mismatches_index1", "barcode_mismatches_index2"):
                value = checked_mismatches(name, value)
```

In `src/seqsetup/models/sequencing_run.py`, find:

```python
from .sample import Sample
```

Replace with:

```python
from .sample import Sample, checked_mismatches
```

Find:

```python
        elif name in ("barcode_mismatches_index1", "barcode_mismatches_index2"):
            value = max(0, min(2, value))
        elif name == "run_name" and isinstance(value, str):
```

Replace with:

```python
        elif name in ("barcode_mismatches_index1", "barcode_mismatches_index2"):
            value = checked_mismatches(name, value)
        elif name == "run_name" and isinstance(value, str):
```

In `src/seqsetup/models/run_template.py`, find:

```python
from .sample import Sample
```

Replace with:

```python
from .sample import Sample, checked_mismatches
```

Find:

```python
        elif name in ("barcode_mismatches_index1", "barcode_mismatches_index2"):
            value = max(0, min(2, value))
        elif name in ("created_by", "updated_by", "flowcell_type") and isinstance(value, str):
```

Replace with:

```python
        elif name in ("barcode_mismatches_index1", "barcode_mismatches_index2"):
            value = checked_mismatches(name, value)
        elif name in ("created_by", "updated_by", "flowcell_type") and isinstance(value, str):
```

- [ ] **Step 4: Run them and the files around them**

Run the Step 2 command: **47 passed**. Then run the server suite (the models are used everywhere). Expected: no failures.

- [ ] **Step 5: Commit**

```bash
git add src/seqsetup/models/sample.py src/seqsetup/models/sequencing_run.py \
  src/seqsetup/models/run_template.py tests/unit/test_model_validation.py \
  tests/integration/test_sheet_followups.py
git commit -m "fix(models): a mismatch value must be a whole number (Sample Sheet follow-ups §2)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: The local instruments file is checked at start (spec §4)

**Files:**
- Modify: `src/seqsetup/data/instruments.py` (`_load_config`; the start code)
- Test: `tests/unit/test_instrument_file_check.py` (create)

**Interfaces:**
- Produces: `InstrumentConfigError(ValueError)`; `load_checked_instrument_file(path: Path) -> dict`; `_initialize_at_start() -> None`.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_instrument_file_check.py`:

```python
"""The local instruments file is checked at start, the way a config sync
checks synced instruments (spec 2026-09-29 Sample Sheet follow-ups, §4)."""

from pathlib import Path

import pytest
import yaml

from seqsetup.data import instruments as instruments_module
from seqsetup.data.instruments import InstrumentConfigError, load_checked_instrument_file

SHIPPED = Path(__file__).resolve().parents[2] / "config" / "instruments.yaml"
STOPS = "instruments.yaml has errors, so SeqSetup will not start: "


def _file(tmp_path, content) -> Path:
    """Write ``content`` (a mapping, or text as it is) to instruments.yaml."""
    path = tmp_path / "instruments.yaml"
    path.write_text(content if isinstance(content, str) else yaml.safe_dump(content))
    return path


def _shipped(**entries) -> dict:
    """The shipped file, with some instruments' entries replaced."""
    data = yaml.safe_load(SHIPPED.read_text())
    data["instruments"].update(entries)
    return data


def _entry(name: str, **fields) -> dict:
    """A shipped instrument's entry, with some fields changed."""
    return {**yaml.safe_load(SHIPPED.read_text())["instruments"][name], **fields}


def _problems(path) -> str:
    with pytest.raises(InstrumentConfigError) as exc:
        load_checked_instrument_file(path)
    return str(exc.value)


class TestShippedFile:
    """What SeqSetup ships passes."""

    def test_shipped_file_passes(self):
        data = load_checked_instrument_file(SHIPPED)
        assert len(data["instruments"]) == 11

    def test_a_stop_is_a_value_error(self):
        assert issubclass(InstrumentConfigError, ValueError)


class TestBrokenInstrument:
    """Each problem names the instrument and, where the check can tell, the field."""

    def test_a_bad_i5_orientation(self, tmp_path):
        path = _file(tmp_path, _shipped(MiSeq=_entry("MiSeq", i5_read_orientation="forwards")))
        assert _problems(path) == (
            STOPS + "MiSeq: i5_read_orientation: Must be one of: forward, "
            "reverse-complement (got: 'forwards')"
        )

    def test_an_entry_that_is_not_a_mapping(self, tmp_path):
        path = _file(tmp_path, _shipped(MiSeq="forward"))
        assert _problems(path) == STOPS + "MiSeq: must be a mapping"

    def test_a_bad_flowcell(self, tmp_path):
        entry = _entry("MiSeq")
        flowcell = next(iter(entry["flowcells"]))
        entry["flowcells"][flowcell]["lanes"] = 0
        path = _file(tmp_path, _shipped(MiSeq=entry))
        assert _problems(path) == (
            STOPS + f"MiSeq: flowcells.{flowcell}.lanes: Must be a positive integer (got: '0')"
        )

    @pytest.mark.parametrize("field,value", [
        pytest.param("i5_read_orientation", [], id="orientation-list"),
        pytest.param("channel1_bases", 42, id="bases-number"),
    ])
    def test_a_value_the_check_cannot_read(self, tmp_path, field, value):
        # validate_instrument_yaml raises TypeError on these (Astra review P8).
        name = "NovaSeq X Series"
        path = _file(tmp_path, _shipped(**{name: _entry(name, **{field: value})}))
        assert _problems(path).startswith(STOPS + f"{name}: could not be checked: ")

    def test_every_problem_is_listed(self, tmp_path):
        path = _file(tmp_path, _shipped(
            MiSeq=_entry("MiSeq", i5_read_orientation="x"),
            MiniSeq=_entry("MiniSeq", samplesheet_v2_i5_orientation="y"),
        ))
        message = _problems(path)
        assert "MiSeq: i5_read_orientation: " in message
        assert "MiniSeq: samplesheet_v2_i5_orientation: " in message


class TestBrokenFile:
    """A file that cannot be read as instruments stops the start, naming the file."""

    def test_yaml_that_cannot_be_read(self, tmp_path):
        assert _problems(_file(tmp_path, "instruments: [unclosed\n")).startswith(
            STOPS + "cannot be read as YAML: "
        )

    @pytest.mark.parametrize("text", [
        pytest.param("", id="empty"),
        pytest.param("- MiSeq\n", id="list"),
    ])
    def test_a_top_level_that_is_not_a_mapping(self, tmp_path, text):
        assert _problems(_file(tmp_path, text)) == STOPS + "must be a mapping at the top level"

    def test_instruments_that_is_not_a_mapping(self, tmp_path):
        path = _file(tmp_path, {"instruments": ["MiSeq"]})
        assert _problems(path) == STOPS + "'instruments' must be a mapping"

    def test_warnings_do_not_stop_it(self, tmp_path):
        # Every local entry lacks `version`, which the check only warns about.
        data = yaml.safe_load(SHIPPED.read_text())
        assert all("version" not in entry for entry in data["instruments"].values())
        assert load_checked_instrument_file(_file(tmp_path, data)) == data


class TestStartAndReload:
    """The app reads the file through the check. A missing file at start still
    loads no instruments, and reload_config() still raises for one."""

    @pytest.fixture
    def keep_loaded_config(self):
        saved = (
            instruments_module._config, instruments_module._instruments,
            instruments_module._default_cycles, instruments_module._index_cycle_options,
        )
        yield
        (
            instruments_module._config, instruments_module._instruments,
            instruments_module._default_cycles, instruments_module._index_cycle_options,
        ) = saved

    @staticmethod
    def _missing():
        raise FileNotFoundError("no instruments.yaml")

    def test_the_app_reads_the_file_through_the_check(self, tmp_path, monkeypatch):
        path = _file(tmp_path, _shipped(MiSeq=_entry("MiSeq", i5_read_orientation="x")))
        monkeypatch.setattr(instruments_module, "_find_config_path", lambda: path)
        with pytest.raises(InstrumentConfigError):
            instruments_module._load_config()

    def test_a_broken_file_stops_the_start(self, tmp_path, monkeypatch, keep_loaded_config):
        path = _file(tmp_path, _shipped(MiSeq="forward"))
        monkeypatch.setattr(instruments_module, "_find_config_path", lambda: path)
        with pytest.raises(InstrumentConfigError):
            instruments_module._initialize_at_start()

    def test_a_missing_file_at_start_loads_no_instruments(self, monkeypatch, keep_loaded_config):
        monkeypatch.setattr(instruments_module, "_find_config_path", self._missing)
        with pytest.warns(UserWarning, match="Instrument config not found"):
            instruments_module._initialize_at_start()
        assert instruments_module._instruments == {}

    def test_reload_with_a_missing_file_raises(self, monkeypatch, keep_loaded_config):
        monkeypatch.setattr(instruments_module, "_find_config_path", self._missing)
        with pytest.raises(FileNotFoundError):
            instruments_module.reload_config()
```

- [ ] **Step 2: Run them and see them fail**

Run: `PYTHONPATH=src $PY -m pytest tests/unit/test_instrument_file_check.py -q -p no:cacheprovider`
Expected: **1 error** during collection: `ImportError: cannot import name 'InstrumentConfigError'`.

- [ ] **Step 3: Implement**

In `src/seqsetup/data/instruments.py`, find:

```python
def _load_config() -> dict:
    """Load instrument configuration from YAML file."""
    config_path = _find_config_path()
    with open(config_path) as f:
        return yaml.safe_load(f)
```

Replace with:

```python
class InstrumentConfigError(ValueError):
    """The local instruments file has errors, so SeqSetup does not start
    (spec 2026-09-29 Sample Sheet follow-ups, §4)."""


def load_checked_instrument_file(path: Path) -> dict:
    """Read the local instruments file and check every instrument the way a
    config sync checks synced ones (``validate_instrument_yaml``, with the
    map key as the name). A typo in ``i5_read_orientation`` would otherwise
    fall back to "forward" without a word. Raise InstrumentConfigError
    naming the file and listing every problem. Warnings are ignored: every
    local entry lacks the ``version`` a synced file carries."""
    from ..services.instrument_validator import validate_instrument_yaml

    problems: list[str] = []
    data = None
    try:
        with open(path) as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        problems.append(f"cannot be read as YAML: {e}")
    else:
        if not isinstance(data, dict):
            problems.append("must be a mapping at the top level")
    if isinstance(data, dict):
        instruments = data.get("instruments", {})
        if not isinstance(instruments, dict):
            problems.append("'instruments' must be a mapping")
            instruments = {}
        for name, entry in instruments.items():
            if not isinstance(entry, dict):
                problems.append(f"{name}: must be a mapping")
                continue
            try:
                result = validate_instrument_yaml({**entry, "name": name}, path.name)
            except Exception as e:
                # The check itself fails on some values of the wrong type
                # (i5_read_orientation: [] raises TypeError). Report it; the
                # start still stops.
                problems.append(f"{name}: could not be checked: {e}")
                continue
            problems += [f"{name}: {error}" for error in result.errors]
    if problems:
        raise InstrumentConfigError(
            f"{path.name} has errors, so SeqSetup will not start: " + "; ".join(problems)
        )
    return data


def _load_config() -> dict:
    """Load instrument configuration from YAML file, checked."""
    return load_checked_instrument_file(_find_config_path())
```

Find:

```python
# Initialize on module load
try:
    _initialize_config()
except FileNotFoundError as e:
    # Allow module to load even if config is missing (for testing)
    import warnings
    warnings.warn(f"Instrument config not found: {e}")
    _instruments = {}
    _default_cycles = {}
    _index_cycle_options = [8, 10, 12, 17, 24]
```

Replace with:

```python
def _initialize_at_start() -> None:
    """At import. A missing file loads no local instruments, as before; a
    file with errors raises InstrumentConfigError, so SeqSetup does not start
    (spec 2026-09-29 Sample Sheet follow-ups, §4)."""
    global _instruments, _default_cycles, _index_cycle_options
    try:
        _initialize_config()
    except FileNotFoundError as e:
        # Allow module to load even if config is missing (for testing)
        import warnings
        warnings.warn(f"Instrument config not found: {e}")
        _instruments = {}
        _default_cycles = {}
        _index_cycle_options = [8, 10, 12, 17, 24]


# Initialize on module load
_initialize_at_start()
```

- [ ] **Step 4: Run them and the files around them**

Run the Step 2 command: **17 passed**. Then:

```bash
PYTHONPATH=src $PY -m pytest tests/unit/test_instruments.py tests/unit/test_sync_name_rules.py \
  tests/integration/test_scheduled_sync_instrument_cache.py tests/integration/test_group_1c.py \
  -q -p no:cacheprovider
```

Expected: no failures.

- [ ] **Step 5: Commit**

```bash
git add src/seqsetup/data/instruments.py tests/unit/test_instrument_file_check.py
git commit -m "fix(instruments): a broken local instruments file stops SeqSetup from starting (Sample Sheet follow-ups §4)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 8: Docs

**Files:**
- Modify: `docs/admin-guide/profiles.rst`, `docs/admin-guide/instruments.rst`, `docs/user-guide/validation.rst`

No picture changes.

- [ ] **Step 1: The profiles guide**

In `docs/admin-guide/profiles.rst`, find:

```rst
   ---
   ApplicationProfileName: ExternalVariantCalling
   ApplicationProfileVersion: 1.0.0
   ApplicationName: CustomVariantPipeline
   ApplicationType: External
```

Replace with:

```rst
   ---
   ApplicationProfileName: ExternalVariantCalling
   ApplicationProfileVersion: 1.0.0
   ApplicationName: CustomVariantPipeline
   ApplicationType: External

   DataFields:
     - Sample_ID
```

Find:

```rst
- All required fields must be present and non-empty
- ``Version`` must be a valid PEP 440 version
- ``ApplicationProfiles`` must be a non-empty list
- Each application profile reference must have a name and a version
  constraint, and the constraint must itself be valid PEP 440
```

Replace with:

```rst
- All required fields must be present and non-empty; a field with nothing
  after it (``Version:``) is empty
- ``Version`` must be a valid PEP 440 version
- ``ApplicationProfiles`` must be a non-empty list
- Each application profile reference must have a name and a version
  constraint, and the constraint must itself be valid PEP 440
- A version written as a number with a decimal point -- ``Version: 1.10``,
  or ``ApplicationProfileVersion: 1.10`` in a reference -- is refused: YAML
  reads it as the number 1.1. Put it in quotes: ``"1.10"``
```

Find:

```rst
- All four required fields must be present and non-empty
- ``ApplicationProfileVersion`` must be a valid PEP 440 version
```

Replace with:

```rst
- All four required fields must be present and non-empty; a field with
  nothing after it is empty
- ``ApplicationProfileVersion`` must be a valid PEP 440 version, in quotes
  when it has a decimal point (``"1.10"``; unquoted, YAML reads it as 1.1,
  and two versions could become one)
```

Find:

```rst
- ``Settings``, ``Data`` and ``Translate`` must be mappings and
  ``DataFields`` a list, when given
- If ``ApplicationType`` is ``Dragen``: ``Settings`` and ``Data`` must be
  present and be dicts, and ``DataFields`` must be present and be a list
```

Replace with:

```rst
- Every ``Settings`` and ``Data`` value must be text, a whole number or
  ``true``/``false``. These are refused, because the Sample Sheet would not
  get what the file says:

  - a number with a decimal point, such as ``SoftwareVersion: 4.10`` --
    YAML reads it as 4.1. Put it in quotes: ``"4.10"``
  - an empty value (a key with nothing after it). Write ``''`` for an empty
    cell
  - a mapping or a list, which would be written as Python text

- ``BarcodeMismatchesIndex1`` and ``BarcodeMismatchesIndex2`` (BCL Convert
  allows at most 2 mismatches): as a ``Settings`` entry, 0, 1 or 2. As a
  ``Data`` default for a sample's column -- also a column that
  ``Translate`` renames to one of them -- 0, 1, 2, blank (``''``) or ``na``,
  which Illumina uses for a setting that does not apply to a sample.
  ``true`` and ``false`` are refused
- The data section must have a ``Sample_ID`` column, or no row would name
  its sample: ``Sample_ID`` must be in ``DataFields`` (or, when
  ``DataFields`` is missing or empty, be a key of ``Data``), as it is or
  renamed to it by ``Translate``
- ``Settings``, ``Data`` and ``Translate`` must be mappings and
  ``DataFields`` a list, when given. A section left empty (``Settings:``
  with nothing under it) means "none"
- If ``ApplicationType`` is ``Dragen``: ``Settings`` and ``Data`` must be
  present and be dicts, and ``DataFields`` must be present and be a list.
  For a DRAGEN profile an empty section is refused
```

Find:

```rst
   but no per-file error is shown there either. The reason is only visible
   on :doc:`Admin > Logs <logs>`, as a warning naming the file.
```

Replace with:

```rst
   but no per-file error is shown there either. The reason is only visible
   on :doc:`Admin > Logs <logs>`, as a warning naming the file.

   The sync then replaces the stored profiles with the ones that passed, so
   a run that needs a refused profile is stopped at **Mark Ready** with
   *"Application profile '<name>' version '<version>' not found"*. If
   **every** application profile (or every test profile) is refused, the
   sync stops instead and changes nothing: the profiles stored before stay
   in use.
```

- [ ] **Step 2: The instruments guide**

In `docs/admin-guide/instruments.rst`, find:

```rst
file) to change. This shipped list cannot be edited or individually disabled
from the UI.
```

Replace with:

```rst
file) to change. This shipped list cannot be edited or individually disabled
from the UI.

SeqSetup checks this file at every start, the same way a config sync checks
synced instruments. If an instrument in it has a mistake -- say
``i5_read_orientation: forwards`` -- or the file cannot be read, SeqSetup
does not start, and the error names the file, each instrument and each
problem: *"instruments.yaml has errors, so SeqSetup will not start: MiSeq:
i5_read_orientation: Must be one of: forward, reverse-complement (got:
'forwards')"*. Fix the file and start again.
```

- [ ] **Step 3: The validation guide**

In `docs/user-guide/validation.rst`, find:

```rst
- **A hidden character in a sample's name, project or description, or in
  the run's name or description** -- a tab, a NUL or another invisible
  control character, often carried in by pasted text. *"Sample 'ID' has a
  hidden character in its project: U+0009 (tab). Hidden characters can
  break the Sample Sheet. Remove it before marking the run ready."* The
  message names each field and each character by its code. You cannot see
  the character, so the simplest fix is to clear the field and type the
  text again.
```

Replace with:

```rst
- **A hidden character in a sample's name, project or description, or in
  the run's name or description** -- a tab, a NUL or another invisible
  control character, or an invisible formatting character such as a
  zero-width space, a byte-order mark or a direction mark, often carried in
  by pasted text. *"Sample 'ID' has a hidden character in its project:
  U+200B. Hidden characters can break the Sample Sheet. Remove it before
  marking the run ready. If you cannot see it, delete the text and type it
  again."* The message names each field and each character by its code.
```

- [ ] **Step 4: Build the docs**

Run: `$PY -m sphinx -W --keep-going -q -b html docs <a scratch dir outside the repo>; echo "exit $?"`
Expected: `exit 0`.

- [ ] **Step 5: Commit**

```bash
git add docs/admin-guide/profiles.rst docs/admin-guide/instruments.rst docs/user-guide/validation.rst
git commit -m "docs: profile checks at sync, the instruments file check, invisible characters (Sample Sheet follow-ups)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 9: Verify the whole branch

- [ ] **Step 1: The server suite.** Expected **2559 passed**, 0 failed, 0 errors.
  - The change is 2559 − 2362 = 197:
    - unit 190 (Task 1: 16; Task 2: 38; Task 3: 44; Task 4: 5; Task 5: 24; Task 6: 46; Task 7: 17);
    - integration 7 (Task 1: 1; Task 2: 4; Task 5: 1; Task 6: 1).
  - If the total differs, name the term. Never adjust a number to make the sum close.
- [ ] **Step 2: Browser suite.** Expected **102 passed, 54 skipped**.
- [ ] **Step 3: Docs build** with `-W`: exit 0.
- [ ] **Step 4: Break tests.** First, the tree must be clean (everything committed).

  For each mutation:
  1. Read the file.
  2. Compute the mutated text **before** opening the file for writing, and check it differs.
  3. Write it, run the named tests **with `PYTHONDONTWRITEBYTECODE=1`**, and record the result.
  4. Write back the exact text read in (1), not `git show HEAD`.
  5. Check that `git diff --quiet` passes.

  Every mutation must turn a test red.

  Why `PYTHONDONTWRITEBYTECODE=1`: two mutated versions of one file can have the same size and be saved within the same second. Python then runs the first one's cached `.pyc` for the second, and the wrong tests turn red (this happened to mutations 14 and 15 in the dry run).

| # | Mutation | Must fail |
|---|----------|-----------|
| 1 | `hidden_characters`: `in ("Cc", "Cf")` → `== "Cc"` | `test_format_character_is_hidden` (5), the three `TestInvisibleCharactersInText` tests, both writers' `TestInvisibleCharacters`, the integration zero-width test |
| 2 | `_hidden_character_message`: delete ` If you cannot see {pronoun}, delete the text and type it again.` | `test_zero_width_space_in_sample_name_is_an_error`, `test_several_characters_are_called_them`, the integration zero-width test |
| 3 | `_value_kind_problem`: delete the `float` branch | `test_decimal_number_is_refused` (8), `test_unquoted_4_10_is_skipped_and_logged`, both `TestSyncIntoStoredProfiles` tests |
| 4 | `_value_kind_problem`: delete the `(dict, list)` branch | `test_mapping_or_list_is_refused` (4), `test_a_mapping_holding_a_decimal_is_refused_as_a_mapping` |
| 5 | `_value_kind_problem`: delete the `value is None` branch | `test_empty_value_is_refused` (2) |
| 6 | `_is_empty`: `return not str(value).strip()` | the ten `TestEmptyRequiredFields` tests |
| 7 | `validate_application_profile_yaml`: delete the `isinstance(version_val, float)` check | `test_application_profile_version_is_refused`, `test_unquoted_1_10_and_1_1_can_no_longer_collide` |
| 8 | `validate_test_profile_yaml`: delete both `float` checks (Version and the reference) | `test_test_profile_version_is_refused`, `test_reference_version_is_refused` |
| 9 | `is_allowed_mismatch`: `return True` in the `str` branch | the Settings `text-3`, `na`, `blank` and Data `text-3`, `upper-NA`, `space-1` cases; the writer's `text-3`, `na`, `blank`, `upper-NA` cases |
| 10 | `is_allowed_mismatch`: drop `per_sample and` | the Settings `na` and `blank` cases (sync and writer) |
| 11 | `_mismatch_problems`: `column = key` | `test_a_translated_data_column_is_checked` |
| 12 | `_sample_id_column_problems`: `fields = data_fields or []` | `test_sample_id_column_passes[data-keys]`, `[datafields-empty]`, `[datafields-empty-list]` |
| 13 | `_sample_id_column_problems`: `columns = list(fields)` | `test_no_sample_id_column_is_refused[renamed-by-translate]`, `test_sample_id_column_passes[reached-by-translate]` |
| 14 | `ApplicationProfile.from_dict`: `settings=data.get("settings", {})` | `test_from_dict_reads_empty_sections_as_none`, `test_stored_profile_with_empty_sections_exports` |
| 15 | `ApplicationProfile.from_yaml`: `data=yaml_data.get("Data", {})` | `test_from_yaml_reads_an_empty_data_as_none` |
| 16 | `_escape_config_cell`: delete the new kind check | both `test_*_of_the_wrong_kind_is_refused` (8) |
| 17 | writer Settings loop: delete the `_require_profile_mismatch` call | `test_setting_mismatch_outside_0_to_2_is_refused` (5), `test_a_setting_of_3_stops_mark_ready` |
| 18 | `_profile_mismatch_cell`: `return cls._escape_config_cell(value)` only | `test_data_mismatch_default_outside_the_allowed_values_is_refused` (4), `test_a_translated_mismatch_default_is_checked` |
| 19 | writer: delete the `Sample_ID` column check | `test_data_section_without_sample_id_is_refused` (3) |
| 20 | `checked_mismatches`: delete the whole-number check | all 30 `TestMismatchIsAWholeNumber` refusals (the `text-1` ones with a `TypeError`), `test_a_run_stored_with_true_cannot_be_marked_ready` |
| 21 | `SequencingRun.__setattr__`: `value = max(0, min(2, value))` | the `run` refusals |
| 22 | `RunTemplate.__setattr__`: `value = max(0, min(2, value))` | the `template` refusals |
| 23 | `load_checked_instrument_file`: delete the `try`/`except Exception` around the check (call it directly) | `test_a_value_the_check_cannot_read` (2) |
| 24 | `load_checked_instrument_file`: delete `problems += [...]` for `result.errors` | `test_a_bad_i5_orientation`, `test_a_bad_flowcell`, `test_every_problem_is_listed`, `test_the_app_reads_the_file_through_the_check` |
| 25 | `_load_config`: read the file with plain `yaml.safe_load` again | `test_the_app_reads_the_file_through_the_check`, `test_a_broken_file_stops_the_start` |

- [ ] **Step 5: Independent review.**
  - One read-only reviewer runs over `97dc047..HEAD` with the spec, this plan, the worktree path and the commands above.
  - It reports Critical / Important / Minor, each with file:line and a failure scenario.
  - Ask it to look hardest at: any path where a profile value, a mismatch value or an i5 direction can still reach a Sample Sheet unchecked or changed; anything that now refuses what a shipped file or today's Sample Sheets need; a start that could still go ahead with a broken instruments file.
  - Fix Critical and Important findings test-first; list the Minors.
- [ ] **Step 6: Identity checks** (paste the output):

```bash
git branch --show-current
git log --oneline 97dc047..HEAD
git status --short
git diff --stat 97dc047..HEAD -- config/ src/seqsetup/templates/ src/seqsetup/routes/ src/seqsetup/static/ src/seqsetup/api/ tests/browser/ docs/_static/   # must be empty
git diff --stat 97dc047..HEAD -- src/seqsetup/services/samplesheet_v1_exporter.py src/seqsetup/services/json_exporter.py src/seqsetup/services/instrument_validator.py   # must be empty
git diff 97dc047..HEAD | grep -nF "$HOME" || true                                  # must print nothing
```

- [ ] **Step 7: Stop.** Do not merge, push or tag. Hand back with the numbers, the break-test table and the review's findings.
