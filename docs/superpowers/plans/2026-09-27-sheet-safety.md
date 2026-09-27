# Sample Sheet Safety (group 1a) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop synced config names and hidden characters from changing the structure of a Sample Sheet, and stop the run-name route from wiping a field it was not sent (audit 2026-09 N-10, N-11, N-12 rest, N-16).

**Architecture:** One small module, `services/sheet_text.py`, holds the rules (plain name, plain version, hidden character). The config-sync validators refuse bad names; Mark Ready refuses hidden characters with a new validation error; both Sample Sheet writers refuse anything that slips past (fail closed: Mark Ready returns 500 and the run stays Draft). The run-name route writes only the fields it was sent.

**Tech Stack:** Python 3, FastAPI/Starlette, pytest, mongomock, Sphinx.

**Spec:** `docs/superpowers/specs/2026-09-27-sheet-safety-design.md`

## Global Constraints

- Worktree: `W=/home/parlar_ai/dev/seqsetup/.worktrees/sheet-safety`, branch `fix/sheet-safety`. Every git command uses `git -C $W`; check `git -C $W branch --show-current` prints `fix/sheet-safety` before each commit.
- Python: `PY=/home/parlar_ai/dev/seqsetup/.pixi/envs/default/bin/python`. Run tests as `cd $W && PYTHONPATH=src $PY -m pytest <paths> -q -p no:cacheprovider`. Never `pixi run` in the worktree. pytest has no `-n`.
- Plain name: `[A-Za-z0-9_-]+`, full match. Plain version: `[A-Za-z0-9._-]+`, full match.
- Hidden character: Unicode category `Cc` (U+0000–U+001F, U+007F–U+009F) plus U+2028 and U+2029.
- New Mark Ready error category: `hidden_character_in_text`, severity ERROR.
- Existing `line_break_in_sample_text` behaviour must not change; a character is never reported under both categories.
- `_escape_csv` keeps today's handling of tab, LF, CR, `,` and `"`; it raises only for the other hidden characters, and its error names character codes only, never the text.
- No UI change, no screenshots retaken, no data migration.
- Commit trailer on every commit: `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`.
- Do not touch the main checkout `/home/parlar_ai/dev/seqsetup` (the user has uncommitted files there).

---

### Task 1: The shared rules module

**Files:**
- Create: `src/seqsetup/services/sheet_text.py`
- Test: `tests/unit/test_sheet_text.py`

**Interfaces:**
- Produces: `PLAIN_NAME_RE: re.Pattern`, `PLAIN_VERSION_RE: re.Pattern` (use with `.fullmatch`), `hidden_characters(text: str | None) -> list[str]`, `describe(chars: list[str]) -> str`.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_sheet_text.py`:

```python
"""The rules for text written into a Sample Sheet (audit 2026-09 N-10, N-11, N-12)."""

import pytest

from seqsetup.services.sheet_text import (
    PLAIN_NAME_RE,
    PLAIN_VERSION_RE,
    describe,
    hidden_characters,
)


class TestPlainName:
    """A name written into the sheet's structure: letters, digits, '_' and '-'."""

    @pytest.mark.parametrize("value", ["BCLConvert", "NovaSeqXSeries", "Dragen_Germline-2", "a"])
    def test_plain_names_match(self, value):
        assert PLAIN_NAME_RE.fullmatch(value)

    @pytest.mark.parametrize("value", ["", "a b", "a,b", "a]", "a\n", "a.b", "Äpp", "a\x00"])
    def test_other_names_do_not_match(self, value):
        assert not PLAIN_NAME_RE.fullmatch(value)


class TestPlainVersion:
    """A software version: a plain name that may also hold '.'."""

    @pytest.mark.parametrize("value", ["4.3.6", "4.2.7-beta_1"])
    def test_plain_versions_match(self, value):
        assert PLAIN_VERSION_RE.fullmatch(value)

    @pytest.mark.parametrize("value", ["", "4.3 6", "4,3", "4.3.6\n"])
    def test_other_versions_do_not_match(self, value):
        assert not PLAIN_VERSION_RE.fullmatch(value)


class TestHiddenCharacters:
    """Control characters and the Unicode line/paragraph separators."""

    @pytest.mark.parametrize("char", [
        "\x00", "\t", "\n", "\r", "\x0b", "\x0c", "\x1f", "\x7f", "\x85", "\x9b",
        "\u2028", "\u2029",
    ])
    def test_finds_each_hidden_character(self, char):
        assert hidden_characters(f"a{char}b") == [char]

    def test_lists_each_character_once_in_order_of_first_appearance(self):
        assert hidden_characters("\t a \x00 b \t") == ["\t", "\x00"]

    @pytest.mark.parametrize("text", [
        "", "Plain text 1-2_3", "Åsa Öberg", "试验", "Проект", "a b", "2 × 150",
    ])
    def test_finds_nothing_in_visible_text(self, text):
        assert hidden_characters(text) == []

    def test_none_counts_as_empty(self):
        assert hidden_characters(None) == []


class TestDescribe:
    """Character codes for messages; a tab is named."""

    def test_codes_with_tab_named(self):
        assert describe(["\x00", "\t", "\u2028"]) == "U+0000, U+0009 (tab), U+2028"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd $W && PYTHONPATH=src $PY -m pytest tests/unit/test_sheet_text.py -q -p no:cacheprovider`
Expected: collection ERROR, `ModuleNotFoundError: No module named 'seqsetup.services.sheet_text'`.

- [ ] **Step 3: Write minimal implementation**

Create `src/seqsetup/services/sheet_text.py`:

```python
"""What text may be written into a Sample Sheet.

One source for the rules that the config sync, Mark Ready and both Sample
Sheet writers apply.
"""

import re
import unicodedata

# A name written into the sheet's structure — a section header such as
# ``[BCLConvert_Settings]`` or the ``InstrumentPlatform`` line — as is.
# Same alphabet as a Sample ID.
PLAIN_NAME_RE = re.compile(r"[A-Za-z0-9_-]+")

# A software version written as is, e.g. ``4.3.6``.
PLAIN_VERSION_RE = re.compile(r"[A-Za-z0-9._-]+")

_SEPARATORS = frozenset("\u2028\u2029")
_NAMES = {"\t": "tab"}


def hidden_characters(text: str | None) -> list[str]:
    """The distinct hidden characters in ``text``, in order of first
    appearance: control characters (Unicode category Cc) and the Unicode
    line and paragraph separators."""
    return [
        c for c in dict.fromkeys(text or "")
        if unicodedata.category(c) == "Cc" or c in _SEPARATORS
    ]


def describe(chars: list[str]) -> str:
    """Character codes for a message: ``'U+0000, U+0009 (tab)'``."""
    parts = []
    for c in chars:
        code = f"U+{ord(c):04X}"
        parts.append(f"{code} ({_NAMES[c]})" if c in _NAMES else code)
    return ", ".join(parts)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd $W && PYTHONPATH=src $PY -m pytest tests/unit/test_sheet_text.py -q -p no:cacheprovider`
Expected: all passed, 0 failed.

- [ ] **Step 5: Commit**

```bash
git -C $W branch --show-current   # must print fix/sheet-safety
git -C $W add src/seqsetup/services/sheet_text.py tests/unit/test_sheet_text.py
git -C $W commit -m "feat(sheet): one module for the Sample Sheet text rules

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Config sync refuses names that are not plain (N-10, N-11 first line)

**Files:**
- Modify: `src/seqsetup/services/profile_validator.py` (imports at top; `validate_application_profile_yaml`, after the required-fields loop, ~line 108)
- Modify: `src/seqsetup/services/instrument_validator.py` (imports at top; `validate_instrument_yaml` ~line 66; `_validate_onboard_applications` ~lines 273-297; new helper after `_validate_required_string` ~line 131)
- Modify: `docs/admin-guide/profiles.rst` ("Application Profile Validation" list, ~line 300)
- Modify: `docs/admin-guide/instruments.rst` (definition list after **SBS chemistry**, ~line 91)
- Test: `tests/unit/test_profile_validator.py` (append a class), `tests/unit/test_sync_name_rules.py` (create)

**Interfaces:**
- Consumes: `PLAIN_NAME_RE`, `PLAIN_VERSION_RE` from Task 1.
- Produces: nothing new for later tasks.

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_profile_validator.py`:

```python
class TestApplicationNameCharacters:
    """ApplicationName becomes a Sample Sheet section name, written as is, so
    only letters, digits, '_' and '-' are allowed (audit 2026-09 N-10)."""

    BASE = {
        "ApplicationProfileName": "P",
        "ApplicationProfileVersion": "1.0.0",
        "ApplicationName": "BCLConvert",
        "ApplicationType": "Custom",
    }

    @pytest.mark.parametrize("name", [
        "BCLConvert]\n[BCLConvert_Data]", "a,b", "Dragen Germline", "App]", "App\x00", "Äpp",
    ])
    def test_non_plain_application_name_is_refused(self, name):
        with pytest.raises(ProfileValidationError, match="ApplicationName' may only contain"):
            validate_application_profile_yaml({**self.BASE, "ApplicationName": name})

    @pytest.mark.parametrize("name", ["BCLConvert", "DragenGermline", "Custom_App-2"])
    def test_plain_application_name_is_accepted(self, name):
        validate_application_profile_yaml({**self.BASE, "ApplicationName": name})
```

Create `tests/unit/test_sync_name_rules.py`:

```python
"""Names from synced instrument files are written into the Sample Sheet as
is, so the sync refuses anything but plain names (audit 2026-09 N-10, N-11)."""

from pathlib import Path

import pytest
import yaml

from seqsetup.services.instrument_validator import validate_instrument_yaml
from seqsetup.services.profile_validator import validate_application_profile_yaml

REPO = Path(__file__).resolve().parents[2]


def _instrument(**extra) -> dict:
    data = {
        "name": "NovaSeq X Series",
        "samplesheet_name": "NovaSeqXSeries",
        "version": "1.0.0",
        "chemistry_type": "4-color",
        "flowcells": {"10B": {"lanes": 8, "reagent_kits": [300]}},
    }
    data.update(extra)
    return data


def _errors_on(result, field: str) -> list:
    return [e for e in result.errors if e.field == field]


class TestSamplesheetName:
    """The instrument's sample sheet name is the InstrumentPlatform line."""

    @pytest.mark.parametrize("name", ["NovaSeqXSeries\n[Cloud_Data]", "NovaSeq X", "a,b", "X\x00"])
    def test_non_plain_samplesheet_name_is_refused(self, name):
        result = validate_instrument_yaml(_instrument(samplesheet_name=name))

        assert not result.is_valid
        assert _errors_on(result, "samplesheet_name")

    def test_plain_samplesheet_name_is_accepted(self):
        result = validate_instrument_yaml(_instrument())

        assert result.is_valid, [str(e) for e in result.errors]


class TestOnboardApplications:
    """Onboard application names whitelist profile ApplicationNames, and the
    BCL Convert software version is the SoftwareVersion line."""

    @pytest.mark.parametrize("name", ["BCLConvert]\n[Junk", "Dragen Germline", "a,b"])
    def test_non_plain_application_name_is_refused(self, name):
        result = validate_instrument_yaml(
            _instrument(onboard_applications={name: {"software_version": "4.3.6"}})
        )

        assert not result.is_valid
        assert _errors_on(result, "onboard_applications")

    @pytest.mark.parametrize("version", ["4.3.6\n[Junk]", "4.3 6", "4,3"])
    def test_non_plain_software_version_is_refused(self, version):
        result = validate_instrument_yaml(
            _instrument(onboard_applications={"BCLConvert": {"software_version": version}})
        )

        assert not result.is_valid
        assert _errors_on(result, "onboard_applications.BCLConvert.software_version")

    def test_plain_names_and_version_are_accepted(self):
        result = validate_instrument_yaml(_instrument(onboard_applications={
            "BCLConvert": {"software_version": "4.3.6"},
            "Dragen_Germline-2": {},
        }))

        assert result.is_valid, [str(e) for e in result.errors]


class TestShippedConfigStillPasses:
    """Everything SeqSetup ships must still pass the stricter rules."""

    def test_every_shipped_instrument_passes(self):
        data = yaml.safe_load((REPO / "config" / "instruments.yaml").read_text())
        for name, inst in data["instruments"].items():
            yaml_data = dict(inst)
            yaml_data.setdefault("name", name)
            result = validate_instrument_yaml(yaml_data, "instruments.yaml")
            assert result.is_valid, (name, [str(e) for e in result.errors])

    def test_every_shipped_application_profile_passes(self):
        checked = 0
        for path in sorted(REPO.glob("config/**/*.y*ml")):
            data = yaml.safe_load(path.read_text())
            if isinstance(data, dict) and "ApplicationName" in data:
                validate_application_profile_yaml(data, str(path))
                checked += 1
        assert checked >= 5
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd $W && PYTHONPATH=src $PY -m pytest tests/unit/test_profile_validator.py tests/unit/test_sync_name_rules.py -q -p no:cacheprovider`
Expected: the `test_non_plain_*` tests FAIL (no error raised / `result.is_valid` is True); the `plain`/`shipped` tests PASS.

- [ ] **Step 3: Implement the profile rule**

In `src/seqsetup/services/profile_validator.py`, add after the `packaging` imports:

```python
from .sheet_text import PLAIN_NAME_RE
```

In `validate_application_profile_yaml`, directly after the `# Required top-level fields` loop, add:

```python
    # ApplicationName becomes a Sample Sheet section name ([<name>_Settings]),
    # written as is, so it may hold only letters, digits, '_' and '-'.
    app_name = yaml_data.get("ApplicationName")
    if (
        app_name is not None
        and str(app_name).strip()
        and not PLAIN_NAME_RE.fullmatch(str(app_name))
    ):
        errors.append(
            "Field 'ApplicationName' may only contain letters, digits, '_' and '-': "
            f"{str(app_name)!r}"
        )
```

- [ ] **Step 4: Implement the instrument rules**

In `src/seqsetup/services/instrument_validator.py`, add after `from typing import Optional`:

```python
from .sheet_text import PLAIN_NAME_RE, PLAIN_VERSION_RE
```

In `validate_instrument_yaml`, directly after the `samplesheet_name` required-string line, add:

```python
    _validate_plain_name(result, yaml_data, "samplesheet_name")
```

Add this helper directly after `_validate_required_string`:

```python
def _validate_plain_name(result: ValidationResult, data: dict, field: str) -> None:
    """The value is written into the Sample Sheet as is (the InstrumentPlatform
    line), so it may hold only letters, digits, '_' and '-'."""
    value = data.get(field)
    if isinstance(value, str) and value and not PLAIN_NAME_RE.fullmatch(value):
        result.add_error(field, "May only contain letters, digits, '_' and '-'", value)
```

In `_validate_onboard_applications`, directly after the `if not app_name:` block (the one ending in `continue`), add:

```python
        if not PLAIN_NAME_RE.fullmatch(str(app_name)):
            result.add_error(
                "onboard_applications",
                "Application name may only contain letters, digits, '_' and '-'",
                str(app_name),
            )
            continue
```

At the end of the same loop, directly after the existing
`if version is not None and not isinstance(version, str): result.add_error(...)` block, add:

```python
        elif version and not PLAIN_VERSION_RE.fullmatch(version):
            result.add_error(
                f"onboard_applications.{app_name}.software_version",
                "May only contain letters, digits, '.', '_' and '-'",
                version,
            )
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd $W && PYTHONPATH=src $PY -m pytest tests/unit/test_profile_validator.py tests/unit/test_sync_name_rules.py tests/unit/test_kit_cycle_limit.py tests/unit/test_instruments.py -q -p no:cacheprovider`
Expected: all passed, 0 failed.

- [ ] **Step 6: Update the docs**

In `docs/admin-guide/profiles.rst`, "Application Profile Validation" list, add a bullet after the PEP 440 bullet:

```rst
- ``ApplicationName`` may only contain letters, digits, ``_`` and ``-`` --
  it becomes a section name in the Sample Sheet (``[<name>_Settings]``),
  written exactly as given
```

In `docs/admin-guide/instruments.rst`, add a new definition-list entry directly after the **SBS chemistry** entry (before the `.. warning::` about reagent kit cycles):

```rst
**Sample sheet name and onboard application names**
   The sample sheet name (e.g. ``NovaSeqXSeries``) is written on the Sample
   Sheet's ``InstrumentPlatform`` line, and each onboard application name
   (e.g. ``BCLConvert``) decides which application profiles the instrument
   can run. Both may only contain letters, digits, ``_`` and ``-``; an
   onboard application's ``software_version`` may also contain ``.``. A
   synced instrument file that breaks this is skipped, with the reason on
   :doc:`Admin > Logs <logs>`. SeqSetup also refuses to write a Sample Sheet
   holding such a name, so a run cannot be marked Ready with one.
```

- [ ] **Step 7: Build the docs**

Run: `cd $W && $PY -m sphinx -W --keep-going -q -b html docs /tmp/claude-1066/-home-parlar-ai-dev-seqsetup/5fb58df9-3502-4156-b60b-b895fc0e6373/scratchpad/docs-sheet-safety`
Expected: exit 0, no output.

- [ ] **Step 8: Commit**

```bash
git -C $W branch --show-current   # must print fix/sheet-safety
git -C $W add src/seqsetup/services/profile_validator.py src/seqsetup/services/instrument_validator.py \
  tests/unit/test_profile_validator.py tests/unit/test_sync_name_rules.py \
  docs/admin-guide/profiles.rst docs/admin-guide/instruments.rst
git -C $W commit -m "fix(sync): refuse config names the Sample Sheet would write as is (N-10, N-11)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Mark Ready refuses hidden characters (N-12 first line)

**Files:**
- Modify: `src/seqsetup/services/validation.py` (imports ~line 33; class constants after `_SAMPLE_TEXT_FIELDS` ~line 271; `validate_configuration` ~lines 292-334; new methods after `_validate_sample_text_line_breaks` ~line 528)
- Modify: `docs/user-guide/validation.rst` (~line 78), `docs/user-guide/run-setup.rst` (~lines 34-37)
- Test: `tests/unit/test_sample_text_validation.py` (append), `tests/integration/test_sheet_safety.py` (create)

**Interfaces:**
- Consumes: `hidden_characters`, `describe` from Task 1.
- Produces: category `hidden_character_in_text`; `tests/integration/test_sheet_safety.py` with helpers `ORIGIN` and `_seed_draft(ctx, run_id, test_id="", run_description="Plan B") -> str` that Tasks 4 and 5 append to.

- [ ] **Step 1: Write the failing unit tests**

Append to `tests/unit/test_sample_text_validation.py`:

```python
HIDDEN = [
    pytest.param("\x00", "U+0000", id="NUL"),
    pytest.param("\t", "U+0009 (tab)", id="TAB"),
    pytest.param("\x1f", "U+001F", id="US"),
    pytest.param("\x7f", "U+007F", id="DEL"),
    pytest.param("\x9b", "U+009B", id="C1-CSI"),
]


class TestSampleTextHiddenCharacters:
    """A hidden character other than a line break in a sample's name, project
    or description is its own Mark Ready error (audit 2026-09 N-12)."""

    @pytest.mark.parametrize("attr,label", TEXT_FIELDS)
    @pytest.mark.parametrize("char,code", HIDDEN)
    def test_hidden_character_in_sample_text_is_an_error(self, attr, label, char, code):
        sample = Sample(sample_id="S1")
        setattr(sample, attr, f"A{char}B")

        errors = _errors(_run_with(sample), "hidden_character_in_text")

        assert len(errors) == 1
        assert errors[0].severity.value == "error"
        assert errors[0].sample_names == ["S1"]
        assert errors[0].message.startswith(
            f"Sample 'S1' has a hidden character in its {label}: {code}."
        )
        assert "Remove it before marking the run ready." in errors[0].message

    @pytest.mark.parametrize("line_break", LINE_BREAKS)
    def test_line_break_alone_gives_only_the_line_break_error(self, line_break):
        run = _run_with(Sample(sample_id="S1", sample_name=f"A{line_break}B"))

        assert len(_errors(run, "line_break_in_sample_text")) == 1
        assert _errors(run, "hidden_character_in_text") == []

    def test_line_break_and_nul_give_each_error_once(self):
        run = _run_with(Sample(sample_id="S1", project="A\nB\x00C"))

        assert len(_errors(run, "line_break_in_sample_text")) == 1
        hidden = _errors(run, "hidden_character_in_text")
        assert len(hidden) == 1
        assert "U+0000" in hidden[0].message
        assert "U+000A" not in hidden[0].message

    def test_several_fields_and_characters_make_one_error(self):
        sample = Sample(sample_id="S1", project="P\x00", description="D\tE")

        errors = _errors(_run_with(sample), "hidden_character_in_text")

        assert len(errors) == 1
        assert (
            "has hidden characters in its project and description: U+0000, U+0009 (tab)."
            in errors[0].message
        )
        assert "Remove them before marking the run ready." in errors[0].message

    def test_visible_text_in_any_script_is_accepted(self):
        sample = Sample(
            sample_id="S1", sample_name="Åsa Öberg", project="Проект-7",
            description="试验 2, rack A",
        )

        assert _errors(_run_with(sample), "hidden_character_in_text") == []


RUN_TEXT_FIELDS = [
    pytest.param("run_name", "name", id="run_name"),
    pytest.param("run_description", "description", id="run_description"),
]


class TestRunTextHiddenCharacters:
    """The run's name and description are checked for every hidden character
    (audit 2026-09 N-12)."""

    @pytest.mark.parametrize("attr,label", RUN_TEXT_FIELDS)
    @pytest.mark.parametrize("char,code", HIDDEN + [
        pytest.param("\x0b", "U+000B", id="VT"),
        pytest.param("\u2028", "U+2028", id="LINE-SEPARATOR"),
    ])
    def test_hidden_character_in_run_text_is_an_error(self, attr, label, char, code):
        run = _run_with(Sample(sample_id="S1"))
        setattr(run, attr, f"Run{char}1")

        errors = _errors(run, "hidden_character_in_text")

        assert len(errors) == 1
        assert errors[0].severity.value == "error"
        assert errors[0].message.startswith(
            f"The run has a hidden character in its {label}: {code}."
        )

    def test_run_without_samples_is_still_checked(self):
        run = SequencingRun(run_name="Run1", run_description="a\tb")

        assert len(_errors(run, "hidden_character_in_text")) == 1

    def test_line_break_in_description_is_saved_as_a_space(self):
        run = SequencingRun(run_name="Run1", run_description="line one\nline two")

        assert run.run_description == "line one line two"
        assert _errors(run, "hidden_character_in_text") == []

    def test_visible_run_text_is_accepted(self):
        run = _run_with(Sample(sample_id="S1"))
        run.run_description = "Åsa's run, 2 × 150"

        assert _errors(run, "hidden_character_in_text") == []
```

- [ ] **Step 2: Run the unit tests to verify they fail**

Run: `cd $W && PYTHONPATH=src $PY -m pytest tests/unit/test_sample_text_validation.py -q -p no:cacheprovider`
Expected: the `TestSampleTextHiddenCharacters::test_hidden_character_in_sample_text_is_an_error`, `test_line_break_and_nul_give_each_error_once`, `test_several_fields_and_characters_make_one_error`, `TestRunTextHiddenCharacters::test_hidden_character_in_run_text_is_an_error` and `test_run_without_samples_is_still_checked` tests FAIL (`assert 0 == 1` / `assert [] ...`); the others PASS.

- [ ] **Step 3: Write the failing integration test**

Create `tests/integration/test_sheet_safety.py`:

```python
"""Sample Sheet safety through the real routes (audit 2026-09 N-10, N-11,
N-12, N-16)."""

from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import (
    InstrumentPlatform,
    RunCycles,
    SequencingRun,
)

from .conftest import disable_repos


ORIGIN = {"Origin": "http://testserver"}


def _seed_draft(ctx, run_id: str, test_id: str = "", run_description: str = "Plan B") -> str:
    """A NovaSeq X DRAFT run with one indexed sample, ready to be marked ready."""
    run = SequencingRun(
        id=run_id,
        run_name="Safety",
        run_description=run_description,
        instrument_platform=InstrumentPlatform.NOVASEQ_X,
        flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8),
    )
    run.add_sample(Sample(
        sample_id="S1",
        test_id=test_id,
        index_pair=IndexPair(
            id="p1", name="p1",
            index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
            index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5),
        ),
    ))
    ctx.run_repo.save(run)
    return run.id


class TestMarkReadyRefusesHiddenCharacters:
    """A hidden character in run or sample text keeps the run in DRAFT."""

    def test_tab_in_run_description_is_refused(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        run_id = _seed_draft(ctx, "hc-desc")
        assert logged_in_client.post(
            f"/runs/{run_id}/name",
            data={"run_name": "Safety", "run_description": "Plan\tB"},
            headers=ORIGIN,
        ).status_code == 200

        resp = logged_in_client.post(f"/runs/{run_id}/status/ready", headers=ORIGIN)

        assert resp.headers.get("HX-Retarget") == "#error-banner"
        assert "hidden character" in resp.text
        assert "U+0009" in resp.text
        run = ctx.run_repo.get_by_id(run_id)
        assert run.status.value == "draft"
        assert not run.generated_samplesheet_v2

    def test_nul_in_sample_project_is_refused(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        run_id = _seed_draft(ctx, "hc-project")
        sample_id = ctx.run_repo.get_by_id(run_id).samples[0].id
        assert logged_in_client.post(
            f"/runs/{run_id}/samples/{sample_id}",
            data={"project": "P\x00Q"},
            headers=ORIGIN,
        ).status_code == 200

        resp = logged_in_client.post(f"/runs/{run_id}/status/ready", headers=ORIGIN)

        assert resp.headers.get("HX-Retarget") == "#error-banner"
        assert "U+0000" in resp.text
        assert ctx.run_repo.get_by_id(run_id).status.value == "draft"

    def test_visible_text_is_made_ready(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        run_id = _seed_draft(ctx, "hc-control", run_description="Åsa's run, 2 × 150")

        resp = logged_in_client.post(f"/runs/{run_id}/status/ready", headers=ORIGIN)

        assert "HX-Retarget" not in resp.headers, resp.text[:400]
        assert ctx.run_repo.get_by_id(run_id).status.value == "ready"
```

- [ ] **Step 4: Run the integration test to verify it fails**

Run: `cd $W && PYTHONPATH=src $PY -m pytest tests/integration/test_sheet_safety.py -q -p no:cacheprovider`
Expected: `test_tab_in_run_description_is_refused` and `test_nul_in_sample_project_is_refused` FAIL (no `HX-Retarget`; the run is marked ready); `test_visible_text_is_made_ready` PASSES.

- [ ] **Step 5: Implement the check**

In `src/seqsetup/services/validation.py`, add to the imports after `from .cycle_calculator import CycleCalculator`:

```python
from .sheet_text import describe, hidden_characters
```

Directly after the `_SAMPLE_TEXT_FIELDS` tuple, add:

```python
    # Free-text run fields written to the Sample Sheet header, with their UI names.
    _RUN_TEXT_FIELDS = (
        ("run_name", "name"),
        ("run_description", "description"),
    )
```

In `validate_configuration`, directly after the `prerequisite_run_name` block (before `errors.extend(cls._validate_cycles_fit_kit(run))`), add:

```python
        errors.extend(cls._validate_run_text_hidden_characters(run))
```

and directly after `errors.extend(cls._validate_sample_text_line_breaks(run))`, add:

```python
        errors.extend(cls._validate_sample_text_hidden_characters(run))
```

Directly after the `_validate_sample_text_line_breaks` method, add:

```python
    @staticmethod
    def _hidden_character_message(subject: str, fields: list[str], chars: list[str]) -> str:
        many = len(chars) > 1
        return (
            f"{subject} has {'hidden characters' if many else 'a hidden character'} "
            f"in its {' and '.join(fields)}: {describe(chars)}. Hidden characters "
            f"can break the Sample Sheet. Remove {'them' if many else 'it'} before "
            f"marking the run ready."
        )

    @classmethod
    def _validate_run_text_hidden_characters(
        cls, run: SequencingRun
    ) -> list[ConfigurationError]:
        """The run's name and description go into the Sample Sheet header. A
        hidden character in either is an error, not something the exporter
        writes."""
        fields: list[str] = []
        chars: list[str] = []
        for attr, label in cls._RUN_TEXT_FIELDS:
            found = hidden_characters(getattr(run, attr) or "")
            if found:
                fields.append(label)
                chars.extend(c for c in found if c not in chars)
        if not fields:
            return []
        return [ConfigurationError(
            severity=ValidationSeverity.ERROR,
            category="hidden_character_in_text",
            message=cls._hidden_character_message("The run", fields, chars),
        )]

    @classmethod
    def _validate_sample_text_hidden_characters(
        cls, run: SequencingRun
    ) -> list[ConfigurationError]:
        """Sample name, project and description: a hidden character other than
        a line break is an error. Line breaks have their own error above, so a
        character is never reported twice."""
        errors: list[ConfigurationError] = []
        for sample in run.samples:
            fields: list[str] = []
            chars: list[str] = []
            for attr, label in cls._SAMPLE_TEXT_FIELDS:
                found = [
                    c for c in hidden_characters(getattr(sample, attr) or "")
                    if c not in cls._LINE_BREAK_CHARS
                ]
                if found:
                    fields.append(label)
                    chars.extend(c for c in found if c not in chars)
            if not fields:
                continue
            name = sample.sample_id or sample.id
            errors.append(ConfigurationError(
                severity=ValidationSeverity.ERROR,
                category="hidden_character_in_text",
                message=cls._hidden_character_message(f"Sample '{name}'", fields, chars),
                sample_names=[name],
            ))
        return errors
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cd $W && PYTHONPATH=src $PY -m pytest tests/unit/test_sample_text_validation.py tests/integration/test_sheet_safety.py tests/integration/test_mark_ready_sample_text_line_breaks.py -q -p no:cacheprovider`
Expected: all passed, 0 failed.

- [ ] **Step 7: Update the docs**

In `docs/user-guide/validation.rst`, directly after the bullet that starts `- **A line break in a sample's name, project or description.**` (ending `(The message names each field that has one.)`), add:

```rst
- **A hidden character in a sample's name, project or description, or in
  the run's name or description** -- a tab, a NUL or another invisible
  control character, often carried in by pasted text. *"Sample 'ID' has a
  hidden character in its project: U+0009 (tab). Hidden characters can
  break the Sample Sheet. Remove it before marking the run ready."* The
  message names each field and each character by its code.
```

In `docs/user-guide/run-setup.rst`, replace:

```rst
field or press Enter. The run name is limited to 256 characters and
cannot contain a line break; the description is limited to 4096
characters.
```

with:

```rst
field or press Enter. The run name is limited to 256 characters and
cannot contain a line break; the description is limited to 4096
characters, and a line break in it is saved as a space. Neither may hold
another hidden character, such as a tab from pasted text -- **Mark Ready**
refuses the run until it is removed (see :doc:`validation`).
```

- [ ] **Step 8: Build the docs**

Run: `cd $W && $PY -m sphinx -W --keep-going -q -b html docs /tmp/claude-1066/-home-parlar-ai-dev-seqsetup/5fb58df9-3502-4156-b60b-b895fc0e6373/scratchpad/docs-sheet-safety`
Expected: exit 0, no output.

- [ ] **Step 9: Commit**

```bash
git -C $W branch --show-current   # must print fix/sheet-safety
git -C $W add src/seqsetup/services/validation.py tests/unit/test_sample_text_validation.py \
  tests/integration/test_sheet_safety.py docs/user-guide/validation.rst docs/user-guide/run-setup.rst
git -C $W commit -m "fix(validation): Mark Ready refuses hidden characters in run and sample text (N-12)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: The Sample Sheet writers refuse what they cannot make safe (backstop)

**Files:**
- Modify: `src/seqsetup/services/samplesheet_v2_exporter.py` (imports ~line 14; `_write_header` ~line 83; `_write_bclconvert_settings` ~lines 117-119; `_escape_csv` ~lines 386-410; new `_require_plain` after `_escape_identifier` ~line 421; `_write_application_profile_section` ~line 490)
- Modify: `src/seqsetup/services/samplesheet_v1_exporter.py` (imports ~line 9; `_escape_csv` ~lines 161-171)
- Test: `tests/unit/test_samplesheet_v2_exporter.py` (append a class), `tests/unit/test_samplesheet_v1_exporter.py` (append a class), `tests/integration/test_sheet_safety.py` (append a class)

**Interfaces:**
- Consumes: `PLAIN_NAME_RE`, `PLAIN_VERSION_RE`, `hidden_characters`, `describe` (Task 1); `ORIGIN`, `_seed_draft` (Task 3).
- Produces: `SampleSheetV2Exporter._require_plain(value: str, pattern: re.Pattern, what: str) -> str` (raises `ValueError`).

- [ ] **Step 1: Write the failing unit tests**

Append to `tests/unit/test_samplesheet_v2_exporter.py`:

```python
class TestSheetTextGuards:
    """The v2 writer refuses text it cannot make safe (audit 2026-09 N-10,
    N-11, N-12). Mark Ready then fails and the run stays Draft."""

    @pytest.mark.parametrize("char", [
        "\x00", "\x0b", "\x0c", "\x1f", "\x7f", "\x85", "\u2028", "\u2029",
    ])
    def test_escape_csv_refuses_hidden_character(self, char):
        with pytest.raises(ValueError, match=f"U\\+{ord(char):04X}"):
            SampleSheetV2Exporter._escape_csv(f"N{char}X")

    def test_escape_csv_error_does_not_contain_the_text(self):
        with pytest.raises(ValueError) as exc:
            SampleSheetV2Exporter._escape_csv("Patient-Name\x00X")
        assert "Patient-Name" not in str(exc.value)

    def test_escape_csv_keeps_its_quoting_and_formula_guard(self):
        assert SampleSheetV2Exporter._escape_csv("a,b") == '"a,b"'
        assert SampleSheetV2Exporter._escape_csv('a"b') == '"a""b"'
        assert SampleSheetV2Exporter._escape_csv("a\nb") == '"a\nb"'
        assert SampleSheetV2Exporter._escape_csv("\tx") == "'\tx"
        assert SampleSheetV2Exporter._escape_csv("Åsa Öberg") == "Åsa Öberg"

    def test_identifier_with_hidden_character_is_refused(self):
        with pytest.raises(ValueError):
            SampleSheetV2Exporter._escape_identifier("S\x001")

    def test_bad_samplesheet_name_is_refused(self, sample_run, monkeypatch):
        monkeypatch.setattr(
            "seqsetup.services.samplesheet_v2_exporter.get_samplesheet_platform_name",
            lambda platform: "NovaSeqXSeries\n[Cloud_Data]",
        )
        with pytest.raises(ValueError, match="sample sheet name"):
            SampleSheetV2Exporter.export(sample_run)

    def test_bad_software_version_is_refused(self, sample_run, monkeypatch):
        monkeypatch.setattr(
            "seqsetup.services.samplesheet_v2_exporter.get_bclconvert_software_version",
            lambda platform: "4.3.6\n[Junk]",
        )
        with pytest.raises(ValueError, match="software version"):
            SampleSheetV2Exporter.export(sample_run)

    def test_bad_application_name_is_refused(self):
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
        app_profile = ApplicationProfile(
            name="Bad", version="1.0.0", application_type="Custom",
            application_name="BCLConvert]\n[Junk",
            settings={}, data_fields=["Sample_ID"], data={},
        )
        tp = TestProfile(
            test_type="WGS", test_name="WGS", version="1.0.0",
            application_profiles=[ApplicationProfileReference(profile_name="Bad", profile_version="1.0.0")],
        )

        with pytest.raises(ValueError, match="ApplicationName"):
            SampleSheetV2Exporter.export(
                run,
                _StubTestProfileRepo({"WGS": tp}),
                _StubAppProfileRepo({("Bad", "1.0.0"): app_profile}),
            )

    def test_plain_names_are_written_unchanged(self, sample_run):
        output = SampleSheetV2Exporter.export(sample_run)

        assert "InstrumentPlatform,NovaSeqXSeries" in output
        assert "SoftwareVersion,4.3.6" in output
```

Append to `tests/unit/test_samplesheet_v1_exporter.py` (check the file already imports `pytest` and `SampleSheetV1Exporter`; add `import pytest` at the top if it does not):

```python
class TestSheetTextGuardV1:
    """The v1 writer refuses hidden characters it cannot make safe (audit
    2026-09 N-12)."""

    @pytest.mark.parametrize("char", ["\x00", "\x0b", "\x0c", "\x85", "\u2028"])
    def test_escape_csv_refuses_hidden_character(self, char):
        with pytest.raises(ValueError, match=f"U\\+{ord(char):04X}"):
            SampleSheetV1Exporter._escape_csv(f"N{char}X")

    def test_escape_csv_keeps_its_quoting_and_formula_guard(self):
        assert SampleSheetV1Exporter._escape_csv("a,b") == '"a,b"'
        assert SampleSheetV1Exporter._escape_csv("a\rb") == '"a\rb"'
        assert SampleSheetV1Exporter._escape_csv("\tx") == "'\tx"
```

- [ ] **Step 2: Run the unit tests to verify they fail**

Run: `cd $W && PYTHONPATH=src $PY -m pytest tests/unit/test_samplesheet_v2_exporter.py tests/unit/test_samplesheet_v1_exporter.py -q -p no:cacheprovider -k "Guard"`
Expected: every `*_refuses_*`, `*_is_refused` and `test_escape_csv_error_does_not_contain_the_text` test FAILS with `DID NOT RAISE`; `test_escape_csv_keeps_its_quoting_and_formula_guard` and `test_plain_names_are_written_unchanged` PASS.

- [ ] **Step 3: Write the failing integration tests**

Append to `tests/integration/test_sheet_safety.py`. Add these imports at the top of the file, after the existing `seqsetup.models` imports:

```python
from seqsetup.data import instruments as instruments_module
from seqsetup.models.application_profile import ApplicationProfile
from seqsetup.models.instrument_definition import InstrumentDefinition, OnboardApplication
from seqsetup.models.test_profile import ApplicationProfileReference, TestProfile
from seqsetup.services.validation import ValidationService, clear_validation_cache
```

Then append:

```python
def _seed_synced_profile(ctx, app_name: str) -> None:
    """What a config sync stores, written straight to the database so the
    sync validator is bypassed. The synced instrument lists the same
    application, so the existing app_not_available check passes and Mark
    Ready reaches the Sample Sheet writer."""
    ctx.app_profile_repo.save(ApplicationProfile(
        name="GuardProfile",
        version="1.0",
        application_type="Dragen",
        application_name=app_name,
        settings={"SoftwareVersion": "4.3.6"},
        data={},
        data_fields=["Sample_ID", "Index", "Index2"],
        translate={},
    ))
    ctx.test_profile_repo.save(TestProfile(
        test_type="GUARD_T",
        test_name="Guard",
        description="d",
        version="1.0",
        application_profiles=[
            ApplicationProfileReference(profile_name="GuardProfile", profile_version="1.0")
        ],
    ))
    ctx.instrument_definition_repo.save(InstrumentDefinition(
        name="NovaSeq X Series",
        samplesheet_name="NovaSeqXSeries",
        version="1.0.0",
        chemistry_type="2-color",
        onboard_applications=[OnboardApplication(name=app_name, software_version="4.3.6")],
    ))
    instruments_module.clear_synced_instruments_cache()
    clear_validation_cache()


def _assert_validation_passes(ctx, run_id: str) -> None:
    run = ctx.run_repo.get_by_id(run_id)
    result = ValidationService.validate_run(
        run,
        test_profile_repo=ctx.test_profile_repo,
        app_profile_repo=ctx.app_profile_repo,
        instrument_config=ctx.instrument_config,
    )
    assert result.error_count == 0, "validation must pass, so only the export guard can stop Mark Ready"


class TestExportGuardStopsBadSyncedNames:
    """A synced ApplicationName that slipped past the sync check stops Mark
    Ready at the Sample Sheet writer; the run stays Draft (audit 2026-09 N-10)."""

    def test_bad_application_name_stops_mark_ready(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        try:
            _seed_synced_profile(ctx, "Evil\n[Junk")
            run_id = _seed_draft(ctx, "guard-appname", test_id="GUARD_T")
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

    def test_plain_application_name_is_made_ready(self, logged_in_client, fresh_app):
        """CONTROL: the same setup with a plain name is marked ready, so the
        test above fails only because of the name."""
        _app, ctx, _db = fresh_app
        try:
            _seed_synced_profile(ctx, "GuardApp")
            run_id = _seed_draft(ctx, "guard-control", test_id="GUARD_T")
            _assert_validation_passes(ctx, run_id)

            resp = logged_in_client.post(f"/runs/{run_id}/status/ready", headers=ORIGIN)

            assert resp.status_code == 200, resp.text[:400]
            assert "HX-Retarget" not in resp.headers, resp.text[:400]
            run = ctx.run_repo.get_by_id(run_id)
            assert run.status.value == "ready"
            assert "[GuardApp_Settings]" in run.generated_samplesheet_v2
        finally:
            instruments_module.clear_synced_instruments_cache()
            clear_validation_cache()
```

- [ ] **Step 4: Run the integration tests to verify the right one fails**

Run: `cd $W && PYTHONPATH=src $PY -m pytest tests/integration/test_sheet_safety.py -q -p no:cacheprovider -k ExportGuard`
Expected: `test_bad_application_name_stops_mark_ready` FAILS at `assert resp.status_code == 500` (it is 200 today; `_assert_validation_passes` must have PASSED — if it fails instead, the setup is wrong: stop and fix the setup, not the assertion). `test_plain_application_name_is_made_ready` PASSES.

- [ ] **Step 5: Implement the v2 guards**

In `src/seqsetup/services/samplesheet_v2_exporter.py`, add after `from .samplesheet_v1_exporter import _PLAIN_IDENTIFIER_RE, _reverse_complement`:

```python
from .sheet_text import PLAIN_NAME_RE, PLAIN_VERSION_RE, describe, hidden_characters
```

In `_write_header`, replace:

```python
        platform_name = get_samplesheet_platform_name(run.instrument_platform)
```

with:

```python
        platform_name = cls._require_plain(
            get_samplesheet_platform_name(run.instrument_platform),
            PLAIN_NAME_RE, "Instrument sample sheet name",
        )
```

In `_write_bclconvert_settings`, replace:

```python
        if software_version:
            output.write(f"SoftwareVersion,{software_version}\n")
```

with:

```python
        if software_version:
            software_version = cls._require_plain(
                software_version, PLAIN_VERSION_RE, "BCL Convert software version"
            )
            output.write(f"SoftwareVersion,{software_version}\n")
```

In `_escape_csv`, add a third point to the docstring, directly before its closing `"""`:

```python
        3. Characters quoting cannot make safe: any other hidden character
           (NUL, VT, FF, NEL, U+2028, ...) raises ``ValueError``. Mark Ready
           refuses them first; this is the backstop. The error names the
           character codes only — the text can be patient data.
```

and add as the first lines of the body (before `if value and value[0] in (...)`):

```python
        unsafe = [c for c in hidden_characters(value) if c not in "\t\n\r"]
        if unsafe:
            raise ValueError(
                f"Hidden character ({describe(unsafe)}) cannot be written to the Sample Sheet"
            )
```

Directly after the `_escape_identifier` method, add:

```python
    @classmethod
    def _require_plain(cls, value: str, pattern, what: str) -> str:
        """Return ``value`` if it may be written into the sheet's structure as
        is (a section header or a header line); raise ``ValueError`` if not.
        These values come from the synced config, and quoting cannot make a
        section header safe."""
        if not pattern.fullmatch(value or ""):
            raise ValueError(f"{what} {value!r} cannot be written to the Sample Sheet")
        return value
```

In `_write_application_profile_section`, replace:

```python
        app_name = profile.application_name
```

with:

```python
        app_name = cls._require_plain(profile.application_name, PLAIN_NAME_RE, "ApplicationName")
```

- [ ] **Step 6: Implement the v1 guard**

In `src/seqsetup/services/samplesheet_v1_exporter.py`, add after `from ..models.sequencing_run import InstrumentPlatform, SequencingRun`:

```python
from .sheet_text import describe, hidden_characters
```

In `_escape_csv`, add as the first lines of the body (before `if value and value[0] in (...)`):

```python
        unsafe = [c for c in hidden_characters(value) if c not in "\t\n\r"]
        if unsafe:
            raise ValueError(
                f"Hidden character ({describe(unsafe)}) cannot be written to the Sample Sheet"
            )
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cd $W && PYTHONPATH=src $PY -m pytest tests/unit/test_samplesheet_v2_exporter.py tests/unit/test_samplesheet_v1_exporter.py tests/unit/test_check_broken_samplesheets.py tests/integration/test_sheet_safety.py -q -p no:cacheprovider`
Expected: all passed, 0 failed.

- [ ] **Step 8: Run the whole server suite (the writers are used everywhere)**

Run: `cd $W && PYTHONPATH=src $PY -m pytest tests/unit tests/integration -q -p no:cacheprovider`
Expected: 0 failed. If an existing test fails because it feeds a hidden character to a writer on purpose, read it: if it asserts the old raw output, it pinned the defect — update it to expect `ValueError` and say so in the commit message. Any other failure: stop and investigate.

- [ ] **Step 9: Commit**

```bash
git -C $W branch --show-current   # must print fix/sheet-safety
git -C $W add src/seqsetup/services/samplesheet_v2_exporter.py src/seqsetup/services/samplesheet_v1_exporter.py \
  tests/unit/test_samplesheet_v2_exporter.py tests/unit/test_samplesheet_v1_exporter.py tests/integration/test_sheet_safety.py
git -C $W commit -m "fix(export): the Sample Sheet writers refuse unsafe names and hidden characters (N-10, N-11, N-12)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: The run-name route writes only what it was sent (N-16)

**Files:**
- Modify: `src/seqsetup/routes/runs.py` (`update_run_name`, ~lines 147-161)
- Test: `tests/integration/test_sheet_safety.py` (append a class)

**Interfaces:**
- Consumes: `ORIGIN`, `_seed_draft` (Task 3).

- [ ] **Step 1: Write the failing tests**

Append to `tests/integration/test_sheet_safety.py`:

```python
class TestRunNameRouteKeepsUnsentFields:
    """POST /runs/{id}/name writes only the fields it was sent (audit 2026-09
    N-16; CLAUDE.md "Partial updates update only what was submitted")."""

    def test_name_only_keeps_the_description(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _seed_draft(ctx, "n16-name", run_description="KEEP-THIS-DESCRIPTION")

        resp = logged_in_client.post(
            f"/runs/{run_id}/name", data={"run_name": "Renamed"}, headers=ORIGIN
        )

        assert resp.status_code == 200
        run = ctx.run_repo.get_by_id(run_id)
        assert run.run_name == "Renamed"
        assert run.run_description == "KEEP-THIS-DESCRIPTION"

    def test_description_only_keeps_the_name(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _seed_draft(ctx, "n16-desc")

        resp = logged_in_client.post(
            f"/runs/{run_id}/name", data={"run_description": "New plan"}, headers=ORIGIN
        )

        assert resp.status_code == 200
        run = ctx.run_repo.get_by_id(run_id)
        assert run.run_name == "Safety"
        assert run.run_description == "New plan"

    def test_both_fields_are_saved(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _seed_draft(ctx, "n16-both")

        resp = logged_in_client.post(
            f"/runs/{run_id}/name",
            data={"run_name": "Both", "run_description": ""},
            headers=ORIGIN,
        )

        assert resp.status_code == 200
        run = ctx.run_repo.get_by_id(run_id)
        assert run.run_name == "Both"
        assert run.run_description == ""

    def test_neither_field_is_refused_and_nothing_is_saved(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _seed_draft(ctx, "n16-none")
        before = ctx.run_repo.get_by_id(run_id).updated_at

        resp = logged_in_client.post(f"/runs/{run_id}/name", data={}, headers=ORIGIN)

        assert resp.status_code == 400
        assert "Nothing to save" in resp.text
        run = ctx.run_repo.get_by_id(run_id)
        assert run.updated_at == before
        assert (run.run_name, run.run_description) == ("Safety", "Plan B")
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd $W && PYTHONPATH=src $PY -m pytest tests/integration/test_sheet_safety.py -q -p no:cacheprovider -k RunNameRoute`
Expected: `test_name_only_keeps_the_description` FAILS (`'' == 'KEEP-THIS-DESCRIPTION'`), `test_description_only_keeps_the_name` FAILS (`'' == 'Safety'`), `test_neither_field_is_refused_and_nothing_is_saved` FAILS (`200 == 400`); `test_both_fields_are_saved` PASSES.

- [ ] **Step 3: Implement**

In `src/seqsetup/routes/runs.py`, replace the body of `update_run_name` after its docstring:

```python
    form = await request.form()
    run_name = sanitize_string(form.get("run_name", ""), 256)
    run_description = sanitize_string(form.get("run_description", ""), 4096)

    with saving_run(run, ctx, request):
        run.run_name = run_name
        run.run_description = run_description
    return Response("")
```

with:

```python
    form = await request.form()
    # Write only the fields that were sent: a missing field must not be
    # saved as "" over its current value.
    has_name = "run_name" in form
    has_description = "run_description" in form
    if not (has_name or has_description):
        return Response("Nothing to save", status_code=400)

    with saving_run(run, ctx, request):
        if has_name:
            run.run_name = sanitize_string(form.get("run_name", ""), 256)
        if has_description:
            run.run_description = sanitize_string(form.get("run_description", ""), 4096)
    return Response("")
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd $W && PYTHONPATH=src $PY -m pytest tests/integration/test_sheet_safety.py tests/integration/test_run_history.py tests/integration/test_smoke_validation.py tests/integration/test_smoke_wizard.py -q -p no:cacheprovider`
Expected: all passed, 0 failed.

- [ ] **Step 5: Commit**

```bash
git -C $W branch --show-current   # must print fix/sheet-safety
git -C $W add src/seqsetup/routes/runs.py tests/integration/test_sheet_safety.py
git -C $W commit -m "fix(runs): the run-name route writes only the fields it was sent (N-16)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: Verify independently

No new code. Everything here must be run and its real output recorded.

- [ ] **Step 1: Full server suite**

Run: `cd $W && PYTHONPATH=src $PY -m pytest tests/unit tests/integration -q -p no:cacheprovider`
Expected: 0 failed; passed = 1791 (main at bfe7be8) + the new tests. Name the count.

- [ ] **Step 2: Browser suite**

Run: `cd $W && PYTHONPATH=src $PY -m pytest tests/browser -q -p no:cacheprovider`
Expected: same as main at 59ec5cc/bfe7be8 — 92 passed, 52 skipped (the skipped ones are the gated docs screenshots). Any new failure: investigate.

- [ ] **Step 3: Docs build and picture check**

Run: `cd $W && $PY -m sphinx -W --keep-going -q -b html docs /tmp/claude-1066/-home-parlar-ai-dev-seqsetup/5fb58df9-3502-4156-b60b-b895fc0e6373/scratchpad/docs-sheet-safety; echo exit=$?`
Expected: `exit=0`. (`tests/unit/test_docs_images.py` ran in Step 1.)

- [ ] **Step 4: Break tests — each guard must be caught**

For each row: make the edit, run the named test, confirm it FAILS for the stated reason, undo the edit with the Edit tool, then confirm `git -C $W diff --stat` is empty. Never use `git checkout --` or `git stash`.

| Edit | Test that must fail |
|---|---|
| `profile_validator.py`: change `not PLAIN_NAME_RE.fullmatch(str(app_name))` to `False` | `tests/unit/test_profile_validator.py -k TestApplicationNameCharacters` |
| `instrument_validator.py`: make `_validate_plain_name` `return` at its first line | `tests/unit/test_sync_name_rules.py -k TestSamplesheetName` |
| `validation.py`: comment out `errors.extend(cls._validate_run_text_hidden_characters(run))` | `tests/integration/test_sheet_safety.py -k tab_in_run_description` |
| `validation.py`: comment out `errors.extend(cls._validate_sample_text_hidden_characters(run))` | `tests/integration/test_sheet_safety.py -k nul_in_sample_project` |
| `samplesheet_v2_exporter.py`: in `_require_plain`, change `if not pattern.fullmatch(...)` to `if False:` | `tests/integration/test_sheet_safety.py -k bad_application_name` |
| `samplesheet_v2_exporter.py`: in `_escape_csv`, change `if unsafe:` to `if False:` | `tests/unit/test_samplesheet_v2_exporter.py -k escape_csv_refuses` |
| `samplesheet_v1_exporter.py`: in `_escape_csv`, change `if unsafe:` to `if False:` | `tests/unit/test_samplesheet_v1_exporter.py -k escape_csv_refuses` |
| `runs.py`: replace `if has_name:` with `if True:` | `tests/integration/test_sheet_safety.py -k description_only_keeps_the_name` |

- [ ] **Step 5: Re-run the audit's own proofs — they must now fail**

```bash
mkdir -p $W/tests/integration/security_proofs
touch $W/tests/integration/security_proofs/__init__.py
cp /home/parlar_ai/seqsetup-audit-run/proofs/test_c_config_sync_unescaped_export.py \
   /home/parlar_ai/seqsetup-audit-run/proofs/test_c_escape_csv_gaps.py \
   /home/parlar_ai/seqsetup-audit-run/proofs/test_orch_partial_update_run_name.py \
   $W/tests/integration/security_proofs/
cd $W && PYTHONPATH=src $PY -m pytest tests/integration/security_proofs -q -p no:cacheprovider
```

Expected: every HARM test FAILS (a PASS means the defect still exists); CONTROL tests may pass. Record each result. Then remove the copies: `rm -r $W/tests/integration/security_proofs` and confirm `git -C $W status --porcelain` shows nothing under `tests/integration/security_proofs`. These files must never be committed — the repo is public.

- [ ] **Step 6: Independent review**

Use superpowers:requesting-code-review with BASE = `bfe7be8` (main when the branch was made; the diff then includes the spec and this plan, which the reviewer should check the code against) and HEAD = the Task 5 commit. Fix Critical and Important findings with a failing test first; re-run Step 1 after any fix.

- [ ] **Step 7: Report**

Report to the user: what changed, the real numbers from Steps 1–5, the review outcome, and that the branch is ready to merge on their "commit and merge". Do not merge or push.

---

## Addendum: tasks 7 and 8 (after the independent review)

The spec's addendum explains why. Same constraints as above.

### Task 7: No hidden characters in synced profile values

**Files:** `src/seqsetup/services/sheet_text.py`, `src/seqsetup/services/profile_validator.py`,
`src/seqsetup/services/samplesheet_v2_exporter.py` (`_escape_csv`, new `_escape_config_cell`,
`_write_application_profile_section` cells at the Settings line, the column-name line, the two
BarcodeMismatches defaults and the final `else` default), `src/seqsetup/services/samplesheet_v1_exporter.py`
(`_escape_csv`), `docs/admin-guide/profiles.rst`. Tests: `tests/unit/test_sheet_text.py`,
`tests/unit/test_profile_validator.py`, `tests/unit/test_samplesheet_v2_exporter.py`,
`tests/integration/test_sheet_safety.py`.

**Interfaces:** Produces `refuse_hidden_characters(value: str, allow: str = "") -> None` (raises
`ValueError("Hidden character (<describe>) cannot be written to the Sample Sheet")`) and
`SampleSheetV2Exporter._escape_config_cell(value) -> str`.

- [ ] Write failing tests: `TestRefuseHiddenCharacters` (sheet_text); `TestProfileValuesHiddenCharacters`
  (validator: LF, CR, tab, NUL, U+2028 in a Settings value, a Settings key, a Data value, a nested
  Data value, a DataFields entry, a Translate value and key; a Dragen profile too; plain values,
  numbers, booleans and None accepted); `TestProfileCellGuard` (writer: LF in a setting value, a
  setting key, a Data default, a BarcodeMismatches default and a translated column name; a tab in a
  Data default; plain cells still written); integration
  `test_line_break_in_synced_setting_stops_mark_ready` (setup as the ApplicationName test, with
  `Settings={"SoftwareVersion": "4.3.6\n[Junk]"}`; asserts validation passes, then 500 and Draft).
- [ ] Run them; each must fail for the missing rule (no error / DID NOT RAISE / 200 instead of 500).
- [ ] Implement `refuse_hidden_characters` in `sheet_text.py`; make both `_escape_csv` methods call it
  with `allow="\t\n\r"` in place of their copied block; add `_escape_config_cell` and use it for the
  five profile cells; add `_hidden_in` and the Settings/Data/DataFields/Translate loop to
  `validate_application_profile_yaml`; add the rule to the profile validation list in `profiles.rst`.
- [ ] Run the tests, the exporter and validator test files, and `test_sheet_safety.py`: all pass.
- [ ] Commit: `fix(sync, export): no hidden characters in synced profile values`.

### Task 8: Review minors

- [ ] Replace every literal U+2028/U+2029 in `src/`, `tests/` and this plan with `\u2028`/`\u2029`
  escapes; confirm `grep -rlP '[\x{2028}\x{2029}]' src tests docs` finds nothing.
- [ ] `test_sync_name_rules.py`: also validate every `config/instruments/*.yaml` file.
- [ ] `test_sample_text_validation.py`: parametrize the line-break-only test over
  `sorted(ValidationService._LINE_BREAK_CHARS)`.
- [ ] `_require_plain`: `text = "" if value is None else str(value)`; check and return `text`.
  Test: `_require_plain(4.3, PLAIN_VERSION_RE, "x") == "4.3"` (write it first, see it fail with
  `TypeError`).
- [ ] v2 `_escape_csv` docstring: "Three independent concerns".
- [ ] `validation.py`: put `from .sheet_text import ...` after `.index_collision_validator`.
- [ ] Docs: `instruments.rst` — the writer checks the sample sheet name (and a profile's
  `ApplicationName`), not onboard application names; `run-setup.rst` — a line break in the name
  or the description is saved as a space; `validation.rst` — you cannot see the character, so
  clear the field and type the text again.
- [ ] Run the touched test files; commit: `fix: review follow-ups for the Sample Sheet safety change`.
- [ ] Then repeat Task 6 Steps 1–4 (full server suite, browser suite with CSS built, docs build,
  break tests for the new guards) and ask the reviewer to check the new commits.

## Addendum: task 9 (after the second review)

The spec's second addendum explains why. Same constraints as above.

### Task 9: Plain names and no section-starting values in synced profiles

**Files:** `src/seqsetup/services/sheet_text.py` (new `starts_a_section(text: str) -> bool`),
`src/seqsetup/services/profile_validator.py` (`_is_plain_name`, shape loop, name loop, value loop,
Dragen shape checks now only for `None`), `src/seqsetup/services/samplesheet_v2_exporter.py`
(`_require_plain` refuses non-text; setting name and column name through `_require_plain`;
`_escape_config_cell` refuses a value that starts a section), `docs/admin-guide/profiles.rst`,
`docs/user-guide/run-setup.rst`. Tests: `tests/unit/test_sheet_text.py` (`TestStartsASection`),
`tests/unit/test_profile_validator.py` (`TestProfileNames`, `TestProfileValuesStartingABracket`,
`TestProfileSectionShapes`, `test_shipped_application_profiles_pass`),
`tests/unit/test_samplesheet_v2_exporter.py` (`test_non_string_config_value_is_refused`,
`TestProfileNameGuard`, `TestProfileValueBracketGuard`; the setting-key and column-name cases move
out of `TestProfileCellGuard`), `tests/integration/test_sheet_safety.py`
(`test_section_name_as_synced_setting_name_stops_mark_ready`).

- [x] Write the failing tests; run them: 35 fail for the missing rules (no error, DID NOT RAISE,
  200 instead of 500, ImportError for `starts_a_section`).
- [x] Implement; the four test files pass (274).
- [x] Break tests: undo each new guard in turn (setting name, column name, value bracket, non-text,
  sync names, double report, sync values, sync shapes, Dragen shape, `lstrip`, ApplicationName
  non-text); every one is caught.
- [x] Docs build; full server suite (2041 passed); commit
  `fix(sync, export): plain names and no section-starting values in synced profiles`.
- [x] Reviewer checked the change: no Critical or Important issue. Doc wording fixed and a
  test that exports every shipped profile added (break-tested); older gaps recorded as
  follow-ups in the spec.
- [ ] Browser suite (CSS built).
