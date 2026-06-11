# Run Templates & Clone-Run Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let users duplicate an existing run (config-only or full, for re-runs) and save/reuse org-wide named run templates that optionally carry scaffold (control) samples.

**Architecture:** A new `RunTemplate` dataclass + thin `RunTemplateRepository`, kept structurally outside the run state machine. A single `build_draft_run()` service produces a fresh DRAFT `SequencingRun` from either an existing run (clone) or a template, with reference-integrity refusal, sample-count-cap enforcement, analyses-filtering, and export/status sanitisation. New routes for clone, save-as-template, template CRUD, and create-from-template, plus dashboard/run-edit UI hooks.

**Tech Stack:** Python 3 / dataclasses, FastAPI + APIRouter, Jinja2 + jinja2-fragments, MongoDB via `BaseRepository`, HTMX, pytest (`pixi run test`).

---

## Spec

Source spec: `docs/superpowers/specs/2026-06-11-run-templates-clone-design.md`. Read it before starting.

## File Structure

**Create:**
- `src/seqsetup/models/run_template.py` — `RunTemplate` dataclass (self-validating, `to_dict`/`from_dict`).
- `src/seqsetup/repositories/run_template_repo.py` — `RunTemplateRepository(BaseRepository[RunTemplate])`.
- `src/seqsetup/services/run_builder.py` — `build_draft_run()` + `RunInstantiationError`.
- `src/seqsetup/routes/run_templates.py` — clone, save-as-template, template list/edit/delete, create-from-template routes.
- `src/seqsetup/templates/run_templates/list.html` — template library page.
- `tests/unit/test_run_template_model.py`
- `tests/unit/test_run_builder.py`
- `tests/integration/test_run_templates_routes.py`

**Modify:**
- `src/seqsetup/repositories/__init__.py` — export `RunTemplateRepository`.
- `src/seqsetup/context.py` — add `run_template_repo` field.
- `src/seqsetup/startup.py` — register repo in `_REPO_REGISTRY`, add getter, wire into `get_app_context()`.
- `src/seqsetup/app.py` — `include_router(run_templates.router)`.
- `src/seqsetup/templates/dashboard.html` — "Duplicate" action per run; "Start from template" entry.
- `src/seqsetup/templates/runs/edit.html` — "Save as template" button (link/target into the new routes).

---

## Task 1: `RunTemplate` model

**Files:**
- Create: `src/seqsetup/models/run_template.py`
- Test: `tests/unit/test_run_template_model.py`

- [ ] **Step 1: Write the failing test**

```python
"""Tests for the RunTemplate model."""

from datetime import datetime

from seqsetup.models.analysis import Analysis, AnalysisType, DRAGENPipeline
from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles
from seqsetup.models.run_template import RunTemplate


def _pair():
    return IndexPair(
        id="kit_D701",
        name="D701",
        index1=Index(name="D701", sequence="ATTACTCG", index_type=IndexType.I7),
        index2=Index(name="D501", sequence="TATAGCCT", index_type=IndexType.I5),
    )


class TestRunTemplateModel:
    def test_round_trips_through_dict(self):
        tmpl = RunTemplate(
            name="WGS Standard",
            description="Standard whole-genome assay",
            created_by="alice",
            updated_by="alice",
            run_description="seeded run description",
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            reagent_cycles=300,
            run_cycles=RunCycles(151, 151, 10, 10),
            barcode_mismatches_index1=1,
            barcode_mismatches_index2=1,
            no_lane_splitting=True,
            analyses=[Analysis(
                name="Germline",
                analysis_type=AnalysisType.DRAGEN_ONBOARD,
                dragen_pipeline=DRAGENPipeline.GERMLINE,
                sample_ids=["CTRL_POS"],
            )],
            scaffold_samples=[Sample(sample_id="CTRL_POS", index_pair=_pair())],
        )
        restored = RunTemplate.from_dict(tmpl.to_dict())
        assert restored.name == "WGS Standard"
        assert restored.description == "Standard whole-genome assay"
        assert restored.instrument_platform == InstrumentPlatform.NOVASEQ_X
        assert restored.flowcell_type == "10B"
        assert restored.reagent_cycles == 300
        assert restored.run_cycles.read1_cycles == 151
        assert restored.no_lane_splitting is True
        assert restored.scaffold_samples[0].sample_id == "CTRL_POS"
        assert restored.scaffold_samples[0].has_index is True
        assert restored.analyses[0].sample_ids == ["CTRL_POS"]

    def test_name_caps_and_strips_crlf_on_assignment(self):
        tmpl = RunTemplate(name="ok")
        tmpl.name = "bad\r\nname"
        assert "\r" not in tmpl.name and "\n" not in tmpl.name
        tmpl.name = "x" * 500
        assert len(tmpl.name) == 256

    def test_description_caps_on_assignment(self):
        tmpl = RunTemplate(name="ok")
        tmpl.description = "y" * 5000
        assert len(tmpl.description) == 4096

    def test_id_is_assigned_by_default(self):
        assert RunTemplate(name="ok").id
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pixi run test tests/unit/test_run_template_model.py -v`
Expected: FAIL — `ModuleNotFoundError: seqsetup.models.run_template`.

- [ ] **Step 3: Write minimal implementation**

Create `src/seqsetup/models/run_template.py`. Mirror the `SequencingRun` self-validating pattern (invariants in `__setattr__`, `to_dict`/`from_dict`). Reuse the existing `RunCycles`, `Sample`, `Analysis`, `InstrumentPlatform` types.

```python
"""Run template model — a reusable run configuration with optional scaffold samples.

A RunTemplate is deliberately NOT a SequencingRun and has no status: it lives
entirely outside the run state machine, dashboard, JSON API, and export
pipeline. New runs are produced from it via services.run_builder.build_draft_run.
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from .analysis import Analysis
from .sample import Sample
from .sequencing_run import InstrumentPlatform, RunCycles


@dataclass
class RunTemplate:
    """A saved, reusable run configuration plus optional scaffold samples."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""

    created_by: str = ""
    updated_by: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)

    # Run configuration (mirrors SequencingRun config fields, excluding
    # identity / status / export / optimistic-lock fields).
    run_description: str = ""
    instrument_platform: InstrumentPlatform = InstrumentPlatform.NOVASEQ_X
    flowcell_type: str = ""
    reagent_cycles: int = 300
    run_cycles: Optional[RunCycles] = None
    barcode_mismatches_index1: int = 1
    barcode_mismatches_index2: int = 1
    adapter_behavior: str = "trim"
    create_fastq_for_index_reads: bool = False
    no_lane_splitting: bool = False
    analyses: list[Analysis] = field(default_factory=list)

    scaffold_samples: list[Sample] = field(default_factory=list)

    def __post_init__(self):
        # Invariants live in __setattr__ so direct attribute writes from
        # route handlers can't bypass them.
        pass

    def __setattr__(self, name, value):
        if name == "name" and isinstance(value, str):
            value = value.replace("\r", " ").replace("\n", " ")[:256]
        elif name in ("description", "run_description") and isinstance(value, str):
            value = value.replace("\r", " ").replace("\n", " ")[:4096]
        elif name == "reagent_cycles":
            value = max(1, value)
        elif name in ("barcode_mismatches_index1", "barcode_mismatches_index2"):
            value = max(0, min(3, value))
        elif name in ("created_by", "updated_by", "flowcell_type") and isinstance(value, str):
            value = value[:256]
        object.__setattr__(self, name, value)

    def touch(self, updated_by: str = "") -> None:
        self.updated_at = datetime.now()
        if updated_by:
            self.updated_by = updated_by

    def to_dict(self) -> dict:
        return {
            "_id": self.id,
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "created_by": self.created_by,
            "updated_by": self.updated_by,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "run_description": self.run_description,
            "instrument_platform": self.instrument_platform.value,
            "flowcell_type": self.flowcell_type,
            "reagent_cycles": self.reagent_cycles,
            "run_cycles": self.run_cycles.to_dict() if self.run_cycles else None,
            "barcode_mismatches_index1": self.barcode_mismatches_index1,
            "barcode_mismatches_index2": self.barcode_mismatches_index2,
            "adapter_behavior": self.adapter_behavior,
            "create_fastq_for_index_reads": self.create_fastq_for_index_reads,
            "no_lane_splitting": self.no_lane_splitting,
            "analyses": [a.to_dict() for a in self.analyses],
            "scaffold_samples": [s.to_dict() for s in self.scaffold_samples],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "RunTemplate":
        run_cycles = RunCycles.from_dict(data["run_cycles"]) if data.get("run_cycles") else None

        created_at = data.get("created_at")
        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at)
        elif created_at is None:
            created_at = datetime.now()
        updated_at = data.get("updated_at")
        if isinstance(updated_at, str):
            updated_at = datetime.fromisoformat(updated_at)
        elif updated_at is None:
            updated_at = datetime.now()

        raw_platform = data.get("instrument_platform", "NovaSeq X Series")
        try:
            platform = InstrumentPlatform(raw_platform)
        except ValueError:
            import logging
            logging.getLogger(__name__).warning(
                "Unknown InstrumentPlatform %r in stored template %r — falling back to NOVASEQ_X",
                raw_platform, data.get("_id") or data.get("id"),
            )
            platform = InstrumentPlatform.NOVASEQ_X

        return cls(
            id=data.get("_id") or data["id"],
            name=data.get("name", ""),
            description=data.get("description", ""),
            created_by=data.get("created_by", ""),
            updated_by=data.get("updated_by", ""),
            created_at=created_at,
            updated_at=updated_at,
            run_description=data.get("run_description", ""),
            instrument_platform=platform,
            flowcell_type=data.get("flowcell_type", ""),
            reagent_cycles=data.get("reagent_cycles", 300),
            run_cycles=run_cycles,
            barcode_mismatches_index1=data.get("barcode_mismatches_index1", 1),
            barcode_mismatches_index2=data.get("barcode_mismatches_index2", 1),
            adapter_behavior=data.get("adapter_behavior", "trim"),
            create_fastq_for_index_reads=data.get("create_fastq_for_index_reads", False),
            no_lane_splitting=data.get("no_lane_splitting", False),
            analyses=[Analysis.from_dict(a) for a in data.get("analyses", [])],
            scaffold_samples=[Sample.from_dict(s) for s in data.get("scaffold_samples", [])],
        )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pixi run test tests/unit/test_run_template_model.py -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add src/seqsetup/models/run_template.py tests/unit/test_run_template_model.py
git commit -m "feat(templates): add RunTemplate model"
```

---

## Task 2: `RunTemplateRepository` + DI wiring

**Files:**
- Create: `src/seqsetup/repositories/run_template_repo.py`
- Modify: `src/seqsetup/repositories/__init__.py`
- Modify: `src/seqsetup/context.py:46` (add field after `profile_sync_config_repo`)
- Modify: `src/seqsetup/startup.py:96` (registry) and `:177` (`get_app_context`)

- [ ] **Step 1: Write the repository**

Create `src/seqsetup/repositories/run_template_repo.py`:

```python
"""Repository for RunTemplate database operations."""

from ..models.run_template import RunTemplate
from .base import BaseRepository


class RunTemplateRepository(BaseRepository[RunTemplate]):
    """Thin data-access layer for run templates. No business logic."""

    COLLECTION = "run_templates"
    MODEL_CLASS = RunTemplate
```

- [ ] **Step 2: Export it from the package**

In `src/seqsetup/repositories/__init__.py`, add the import after the other repo imports and add `"RunTemplateRepository"` to `__all__`:

```python
from .run_template_repo import RunTemplateRepository
```

- [ ] **Step 3: Add the registry entry + getter in startup.py**

In `src/seqsetup/startup.py`, add `RunTemplateRepository` to the imports near the top (alongside the other repo imports), add it to `_REPO_REGISTRY` (around line 96):

```python
    "run_template": RunTemplateRepository,
```

and add a getter near the other getters:

```python
def get_run_template_repo() -> RunTemplateRepository:
    return _get_repo("run_template")
```

- [ ] **Step 4: Add the AppContext field**

In `src/seqsetup/context.py`, add the import and an optional field (default `None`) in the "Optional repositories" block:

```python
from .repositories.run_template_repo import RunTemplateRepository
```
```python
    run_template_repo: Optional[RunTemplateRepository] = None
```

- [ ] **Step 5: Wire it into get_app_context()**

In `src/seqsetup/startup.py` `get_app_context()` (around line 179), add:

```python
        run_template_repo=get_run_template_repo(),
```

- [ ] **Step 6: Verify the app still imports and tests pass**

Run: `pixi run test tests/unit/test_models.py -q`
Expected: PASS (no import errors from the wiring).

- [ ] **Step 7: Commit**

```bash
git add src/seqsetup/repositories/run_template_repo.py src/seqsetup/repositories/__init__.py src/seqsetup/context.py src/seqsetup/startup.py
git commit -m "feat(templates): add RunTemplateRepository and DI wiring"
```

---

## Task 3: `build_draft_run` service

This is the load-bearing logic: produces a fresh DRAFT run from a run **or** a template, enforcing every clinical-safety rule in the spec.

**Files:**
- Create: `src/seqsetup/services/run_builder.py`
- Test: `tests/unit/test_run_builder.py`

- [ ] **Step 1: Write the failing tests**

```python
"""Tests for build_draft_run — the shared clone/template instantiation path."""

import pytest

from seqsetup.models.analysis import Analysis, AnalysisType, DRAGENPipeline
from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import (
    InstrumentPlatform,
    RunCycles,
    RunStatus,
    SequencingRun,
    MAX_SAMPLES_PER_RUN,
)
from seqsetup.services.run_builder import build_draft_run, RunInstantiationError


def _pair(i7="ATTACTCG", i5="TATAGCCT", name="D701"):
    return IndexPair(
        id=f"kit_{name}",
        name=name,
        index1=Index(name=name, sequence=i7, index_type=IndexType.I7),
        index2=Index(name="D501", sequence=i5, index_type=IndexType.I5),
    )


def _source_run(samples=None, analyses=None):
    return SequencingRun(
        run_name="Source",
        run_description="src desc",
        status=RunStatus.READY,
        created_by="bob",
        updated_by="bob",
        instrument_platform=InstrumentPlatform.NOVASEQ_X,
        flowcell_type="10B",
        reagent_cycles=300,
        run_cycles=RunCycles(151, 151, 10, 10),
        no_lane_splitting=True,
        samples=samples or [],
        analyses=analyses or [],
        generated_samplesheet_v2="STALE",
        generated_json="STALE",
    )


class TestBuildDraftRunBasics:
    def test_result_is_fresh_draft_with_no_exports(self):
        src = _source_run(samples=[Sample(sample_id="S1", index_pair=_pair())])
        run = build_draft_run(
            config_source=src, samples=src.samples, created_by="alice",
            run_name="New", instrument_config=None,
        )
        assert run.status == RunStatus.DRAFT
        assert run.id != src.id
        assert run.created_by == "alice" and run.updated_by == "alice"
        assert run._loaded_updated_at is None
        assert run.generated_samplesheet_v2 is None
        assert run.generated_json is None
        assert run.run_name == "New"

    def test_config_copied_from_source(self):
        src = _source_run()
        run = build_draft_run(
            config_source=src, samples=[], created_by="alice",
            run_name="x", instrument_config=None,
        )
        assert run.instrument_platform == InstrumentPlatform.NOVASEQ_X
        assert run.flowcell_type == "10B"
        assert run.reagent_cycles == 300
        assert run.run_cycles.read1_cycles == 151
        assert run.no_lane_splitting is True
        assert run.run_description == "src desc"

    def test_samples_deep_copied_and_ids_preserved(self):
        s1 = Sample(sample_id="S1", index_pair=_pair())
        src = _source_run(samples=[s1])
        run = build_draft_run(
            config_source=src, samples=src.samples, created_by="alice",
            run_name="x", instrument_config=None,
        )
        assert len(run.samples) == 1
        assert run.samples[0] is not s1                  # independent object
        assert run.samples[0].id == s1.id                # identity preserved
        assert run.samples[0].sample_id == "S1"

    def test_config_only_passes_empty_samples(self):
        src = _source_run(samples=[Sample(sample_id="S1", index_pair=_pair())])
        run = build_draft_run(
            config_source=src, samples=[], created_by="alice",
            run_name="x", instrument_config=None,
        )
        assert run.samples == []


class TestSampleCountCap:
    def test_refuses_when_included_samples_exceed_cap(self, monkeypatch):
        monkeypatch.setattr("seqsetup.services.run_builder.MAX_SAMPLES_PER_RUN", 2)
        src = _source_run()
        too_many = [Sample(sample_id=f"S{i}", index_pair=_pair()) for i in range(3)]
        with pytest.raises(RunInstantiationError, match="maximum"):
            build_draft_run(
                config_source=src, samples=too_many, created_by="alice",
                run_name="x", instrument_config=None,
            )


class TestAnalysesFiltering:
    def test_config_only_clone_drops_all_analyses(self):
        analyses = [Analysis(
            name="g", analysis_type=AnalysisType.DRAGEN_ONBOARD,
            dragen_pipeline=DRAGENPipeline.GERMLINE, sample_ids=["S1"],
        )]
        src = _source_run(
            samples=[Sample(sample_id="S1", index_pair=_pair())], analyses=analyses,
        )
        run = build_draft_run(
            config_source=src, samples=[], created_by="alice",
            run_name="x", instrument_config=None,
        )
        assert run.analyses == []

    def test_include_samples_keeps_analyses_filtered_to_included(self):
        analyses = [Analysis(
            name="g", analysis_type=AnalysisType.DRAGEN_ONBOARD,
            dragen_pipeline=DRAGENPipeline.GERMLINE, sample_ids=["S1", "S2"],
        )]
        s1 = Sample(sample_id="S1", index_pair=_pair())
        src = _source_run(samples=[s1], analyses=analyses)
        # Only S1 is included; the analysis referenced S1 and S2.
        run = build_draft_run(
            config_source=src, samples=[s1], created_by="alice",
            run_name="x", instrument_config=None,
        )
        assert len(run.analyses) == 1
        assert run.analyses[0].sample_ids == ["S1"]
        assert run.analyses[0] is not analyses[0]        # deep-copied

    def test_analysis_with_no_surviving_samples_is_dropped(self):
        analyses = [Analysis(
            name="g", analysis_type=AnalysisType.DRAGEN_ONBOARD,
            dragen_pipeline=DRAGENPipeline.GERMLINE, sample_ids=["OTHER"],
        )]
        s1 = Sample(sample_id="S1", index_pair=_pair())
        src = _source_run(samples=[s1], analyses=analyses)
        run = build_draft_run(
            config_source=src, samples=[s1], created_by="alice",
            run_name="x", instrument_config=None,
        )
        assert run.analyses == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pixi run test tests/unit/test_run_builder.py -v`
Expected: FAIL — `ModuleNotFoundError: seqsetup.services.run_builder`.

- [ ] **Step 3: Write the implementation**

Create `src/seqsetup/services/run_builder.py`. The reference-integrity check (used by the route layer, exercised in Task 6) uses the existing instrument data helpers. `config_source` is duck-typed: both `SequencingRun` and `RunTemplate` expose the same config attribute names.

```python
"""Shared instantiation path for clone-run and create-from-template.

build_draft_run() is the single place that turns a config source (an existing
SequencingRun or a RunTemplate) plus a sample list into a FRESH DRAFT run,
enforcing every clinical-safety invariant in the spec:

  * always DRAFT, never inherits status/exports;
  * fresh run id, _loaded_updated_at=None (insert);
  * samples deep-copied via Sample round-trip, identity preserved;
  * sample-count cap enforced (the copy path bypasses add_sample);
  * analyses filtered to included samples, empty analyses dropped;
  * optional reference-integrity check refuses withdrawn
    instrument/flowcell/reagent-kit.
"""

from ..data.instruments import (
    get_flowcells_for_instrument,
    get_reagent_kits_for_flowcell,
)
from ..models.analysis import Analysis
from ..models.sample import Sample
from ..models.sequencing_run import (
    MAX_SAMPLES_PER_RUN,
    RunCycles,
    RunStatus,
    SequencingRun,
)


class RunInstantiationError(ValueError):
    """Raised when a run cannot be instantiated from a source/template.

    The route layer translates this into an HTTP 400 with the message shown
    to the user. Covers: too many samples, and (when a reference check is
    requested) a withdrawn instrument / flowcell / reagent kit.
    """


def assert_references_available(config_source, instrument_config) -> None:
    """Refuse if the source/template points at config no longer offered.

    Validates against the CURRENT enabled instrument configuration:
      * instrument definition still exists (non-empty flowcell set),
      * flowcell_type still offered,
      * reagent_cycles still offered for that flowcell.

    A missing index kit is intentionally NOT checked here — copied samples
    carry authoritative embedded index sequences; kit name is metadata only.
    """
    platform = config_source.instrument_platform
    flowcells = get_flowcells_for_instrument(platform, instrument_config)
    if not flowcells:
        raise RunInstantiationError(
            f"Instrument '{platform.value}' is no longer available; "
            "this template/run cannot be instantiated."
        )
    if config_source.flowcell_type not in flowcells:
        raise RunInstantiationError(
            f"Flowcell '{config_source.flowcell_type}' is no longer offered for "
            f"'{platform.value}'; this template/run cannot be instantiated."
        )
    reagent_kits = get_reagent_kits_for_flowcell(
        platform, config_source.flowcell_type, instrument_config
    )
    if reagent_kits and config_source.reagent_cycles not in reagent_kits:
        raise RunInstantiationError(
            f"Reagent kit '{config_source.reagent_cycles}' cycles is no longer "
            f"offered for '{platform.value}' / '{config_source.flowcell_type}'; "
            "this template/run cannot be instantiated."
        )


def _copy_samples(samples) -> list:
    """Deep-copy via Sample round-trip; identity (id, sample_id) preserved."""
    return [Sample.from_dict(s.to_dict()) for s in samples]


def _filter_analyses(analyses, included_sample_ids: set) -> list:
    """Deep-copy each analysis, restrict sample_ids to included samples,
    drop analyses with no surviving samples.

    Analysis.sample_ids holds the clinical Sample.sample_id (not the uuid).
    """
    result = []
    for a in analyses:
        kept = [sid for sid in a.sample_ids if sid in included_sample_ids]
        if not kept:
            continue
        copied = Analysis.from_dict(a.to_dict())
        copied.sample_ids = kept
        result.append(copied)
    return result


def build_draft_run(
    *,
    config_source,
    samples,
    created_by: str,
    run_name: str,
    instrument_config=None,
    check_references: bool = False,
) -> SequencingRun:
    """Build a fresh DRAFT SequencingRun from a run or template.

    Args:
        config_source: a SequencingRun (clone) or RunTemplate (template).
        samples: the samples to include (already chosen by the caller —
            e.g. [] for config-only clone, source.samples for full clone,
            template.scaffold_samples for create-from-template).
        created_by: actor username (becomes created_by and updated_by).
        run_name: name for the new run.
        instrument_config: current instrument config (for reference check).
        check_references: when True, refuse withdrawn instrument/flowcell/
            reagent kit before building.

    Raises:
        RunInstantiationError: too many samples, or (if check_references)
            an unavailable instrument/flowcell/reagent kit.
    """
    if check_references:
        assert_references_available(config_source, instrument_config)

    if len(samples) > MAX_SAMPLES_PER_RUN:
        raise RunInstantiationError(
            f"Cannot instantiate a run with {len(samples)} samples; the maximum "
            f"is {MAX_SAMPLES_PER_RUN}. Split the work across runs."
        )

    copied_samples = _copy_samples(samples)
    included_ids = {s.sample_id for s in copied_samples}
    copied_analyses = _filter_analyses(config_source.analyses, included_ids)

    run_cycles = (
        RunCycles.from_dict(config_source.run_cycles.to_dict())
        if config_source.run_cycles else None
    )

    return SequencingRun(
        run_name=run_name,
        run_description=config_source.run_description,
        status=RunStatus.DRAFT,
        created_by=created_by,
        updated_by=created_by,
        instrument_platform=config_source.instrument_platform,
        flowcell_type=config_source.flowcell_type,
        reagent_cycles=config_source.reagent_cycles,
        run_cycles=run_cycles,
        barcode_mismatches_index1=config_source.barcode_mismatches_index1,
        barcode_mismatches_index2=config_source.barcode_mismatches_index2,
        adapter_behavior=config_source.adapter_behavior,
        create_fastq_for_index_reads=config_source.create_fastq_for_index_reads,
        no_lane_splitting=config_source.no_lane_splitting,
        samples=copied_samples,
        analyses=copied_analyses,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pixi run test tests/unit/test_run_builder.py -v`
Expected: PASS (all tests in the three classes).

- [ ] **Step 5: Commit**

```bash
git add src/seqsetup/services/run_builder.py tests/unit/test_run_builder.py
git commit -m "feat(templates): add build_draft_run instantiation service"
```

---

## Task 4: Clone route + router registration

**Files:**
- Create: `src/seqsetup/routes/run_templates.py`
- Modify: `src/seqsetup/app.py:33` (import) and `:157` area (include_router)
- Test: `tests/integration/test_run_templates_routes.py`

- [ ] **Step 1: Write the failing tests**

```python
"""Integration tests for clone + template routes."""

import json

from seqsetup.models.sequencing_run import RunStatus


def _origin() -> dict:
    return {"Origin": "http://testserver"}


def _create_run(client) -> str:
    r = client.post("/runs/new", follow_redirects=False, headers=_origin())
    assert r.status_code == 303, r.text[:300]
    return r.headers["location"].split("run_id=", 1)[1].split("&", 1)[0]


def _add_sample(client, run_id, sample_id="S1"):
    r = client.post(
        f"/runs/{run_id}/samples", data={"sample_id": sample_id}, headers=_origin()
    )
    assert r.status_code == 200


class TestCloneRun:
    def test_duplicate_config_only_creates_draft_without_samples(
        self, logged_in_client, fresh_app
    ):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        _add_sample(logged_in_client, run_id, "S1")
        before = len(ctx.run_repo.list_all())

        r = logged_in_client.post(
            f"/runs/{run_id}/duplicate",
            data={"include_samples": "false"},
            headers=_origin(),
            follow_redirects=False,
        )
        assert r.status_code == 303
        new_id = r.headers["location"].rsplit("/", 1)[1]
        assert len(ctx.run_repo.list_all()) == before + 1

        new_run = ctx.run_repo.get_by_id(new_id)
        assert new_run.status == RunStatus.DRAFT
        assert new_run.samples == []
        assert new_run.generated_samplesheet_v2 is None

    def test_duplicate_include_samples_copies_samples(
        self, logged_in_client, fresh_app
    ):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        _add_sample(logged_in_client, run_id, "S1")

        r = logged_in_client.post(
            f"/runs/{run_id}/duplicate",
            data={"include_samples": "true"},
            headers=_origin(),
            follow_redirects=False,
        )
        assert r.status_code == 303
        new_id = r.headers["location"].rsplit("/", 1)[1]
        new_run = ctx.run_repo.get_by_id(new_id)
        assert [s.sample_id for s in new_run.samples] == ["S1"]

    def test_duplicate_does_not_mutate_source(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        _add_sample(logged_in_client, run_id, "S1")
        logged_in_client.post(
            f"/runs/{run_id}/duplicate",
            data={"include_samples": "true"}, headers=_origin(),
            follow_redirects=False,
        )
        src = ctx.run_repo.get_by_id(run_id)
        assert len(src.samples) == 1
        assert src.status == RunStatus.DRAFT

    def test_duplicate_missing_run_404(self, logged_in_client):
        r = logged_in_client.post(
            "/runs/does-not-exist/duplicate",
            data={"include_samples": "false"}, headers=_origin(),
            follow_redirects=False,
        )
        assert r.status_code == 404
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pixi run test tests/integration/test_run_templates_routes.py::TestCloneRun -v`
Expected: FAIL — 404 on `/runs/{id}/duplicate` (route not registered).

- [ ] **Step 3: Create the routes module with the clone handler**

Create `src/seqsetup/routes/run_templates.py`:

```python
"""Clone-run and run-template routes.

Clone and create-from-template both delegate to services.run_builder.
build_draft_run; templates are managed via a thin CRUD over
ctx.run_template_repo and live entirely outside the run state machine.
"""

from fastapi import APIRouter, Depends, Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from ..context import AppContext
from ..models.run_template import RunTemplate
from ..services.audit_log import audit
from ..services.run_builder import build_draft_run, RunInstantiationError
from ..templating import render
from .dependencies import get_archivable_run, get_ctx
from .utils import get_username, sanitize_string


router = APIRouter(tags=["run-templates"])


def _bool_field(form, key: str) -> bool:
    raw = form.get(key)
    if raw is None:
        return False
    return str(raw).lower() in ("1", "true", "on", "yes")


@router.post("/runs/{run_id}/duplicate")
async def duplicate_run(
    request: Request,
    run=Depends(get_archivable_run),   # loads any run, 404 if missing; read-only
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /runs/{run_id}/duplicate — clone a run into a fresh DRAFT.

    include_samples=true performs a full duplicate (re-run); false copies
    config only (new batch). The source is read, never mutated.
    """
    form = await request.form()
    include_samples = _bool_field(form, "include_samples")
    requested_name = sanitize_string(form.get("run_name", ""), 256)
    new_name = requested_name or f"{run.run_name} (copy)"

    samples = run.samples if include_samples else []
    try:
        new_run = build_draft_run(
            config_source=run,
            samples=samples,
            created_by=get_username(request),
            run_name=new_name,
            instrument_config=ctx.instrument_config,
            check_references=False,   # cloning preserves whatever the source had
        )
    except RunInstantiationError as exc:
        return Response(str(exc), status_code=400)

    ctx.run_repo.save(new_run)
    audit(
        "run.cloned",
        actor=get_username(request),
        target=new_run.id,
        source=run.id,
        included_samples=include_samples,
    )
    return RedirectResponse(f"/runs/{new_run.id}", status_code=303)
```

- [ ] **Step 4: Register the router in app.py**

In `src/seqsetup/app.py`, add `run_templates` to the routes import on line 33:

```python
from .routes import api_tokens, auth, dashboard, export, indexes, local_users, main, profiles, run_templates, runs, samples, validation, wizard
```

and add the include near the other run-related routers (after `app.include_router(runs.router)` ~line 162):

```python
app.include_router(run_templates.router)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pixi run test tests/integration/test_run_templates_routes.py::TestCloneRun -v`
Expected: PASS (4 tests).

- [ ] **Step 6: Commit**

```bash
git add src/seqsetup/routes/run_templates.py src/seqsetup/app.py tests/integration/test_run_templates_routes.py
git commit -m "feat(templates): add clone-run route"
```

---

## Task 5: Save-as-template + template CRUD routes

**Files:**
- Modify: `src/seqsetup/routes/run_templates.py`
- Create: `src/seqsetup/templates/run_templates/list.html`
- Test: `tests/integration/test_run_templates_routes.py` (add classes)

- [ ] **Step 1: Write the failing tests**

Append to `tests/integration/test_run_templates_routes.py`:

```python
class TestSaveAsTemplate:
    def test_save_as_template_captures_config_and_selected_samples(
        self, logged_in_client, fresh_app
    ):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        _add_sample(logged_in_client, run_id, "CTRL_POS")
        run = ctx.run_repo.get_by_id(run_id)
        scaffold_uuid = run.samples[0].id

        r = logged_in_client.post(
            f"/runs/{run_id}/save-as-template",
            data={
                "name": "WGS Standard",
                "description": "std",
                "scaffold_sample_ids": json.dumps([scaffold_uuid]),
            },
            headers=_origin(),
            follow_redirects=False,
        )
        assert r.status_code == 303
        templates = ctx.run_template_repo.list_all()
        assert len(templates) == 1
        t = templates[0]
        assert t.name == "WGS Standard"
        assert t.flowcell_type == run.flowcell_type
        assert [s.sample_id for s in t.scaffold_samples] == ["CTRL_POS"]

    def test_save_as_template_with_no_scaffold_is_config_only(
        self, logged_in_client, fresh_app
    ):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        _add_sample(logged_in_client, run_id, "S1")
        r = logged_in_client.post(
            f"/runs/{run_id}/save-as-template",
            data={"name": "Config Only", "description": "", "scaffold_sample_ids": "[]"},
            headers=_origin(), follow_redirects=False,
        )
        assert r.status_code == 303
        t = ctx.run_template_repo.list_all()[0]
        assert t.scaffold_samples == []

    def test_save_as_template_requires_name(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        r = logged_in_client.post(
            f"/runs/{run_id}/save-as-template",
            data={"name": "  ", "description": "", "scaffold_sample_ids": "[]"},
            headers=_origin(), follow_redirects=False,
        )
        assert r.status_code == 400
        assert ctx.run_template_repo.list_all() == []

    def test_save_as_template_is_create_only(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        for _ in range(2):
            logged_in_client.post(
                f"/runs/{run_id}/save-as-template",
                data={"name": "Dup", "description": "", "scaffold_sample_ids": "[]"},
                headers=_origin(), follow_redirects=False,
            )
        # Two saves with the same name -> two distinct templates.
        assert len(ctx.run_template_repo.list_all()) == 2


class TestTemplateCrud:
    def _make_template(self, logged_in_client, ctx) -> str:
        run_id = _create_run(logged_in_client)
        logged_in_client.post(
            f"/runs/{run_id}/save-as-template",
            data={"name": "Orig", "description": "d", "scaffold_sample_ids": "[]"},
            headers=_origin(), follow_redirects=False,
        )
        return ctx.run_template_repo.list_all()[0].id

    def test_list_page_renders_template(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        self._make_template(logged_in_client, ctx)
        r = logged_in_client.get("/templates")
        assert r.status_code == 200
        assert "Orig" in r.text

    def test_edit_updates_name_description_and_touches(
        self, logged_in_client, fresh_app
    ):
        _app, ctx, _db = fresh_app
        tid = self._make_template(logged_in_client, ctx)
        before = ctx.run_template_repo.get_by_id(tid).updated_at
        r = logged_in_client.post(
            f"/templates/{tid}",
            data={"name": "Renamed", "description": "new"},
            headers=_origin(), follow_redirects=False,
        )
        assert r.status_code == 303
        t = ctx.run_template_repo.get_by_id(tid)
        assert t.name == "Renamed"
        assert t.description == "new"
        assert t.updated_at >= before
        assert t.updated_by  # actor recorded

    def test_delete_removes_template(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        tid = self._make_template(logged_in_client, ctx)
        r = logged_in_client.delete(f"/templates/{tid}", headers=_origin())
        assert r.status_code in (200, 204)
        assert ctx.run_template_repo.get_by_id(tid) is None

    def test_template_never_appears_in_run_repo(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        self._make_template(logged_in_client, ctx)
        # The save-as-template flow created exactly one run (the source);
        # the template is NOT a run.
        assert len(ctx.run_repo.list_all()) == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pixi run test tests/integration/test_run_templates_routes.py::TestSaveAsTemplate tests/integration/test_run_templates_routes.py::TestTemplateCrud -v`
Expected: FAIL — routes return 404 / 405.

- [ ] **Step 3: Add the handlers to `routes/run_templates.py`**

Add the imports `json` and `from .dependencies import get_editable_run` is NOT needed (save-as-template only reads the run). Append:

```python
import json


def _config_from_run(run, name: str, description: str, scaffold_samples) -> RunTemplate:
    """Build a RunTemplate capturing a run's config + chosen scaffold samples."""
    from ..models.sample import Sample
    return RunTemplate(
        name=name,
        description=description,
        run_description=run.run_description,
        instrument_platform=run.instrument_platform,
        flowcell_type=run.flowcell_type,
        reagent_cycles=run.reagent_cycles,
        run_cycles=run.run_cycles,
        barcode_mismatches_index1=run.barcode_mismatches_index1,
        barcode_mismatches_index2=run.barcode_mismatches_index2,
        adapter_behavior=run.adapter_behavior,
        create_fastq_for_index_reads=run.create_fastq_for_index_reads,
        no_lane_splitting=run.no_lane_splitting,
        analyses=[a.__class__.from_dict(a.to_dict()) for a in run.analyses],
        scaffold_samples=[Sample.from_dict(s.to_dict()) for s in scaffold_samples],
    )


@router.post("/runs/{run_id}/save-as-template")
async def save_as_template(
    request: Request,
    run=Depends(get_archivable_run),   # read the run; any status may be templated
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /runs/{run_id}/save-as-template — create-only; mints a new template."""
    form = await request.form()
    name = sanitize_string(form.get("name", ""), 256)
    if not name:
        return Response("Template name is required", status_code=400)
    description = sanitize_string(form.get("description", ""), 4096)

    try:
        wanted_ids = set(json.loads(form.get("scaffold_sample_ids", "[]")))
    except (ValueError, TypeError):
        return Response("Invalid scaffold_sample_ids", status_code=400)
    scaffold = [s for s in run.samples if s.id in wanted_ids]

    template = _config_from_run(run, name, description, scaffold)
    template.created_by = get_username(request)
    template.updated_by = get_username(request)
    ctx.run_template_repo.save(template)
    audit(
        "template.created",
        actor=get_username(request),
        target=template.id,
        source_run=run.id,
        scaffold_count=len(scaffold),
    )
    return RedirectResponse("/templates", status_code=303)


@router.get("/templates", response_class=HTMLResponse)
def list_templates(request: Request, ctx: AppContext = Depends(get_ctx)) -> Response:
    """GET /templates — org-wide template library."""
    templates = sorted(
        ctx.run_template_repo.list_all(),
        key=lambda t: t.updated_at, reverse=True,
    )
    return render(request, "run_templates/list.html", {"templates": templates})


@router.post("/templates/{template_id}")
async def update_template(
    template_id: str, request: Request, ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /templates/{id} — edit name/description only."""
    template = ctx.run_template_repo.get_by_id(template_id)
    if template is None:
        return Response("Template not found", status_code=404)
    form = await request.form()
    name = sanitize_string(form.get("name", ""), 256)
    if not name:
        return Response("Template name is required", status_code=400)
    template.name = name
    template.description = sanitize_string(form.get("description", ""), 4096)
    template.touch(updated_by=get_username(request))
    ctx.run_template_repo.save(template)
    audit("template.updated", actor=get_username(request), target=template.id)
    return RedirectResponse("/templates", status_code=303)


@router.delete("/templates/{template_id}")
def delete_template(
    template_id: str, request: Request, ctx: AppContext = Depends(get_ctx),
) -> Response:
    """DELETE /templates/{id}."""
    if ctx.run_template_repo.get_by_id(template_id) is None:
        return Response("Template not found", status_code=404)
    ctx.run_template_repo.delete(template_id)
    audit("template.deleted", actor=get_username(request), target=template_id)
    return Response("", status_code=200)
```

- [ ] **Step 4: Create the list template**

Create `src/seqsetup/templates/run_templates/list.html`. Mirror the existing app shell usage (extend `_app_shell.html` as the other top-level pages do — check `dashboard.html`'s `{% extends %}` line and copy it). Minimal content:

```html
{% extends "_app_shell.html" %}
{% block content %}
<div class="max-w-5xl mx-auto p-4">
  <h1 class="text-xl font-semibold mb-4">Run Templates</h1>
  {% if not templates %}
    <p class="text-slate-500">No templates yet. Open a run and choose “Save as template”.</p>
  {% else %}
    <div class="border rounded">
      {% for t in templates %}
      <div class="grid grid-cols-[2fr_1fr_1fr_1fr_1.2fr] gap-2 items-center px-3 py-2 border-t text-sm"
           id="template-item-{{ t.id }}">
        <span class="font-medium truncate">{{ t.name }}</span>
        <span class="text-slate-500 truncate">{{ t.instrument_platform.value }}</span>
        <span class="text-slate-500">{{ t.scaffold_samples|length }} scaffold</span>
        <span class="text-slate-500 truncate">{{ t.updated_by }}</span>
        <span class="flex gap-2 justify-end">
          <form method="post" action="/runs/new/from-template/{{ t.id }}">
            <button class="bg-primary text-white rounded px-2 py-1 text-xs">New run</button>
          </form>
          <button class="bg-slate-200 hover:bg-red-200 rounded px-2 py-1 text-xs"
                  hx-delete="/templates/{{ t.id }}"
                  hx-target="#template-item-{{ t.id }}"
                  hx-swap="outerHTML"
                  hx-confirm="Delete template “{{ t.name }}”?">Delete</button>
        </span>
      </div>
      {% endfor %}
    </div>
  {% endif %}
</div>
{% endblock %}
```

> Verify the `{% extends %}` target and `{% block %}` name against `dashboard.html` — if the shell block is named differently (e.g. `dashboard_content` vs `content`), match the convention used by other full pages. The "New run" form posts to the route built in Task 6.

- [ ] **Step 5: Run tests to verify they pass**

Run: `pixi run test tests/integration/test_run_templates_routes.py::TestSaveAsTemplate tests/integration/test_run_templates_routes.py::TestTemplateCrud -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/seqsetup/routes/run_templates.py src/seqsetup/templates/run_templates/list.html tests/integration/test_run_templates_routes.py
git commit -m "feat(templates): add save-as-template and template CRUD"
```

---

## Task 6: Create-from-template route + reference-integrity refusal

**Files:**
- Modify: `src/seqsetup/routes/run_templates.py`
- Test: `tests/integration/test_run_templates_routes.py` (add class)

- [ ] **Step 1: Write the failing tests**

```python
class TestCreateFromTemplate:
    def _make_template_with_scaffold(self, logged_in_client, ctx) -> str:
        run_id = _create_run(logged_in_client)
        _add_sample(logged_in_client, run_id, "CTRL_POS")
        run = ctx.run_repo.get_by_id(run_id)
        sid = run.samples[0].id
        logged_in_client.post(
            f"/runs/{run_id}/save-as-template",
            data={"name": "WithCtrl", "description": "",
                  "scaffold_sample_ids": json.dumps([sid])},
            headers=_origin(), follow_redirects=False,
        )
        return ctx.run_template_repo.list_all()[0].id

    def test_from_template_creates_draft_with_scaffold(
        self, logged_in_client, fresh_app
    ):
        _app, ctx, _db = fresh_app
        tid = self._make_template_with_scaffold(logged_in_client, ctx)
        r = logged_in_client.post(
            f"/runs/new/from-template/{tid}",
            headers=_origin(), follow_redirects=False,
        )
        assert r.status_code == 303
        new_id = r.headers["location"].rsplit("/", 1)[1]
        new_run = ctx.run_repo.get_by_id(new_id)
        assert new_run.status == RunStatus.DRAFT
        assert [s.sample_id for s in new_run.samples] == ["CTRL_POS"]
        assert new_run.generated_samplesheet_v2 is None

    def test_from_template_refuses_withdrawn_flowcell(
        self, logged_in_client, fresh_app, monkeypatch
    ):
        _app, ctx, _db = fresh_app
        tid = self._make_template_with_scaffold(logged_in_client, ctx)
        # Simulate the flowcell no longer being offered.
        monkeypatch.setattr(
            "seqsetup.services.run_builder.get_flowcells_for_instrument",
            lambda platform, cfg=None: {},
        )
        r = logged_in_client.post(
            f"/runs/new/from-template/{tid}",
            headers=_origin(), follow_redirects=False,
        )
        assert r.status_code == 400
        assert "no longer available" in r.text.lower()

    def test_from_template_missing_template_404(self, logged_in_client):
        r = logged_in_client.post(
            "/runs/new/from-template/nope",
            headers=_origin(), follow_redirects=False,
        )
        assert r.status_code == 404
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pixi run test tests/integration/test_run_templates_routes.py::TestCreateFromTemplate -v`
Expected: FAIL — route not found (404 on all, including the refusal test which expects 400).

- [ ] **Step 3: Add the handler to `routes/run_templates.py`**

```python
@router.post("/runs/new/from-template/{template_id}")
def new_run_from_template(
    template_id: str, request: Request, ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /runs/new/from-template/{id} — instantiate a draft from a template."""
    template = ctx.run_template_repo.get_by_id(template_id)
    if template is None:
        return Response("Template not found", status_code=404)

    try:
        new_run = build_draft_run(
            config_source=template,
            samples=template.scaffold_samples,
            created_by=get_username(request),
            run_name=template.name,
            instrument_config=ctx.instrument_config,
            check_references=True,   # template config may have gone stale
        )
    except RunInstantiationError as exc:
        return Response(str(exc), status_code=400)

    ctx.run_repo.save(new_run)
    audit(
        "run.created_from_template",
        actor=get_username(request),
        target=new_run.id,
        template=template_id,
    )
    return RedirectResponse(f"/runs/{new_run.id}", status_code=303)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pixi run test tests/integration/test_run_templates_routes.py::TestCreateFromTemplate -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Run the full new test file**

Run: `pixi run test tests/integration/test_run_templates_routes.py -v`
Expected: PASS (all classes).

- [ ] **Step 6: Commit**

```bash
git add src/seqsetup/routes/run_templates.py tests/integration/test_run_templates_routes.py
git commit -m "feat(templates): add create-from-template with reference-integrity refusal"
```

---

## Task 7: UI hooks — dashboard Duplicate + run-edit Save-as-template

These wire the existing pages to the new routes. Cover with light smoke assertions (the behavior is already covered by Tasks 4–6).

**Files:**
- Modify: `src/seqsetup/templates/dashboard.html` (around the per-run actions, lines 80–91)
- Modify: `src/seqsetup/templates/runs/edit.html`
- Test: `tests/integration/test_run_templates_routes.py` (add a smoke class)

- [ ] **Step 1: Write the failing smoke tests**

```python
class TestUiHooks:
    def test_dashboard_shows_duplicate_action(self, logged_in_client, fresh_app):
        run_id = _create_run(logged_in_client)
        r = logged_in_client.get("/")
        assert r.status_code == 200
        assert f"/runs/{run_id}/duplicate" in r.text

    def test_edit_page_shows_save_as_template(self, logged_in_client, fresh_app):
        run_id = _create_run(logged_in_client)
        r = logged_in_client.get(f"/runs/{run_id}")
        assert r.status_code == 200
        assert "save-as-template" in r.text
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pixi run test tests/integration/test_run_templates_routes.py::TestUiHooks -v`
Expected: FAIL — strings not present.

- [ ] **Step 3: Add the Duplicate action to dashboard.html**

In `src/seqsetup/templates/dashboard.html`, inside the per-run actions cell (next to the existing Edit/Archive controls near line 81), add a Duplicate form. Keep it CSP-compliant (no inline `on*` handlers; this is a plain POST form, which is fine):

```html
<form method="post" action="/runs/{{ run.id }}/duplicate" class="inline-block">
  <input type="hidden" name="include_samples" value="false">
  <button type="submit"
          class="inline-block bg-slate-200 hover:bg-slate-300 text-slate-800 rounded px-2 py-1 text-xs">
    Duplicate
  </button>
</form>
```

> The include-samples choice is a follow-on refinement; the spec wants a checkbox dialog, but the route already accepts `include_samples`. For this task ship the config-only default action (matches the most common "new batch" use). A checkbox/confirm dialog can be layered later without route changes.

- [ ] **Step 4: Add Save-as-template control to the run edit page**

In `src/seqsetup/templates/runs/edit.html`, add a small form posting to the save-as-template route. Place it near the export panel / run header. Use a minimal inline form (name + optional description); scaffold selection defaults to none for this first cut:

```html
<form method="post" action="/runs/{{ run.id }}/save-as-template" class="flex gap-2 items-center">
  <input type="text" name="name" placeholder="Template name"
         class="border rounded px-2 py-1 text-sm" required maxlength="256">
  <input type="hidden" name="scaffold_sample_ids" value="[]">
  <button type="submit"
          class="bg-slate-200 hover:bg-slate-300 text-slate-800 rounded px-2 py-1 text-sm">
    Save as template
  </button>
</form>
```

> Scaffold-sample selection from the edit page (checkboxes feeding `scaffold_sample_ids`) is a follow-on; the route fully supports it and `TestSaveAsTemplate` already covers the populated path.

- [ ] **Step 5: Run tests to verify they pass**

Run: `pixi run test tests/integration/test_run_templates_routes.py::TestUiHooks -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/seqsetup/templates/dashboard.html src/seqsetup/templates/runs/edit.html tests/integration/test_run_templates_routes.py
git commit -m "feat(templates): wire dashboard Duplicate and run-edit Save-as-template"
```

---

## Task 8: Full suite + safety-boundary regression

**Files:**
- Test: `tests/integration/test_run_templates_routes.py` (add final class)

- [ ] **Step 1: Write the boundary tests**

```python
class TestSafetyBoundaries:
    def test_malicious_scaffold_index_rejected_at_model_layer(
        self, logged_in_client, fresh_app
    ):
        """A non-ACGTN index sequence cannot survive into a template's
        scaffold sample — Sample construction validates DNA."""
        _app, ctx, _db = fresh_app
        from seqsetup.models.run_template import RunTemplate
        bad_dict = {
            "name": "evil",
            "instrument_platform": "NovaSeq X Series",
            "scaffold_samples": [{
                "id": "x", "sample_id": "S1",
                "index1": {"name": "i", "sequence": "ZZZZ", "index_type": "i7"},
            }],
        }
        t = RunTemplate.from_dict(bad_dict)
        # Sample model validation uppercases + strips non-ACGTN; the stored
        # sequence must not contain Z.
        seq = t.scaffold_samples[0].index1.sequence if t.scaffold_samples[0].index1 else ""
        assert "Z" not in seq

    def test_clone_of_archived_run_does_not_resurrect_status(
        self, logged_in_client, fresh_app
    ):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        run = ctx.run_repo.get_by_id(run_id)
        run.status = RunStatus.ARCHIVED
        run.generated_samplesheet_v2 = "snapshot"
        ctx.run_repo.save(run)
        r = logged_in_client.post(
            f"/runs/{run_id}/duplicate",
            data={"include_samples": "true"}, headers=_origin(),
            follow_redirects=False,
        )
        assert r.status_code == 303
        new_id = r.headers["location"].rsplit("/", 1)[1]
        new_run = ctx.run_repo.get_by_id(new_id)
        assert new_run.status == RunStatus.DRAFT
        assert new_run.generated_samplesheet_v2 is None
```

> If `Sample.from_dict` for a malformed index dict raises rather than sanitises, adapt the first test to assert the `ValueError`/`pytest.raises` instead — inspect `models/sample.py` index handling and match its actual contract. The point is: invalid index data must not silently become a valid-looking template.

- [ ] **Step 2: Run the tests**

Run: `pixi run test tests/integration/test_run_templates_routes.py::TestSafetyBoundaries -v`
Expected: PASS (adjust the first test to the model's real contract if needed).

- [ ] **Step 3: Run the entire suite**

Run: `pixi run test`
Expected: PASS — all pre-existing tests plus the new model/builder/route tests. Investigate any failure before continuing.

- [ ] **Step 4: Commit**

```bash
git add tests/integration/test_run_templates_routes.py
git commit -m "test(templates): add safety-boundary regression tests"
```

---

## Self-Review Notes (for the implementer)

- **Spec coverage:** model (T1), repo+DI (T2), `build_draft_run` with cap/analyses-filter/ref-integrity/no-exports/DRAFT (T3), clone with include-samples choice (T4), save-as-template create-only + CRUD + edit audit (T5), create-from-template + reagent/flowcell/instrument refusal (T6), UI hooks (T7), safety boundaries (T8). The spec's "stale scaffold control index" risk is covered by relying on existing run validation — no new code, so no task; note it in the PR description.
- **Deferred (explicit, per spec):** include-samples checkbox dialog and edit-page scaffold-sample checkboxes are shipped as their simplest correct form (config-only Duplicate; empty scaffold Save-as-template) with the routes already supporting the richer path. Do not silently expand scope.
- **Type consistency:** `build_draft_run(config_source, samples, created_by, run_name, instrument_config, check_references)` is called identically in clone (T4, `check_references=False`) and from-template (T6, `check_references=True`). `RunInstantiationError` is the single error type both routes translate to 400. `RunTemplate` exposes the same config attribute names as `SequencingRun`, which is what lets `build_draft_run` read either via duck typing.
- **Watch points:** confirm `Sample.to_dict()` includes `"id"` (preserved-identity tests depend on it); confirm `_app_shell.html` block name when writing `list.html`; confirm `runs/edit.html` has a sensible insertion point for the Save-as-template form.

---

## Execution Handoff

Choose execution approach (subagent-driven recommended).
