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
    # An empty reagent_kits list means the flowcell declares no kit
    # constraints (e.g. a custom-configured instrument); treat as
    # unrestricted and skip the check.
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
