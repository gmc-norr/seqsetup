"""Validation service orchestrator for sequencing runs.

This module provides the main ValidationService that orchestrates
all validation checks. Individual validation logic is delegated to
specialized validator modules:

- index_collision_validator: Index collision detection and distance matrices
- color_analysis_validator: Dark cycle and color balance analysis
- application_profile_validator: Application profile compatibility checks
"""

import logging
import re
from collections import OrderedDict, defaultdict
from threading import Lock

from ..data.instruments import (
    get_channel_config,
    get_chemistry_type,
    get_i5_read_orientation,
    get_lanes_for_flowcell,
    is_color_balance_enabled,
)
from ..models.sequencing_run import SequencingRun
from ..models.validation import (
    ConfigurationError,
    ValidationResult,
    ValidationSeverity,
)
from .application_profile_validator import ApplicationProfileValidator
from .color_analysis_validator import ColorAnalysisValidator
from .cycle_calculator import CycleCalculator
from .index_collision_validator import IndexCollisionValidator
from .validation_utils import effective_index_sequence, hamming_distance


logger = logging.getLogger(__name__)


# Memoize validation results keyed on (run.id, run.updated_at,
# validation_input_version). `run.touch()` always bumps `updated_at` on
# mutation, so per-run state changes invalidate naturally. The version
# counter covers mutations to *external* inputs (test profiles, app
# profiles, instruments, index kits) that don't change `run.updated_at`;
# `clear_validation_cache()` bumps it so all previously cached entries
# become unreachable. Bounded LRU (eviction handles unbounded growth from
# version churn). Protected with a lock because Starlette's threadpool
# may call validate_run concurrently.
_CACHE_MAX_SIZE = 64
_VALIDATION_CACHE: "OrderedDict[tuple, ValidationResult]" = OrderedDict()
_VALIDATION_CACHE_LOCK = Lock()
_VALIDATION_INPUT_VERSION: int = 0


def _validation_cache_key(
    run: "SequencingRun",
    version: int,
    *,
    has_test_profile_repo: bool,
    has_app_profile_repo: bool,
    has_instrument_config: bool,
) -> tuple:
    """Build the cache key.

    Includes ``run.id`` + ``run.updated_at`` (covers run-state changes)
    and the global ``validation_input_version`` (covers profile /
    instrument / index-kit mutations that don't touch the run).

    It ALSO keys on whether each optional input was supplied, because the
    result *content* depends on them: application-profile and missing-test_id
    checks run only when both profile repos are present, and ``instrument_config``
    affects collision/color/configuration. The edit page calls ``validate_run``
    with no repos while the Mark-Ready gate calls it with all of them at the same
    ``run.updated_at`` — without this, the gate would be served the edit page's
    repos-less (under-counted) cached result and could promote an invalid run.
    We key on PRESENCE (a bool), not identity: ``ctx.instrument_config`` is a
    property returning a freshly-constructed object each access, so an
    ``id()``-based key would change every call and defeat the cache.
    """
    return (
        run.id, run.updated_at, version,
        has_test_profile_repo, has_app_profile_repo, has_instrument_config,
    )


def clear_validation_cache() -> None:
    """Invalidate every previously cached validation result.

    Called by every mutation path that changes validation inputs without
    bumping any specific run's ``updated_at``: GitHub config sync,
    instrument toggle/enable-all/disable-all, index-kit save/delete.
    Increments the global version under the lock so concurrent
    ``validate_run`` callers either (a) read the old version and store
    under the now-unreachable key, or (b) read the new version and miss,
    recomputing. Either outcome is safe — no thread can read a hit
    against the post-mutation key with pre-mutation content.
    """
    global _VALIDATION_INPUT_VERSION
    with _VALIDATION_CACHE_LOCK:
        _VALIDATION_INPUT_VERSION += 1
        _VALIDATION_CACHE.clear()


def _current_validation_input_version() -> int:
    """Snapshot of the version counter for a single ``validate_run`` call."""
    with _VALIDATION_CACHE_LOCK:
        return _VALIDATION_INPUT_VERSION


class ValidationService:
    """Service for validating sequencing run configuration.

    This class orchestrates all validation checks by delegating to
    specialized validator classes and aggregating results.
    """

    @classmethod
    def validate_run(
        cls,
        run: SequencingRun,
        test_profile_repo=None,
        app_profile_repo=None,
        instrument_config=None,
    ) -> ValidationResult:
        """Validate a run. Memoized on (run.id, run.updated_at, input_version).

        Per-run state changes invalidate via ``run.touch()`` bumping
        ``updated_at``. External-input mutations (profiles / instruments /
        kits) invalidate via ``clear_validation_cache()`` bumping the
        version counter. The cache is bounded (LRU); locked because
        Starlette's threadpool may call this concurrently.
        """
        key = _validation_cache_key(
            run,
            _current_validation_input_version(),
            has_test_profile_repo=test_profile_repo is not None,
            has_app_profile_repo=app_profile_repo is not None,
            has_instrument_config=instrument_config is not None,
        )
        with _VALIDATION_CACHE_LOCK:
            if key in _VALIDATION_CACHE:
                _VALIDATION_CACHE.move_to_end(key)
                return _VALIDATION_CACHE[key]
        result = cls._validate_run_uncached(run, test_profile_repo, app_profile_repo, instrument_config)
        with _VALIDATION_CACHE_LOCK:
            _VALIDATION_CACHE[key] = result
            if len(_VALIDATION_CACHE) > _CACHE_MAX_SIZE:
                _VALIDATION_CACHE.popitem(last=False)
        return result

    @classmethod
    def _validate_run_uncached(
        cls,
        run: SequencingRun,
        test_profile_repo=None,
        app_profile_repo=None,
        instrument_config=None,
    ) -> ValidationResult:
        """The original validate_run logic, now wrapped by the cached
        public method above. Do not call directly outside the class.
        """
        # Sample ID validation
        duplicate_errors = cls.validate_sample_ids(run)

        # Index collision validation (delegated)
        collisions = IndexCollisionValidator.validate_index_collisions(run, instrument_config)

        distance_matrices = (
            IndexCollisionValidator.calculate_index_distances(run, instrument_config)
            if run.samples else {}
        )

        # Check if color balance analysis is enabled for this instrument
        color_balance_enabled = is_color_balance_enabled(run.instrument_platform)

        # Get channel configuration for this instrument
        channel_config = get_channel_config(run.instrument_platform)

        # Get i5 read orientation for this instrument
        i5_orientation = get_i5_read_orientation(run.instrument_platform)

        # Color balance and dark cycle analysis (delegated)
        if color_balance_enabled and run.samples:
            color_balance = ColorAnalysisValidator.calculate_color_balance(
                run, channel_config, i5_orientation, instrument_config,
            )
            dark_cycle_errors = ColorAnalysisValidator.validate_dark_cycles(
                run, channel_config, i5_orientation,
            )
            dark_cycle_samples = ColorAnalysisValidator.build_dark_cycle_info(
                run, channel_config, i5_orientation,
            )
        else:
            color_balance = {}
            dark_cycle_errors = []
            dark_cycle_samples = []

        # Application profile validation (delegated)
        application_errors = []
        if test_profile_repo and app_profile_repo and run.samples:
            application_errors = ApplicationProfileValidator.validate_application_profiles(
                run, test_profile_repo, app_profile_repo, instrument_config,
            )

        # Configuration validation (inline - many private helpers)
        configuration_errors = cls.validate_configuration(run, instrument_config)

        # When profile repos are configured, every sample must have a test_id —
        # the SampleSheet v2 exporter's profile-driven path silently drops samples
        # without one, and emits no BCLConvert section at all if none are present.
        if test_profile_repo and app_profile_repo and run.samples:
            configuration_errors.extend(cls._validate_samples_have_test_id(run))

        # Get chemistry type for display purposes
        chemistry = get_chemistry_type(run.instrument_platform)

        return ValidationResult(
            duplicate_sample_ids=duplicate_errors,
            index_collisions=collisions,
            distance_matrices=distance_matrices,
            dark_cycle_errors=dark_cycle_errors,
            dark_cycle_samples=dark_cycle_samples,
            color_balance=color_balance,
            application_errors=application_errors,
            configuration_errors=configuration_errors,
            chemistry_type=chemistry.value if chemistry else "",
            color_balance_enabled=color_balance_enabled,
            channel_config=channel_config,
        )

    @classmethod
    def validate_sample_ids(cls, run: SequencingRun) -> list[str]:
        """
        Check for duplicate sample IDs.

        Args:
            run: Sequencing run to validate

        Returns:
            List of error messages for duplicate sample_ids
        """
        errors = []
        seen: dict[str, list[str]] = defaultdict(list)

        for sample in run.samples:
            if sample.sample_id:
                seen[sample.sample_id].append(sample.id)

        for sample_id, internal_ids in seen.items():
            if len(internal_ids) > 1:
                errors.append(
                    f"Duplicate sample_id '{sample_id}' found {len(internal_ids)} times"
                )

        return errors

    # Allowed characters in Illumina sample IDs: alphanumeric, dash, underscore
    _SAMPLE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_\-]+$")

    @classmethod
    def validate_configuration(
        cls,
        run: SequencingRun,
        instrument_config=None,
    ) -> list[ConfigurationError]:
        """
        Validate run configuration: lane assignments, index consistency,
        sample IDs, run cycles vs index lengths, etc.

        Args:
            run: Sequencing run to validate
            instrument_config: Optional InstrumentConfig for DB overrides

        Returns:
            List of ConfigurationError (errors and warnings)
        """
        errors: list[ConfigurationError] = []

        # Prerequisite: at least one sample
        if not run.samples:
            errors.append(ConfigurationError(
                severity=ValidationSeverity.ERROR,
                category="prerequisite_no_samples",
                message="Run has no samples; add samples before marking the run as ready.",
            ))
            return errors  # No samples — skip the rest, they all assume samples exist

        # Prerequisite: every sample has an index assigned
        unindexed = [s for s in run.samples if not s.has_index]
        if unindexed:
            names = [s.sample_id for s in unindexed]
            msg = f"{len(unindexed)} sample(s) have no index assigned: {', '.join(names[:5])}"
            if len(unindexed) > 5:
                msg += f", and {len(unindexed) - 5} more"
            msg += "."
            errors.append(ConfigurationError(
                severity=ValidationSeverity.ERROR,
                category="prerequisite_missing_indexes",
                message=msg,
                sample_names=names,
            ))

        total_lanes = get_lanes_for_flowcell(
            run.instrument_platform, run.flowcell_type, instrument_config
        )
        all_lanes = list(range(1, total_lanes + 1))

        errors.extend(cls._validate_sample_id_characters(run))
        errors.extend(cls._validate_lane_assignments(run, total_lanes))
        errors.extend(cls._validate_no_lane_assignment(run))
        errors.extend(cls._validate_index_length_consistency(run, all_lanes))
        errors.extend(cls._validate_mixed_indexing(run, all_lanes))
        errors.extend(cls._validate_run_cycles_vs_index_length(run))
        errors.extend(cls._validate_override_cycles_match_run(run))
        errors.extend(cls._validate_duplicate_index_pairs(run, all_lanes))
        errors.extend(cls._validate_mismatch_threshold(run, all_lanes))

        return errors

    @classmethod
    def _validate_override_cycles_match_run(
        cls, run: SequencingRun
    ) -> list[ConfigurationError]:
        """Each sample's effective OverrideCycles must reconcile with the run's
        declared cycles. BCL Convert requires every OverrideCycles segment to sum
        to the corresponding Read/Index cycle count; a fixed read-override pattern
        (e.g. a kit default of ``Y100`` on a 151-cycle run) or an operator-pasted
        bulk override that doesn't match would otherwise ship a sheet the
        sequencer rejects or miscalls — and nothing else catches it.
        """
        rc = run.run_cycles
        if not rc:
            return []

        # Expected segment cycle-sums, in OverrideCycles order. Index segments are
        # only present when the run reads those index cycles (matches the exporter).
        expected = [rc.read1_cycles]
        if rc.index1_cycles > 0:
            expected.append(rc.index1_cycles)
        if rc.index2_cycles > 0:
            expected.append(rc.index2_cycles)
        expected.append(rc.read2_cycles)

        bad: list[str] = []
        for sample in run.samples:
            oc = sample.override_cycles
            if not oc and sample.has_index:
                oc = CycleCalculator.calculate_override_cycles(run_cycles=rc, sample=sample)
            if not oc:
                continue
            if "*" in oc:
                continue  # unresolved wildcard — cannot statically reconcile
            segments = [s for s in re.split(r"[;,]", oc) if s]
            if len(segments) != len(expected):
                bad.append(sample.sample_id or sample.id)
                continue
            for want, seg in zip(expected, segments):
                got = sum(int(n) for n in re.findall(r"\d+", seg))
                if got != want:
                    bad.append(sample.sample_id or sample.id)
                    break

        if not bad:
            return []
        preview = ", ".join(bad[:5])
        more = f", and {len(bad) - 5} more" if len(bad) > 5 else ""
        return [ConfigurationError(
            severity=ValidationSeverity.ERROR,
            category="override_cycles_mismatch",
            message=(
                f"{len(bad)} sample(s) have OverrideCycles that do not match the run's "
                f"declared cycles (Read1 {rc.read1_cycles} / Index1 {rc.index1_cycles} / "
                f"Index2 {rc.index2_cycles} / Read2 {rc.read2_cycles}): {preview}{more}. "
                f"Each OverrideCycles segment must sum to the corresponding cycle count "
                f"or BCL Convert will reject or miscall the run."
            ),
            sample_names=bad,
        )]

    @classmethod
    def _validate_sample_id_characters(cls, run: SequencingRun) -> list[ConfigurationError]:
        """Check sample IDs for invalid characters."""
        errors: list[ConfigurationError] = []
        for sample in run.samples:
            sid = sample.sample_id
            if sid and not cls._SAMPLE_ID_PATTERN.match(sid):
                invalid_chars = set(c for c in sid if not re.match(r"[A-Za-z0-9_\-]", c))
                errors.append(
                    ConfigurationError(
                        severity=ValidationSeverity.ERROR,
                        category="invalid_sample_id",
                        message=(
                            f"Sample ID '{sid}' contains invalid characters: "
                            f"{', '.join(repr(c) for c in sorted(invalid_chars))}. "
                            f"Only alphanumeric characters, hyphens, and underscores are allowed."
                        ),
                        sample_names=[sid],
                    )
                )
        return errors

    @classmethod
    def _validate_lane_assignments(
        cls,
        run: SequencingRun,
        total_lanes: int,
    ) -> list[ConfigurationError]:
        """Check that lane assignments are within the flowcell's lane range."""
        errors: list[ConfigurationError] = []
        for sample in run.samples:
            display_name = sample.sample_id or sample.sample_name or sample.id
            for lane in sample.lanes:
                if lane < 1 or lane > total_lanes:
                    errors.append(
                        ConfigurationError(
                            severity=ValidationSeverity.ERROR,
                            category="lane_out_of_range",
                            message=(
                                f"Sample '{display_name}' is assigned to lane {lane}, "
                                f"but the selected flowcell only has lanes 1-{total_lanes}."
                            ),
                            sample_names=[display_name],
                            lane=lane,
                        )
                    )
        return errors

    @classmethod
    def _validate_no_lane_assignment(cls, run: SequencingRun) -> list[ConfigurationError]:
        """Warn about samples with no explicit lane assignment (will go to all lanes)."""
        errors: list[ConfigurationError] = []
        no_lane = [
            sample.sample_id or sample.sample_name or sample.id
            for sample in run.samples
            if not sample.lanes
        ]
        if no_lane and any(s.lanes for s in run.samples):
            # Only warn if some samples have explicit lanes and others don't -
            # if none have lanes, they all go to all lanes and that's fine.
            errors.append(
                ConfigurationError(
                    severity=ValidationSeverity.WARNING,
                    category="no_lane_assignment",
                    message=(
                        f"{len(no_lane)} sample(s) have no lane assignment and will be "
                        f"placed in all lanes: {', '.join(no_lane[:5])}"
                        + (f" and {len(no_lane) - 5} more" if len(no_lane) > 5 else "")
                    ),
                    sample_names=no_lane,
                )
            )
        return errors

    @classmethod
    def _group_samples_by_lane(
        cls,
        run: SequencingRun,
        all_lanes: list[int],
    ) -> dict[int, list]:
        """Group samples by lane (empty lanes = all lanes)."""
        lane_samples: dict[int, list] = defaultdict(list)
        for sample in run.samples:
            if sample.lanes:
                for lane in sample.lanes:
                    lane_samples[lane].append(sample)
            else:
                for lane in all_lanes:
                    lane_samples[lane].append(sample)
        return lane_samples

    @classmethod
    def _validate_index_length_consistency(
        cls,
        run: SequencingRun,
        all_lanes: list[int],
    ) -> list[ConfigurationError]:
        """Check that all samples in a lane have consistent EFFECTIVE index lengths.

        Uses the kit-effective cycle count (``CycleCalculator._get_effective_index_length``)
        rather than the raw stored sequence length. A kit with
        ``default_index1_cycles=8`` and a 10bp sequence demuxes as 8 cycles —
        comparing the raw sequence length here would falsely report a mismatch
        against an 8bp sample that shares the same effective length.
        """
        errors: list[ConfigurationError] = []
        lane_samples = cls._group_samples_by_lane(run, all_lanes)

        for lane, samples in sorted(lane_samples.items()):
            indexed = [s for s in samples if s.has_index]
            if len(indexed) < 2:
                continue

            # Check i7 effective lengths
            i7_lengths: dict[int, list[str]] = defaultdict(list)
            for s in indexed:
                if s.index1_sequence:
                    display = s.sample_id or s.sample_name or s.id
                    eff = CycleCalculator._get_effective_index_length(s, 1)
                    i7_lengths[eff].append(display)

            if len(i7_lengths) > 1:
                length_detail = ", ".join(
                    f"{length}bp ({len(names)} samples)"
                    for length, names in sorted(i7_lengths.items())
                )
                errors.append(
                    ConfigurationError(
                        severity=ValidationSeverity.ERROR,
                        category="index_length_mismatch",
                        message=(
                            f"Lane {lane}: i7 index lengths are inconsistent - {length_detail}. "
                            f"All samples in a lane must have the same index length."
                        ),
                        lane=lane,
                    )
                )

            # Check i5 effective lengths (only among samples that have i5)
            i5_lengths: dict[int, list[str]] = defaultdict(list)
            for s in indexed:
                if s.index2_sequence:
                    display = s.sample_id or s.sample_name or s.id
                    eff = CycleCalculator._get_effective_index_length(s, 2)
                    i5_lengths[eff].append(display)

            if len(i5_lengths) > 1:
                length_detail = ", ".join(
                    f"{length}bp ({len(names)} samples)"
                    for length, names in sorted(i5_lengths.items())
                )
                errors.append(
                    ConfigurationError(
                        severity=ValidationSeverity.ERROR,
                        category="index_length_mismatch",
                        message=(
                            f"Lane {lane}: i5 index lengths are inconsistent - {length_detail}. "
                            f"All samples in a lane must have the same index length."
                        ),
                        lane=lane,
                    )
                )

        return errors

    @classmethod
    def _validate_mixed_indexing(
        cls,
        run: SequencingRun,
        all_lanes: list[int],
    ) -> list[ConfigurationError]:
        """Check for lanes with a mix of single-indexed and dual-indexed samples."""
        errors: list[ConfigurationError] = []
        lane_samples = cls._group_samples_by_lane(run, all_lanes)

        for lane, samples in sorted(lane_samples.items()):
            indexed = [s for s in samples if s.has_index]
            if len(indexed) < 2:
                continue

            has_dual = any(s.index2_sequence for s in indexed)
            has_single = any(s.index1_sequence and not s.index2_sequence for s in indexed)

            if has_dual and has_single:
                dual_names = [
                    s.sample_id or s.sample_name or s.id
                    for s in indexed
                    if s.index2_sequence
                ]
                single_names = [
                    s.sample_id or s.sample_name or s.id
                    for s in indexed
                    if s.index1_sequence and not s.index2_sequence
                ]
                errors.append(
                    ConfigurationError(
                        severity=ValidationSeverity.ERROR,
                        category="mixed_indexing",
                        message=(
                            f"Lane {lane}: mixed single-indexed ({len(single_names)} samples) "
                            f"and dual-indexed ({len(dual_names)} samples). "
                            f"All samples in a lane must use the same indexing mode."
                        ),
                        lane=lane,
                    )
                )

        return errors

    @classmethod
    def _validate_run_cycles_vs_index_length(
        cls,
        run: SequencingRun,
    ) -> list[ConfigurationError]:
        """Check that run index cycles are >= each sample's EFFECTIVE index length.

        Uses the kit-effective cycle count (``CycleCalculator._get_effective_index_length``)
        rather than the raw stored sequence length. The export pipeline builds
        OverrideCycles segments from the effective length; comparing the raw
        sequence length would refuse legitimate "10bp sequence, 8 effective
        cycles" kit configurations even though the resulting Sample Sheet is
        valid (e.g. ``I8N2`` against 8 run cycles).
        """
        errors: list[ConfigurationError] = []
        if not run.run_cycles:
            return errors

        for sample in run.samples:
            display_name = sample.sample_id or sample.sample_name or sample.id

            # Check i7: run index1_cycles must be >= effective i7 length
            if sample.index1_sequence:
                eff_i7 = CycleCalculator._get_effective_index_length(sample, 1)
                if eff_i7 and run.run_cycles.index1_cycles < eff_i7:
                    errors.append(
                        ConfigurationError(
                            severity=ValidationSeverity.ERROR,
                            category="index_exceeds_cycles",
                            message=(
                                f"Sample '{display_name}': i7 index length ({eff_i7}bp) "
                                f"exceeds run index1 cycles ({run.run_cycles.index1_cycles}). "
                                f"Index cycles must be >= index length."
                            ),
                            sample_names=[display_name],
                        )
                    )

            # Check i5: run index2_cycles must be >= effective i5 length
            if sample.index2_sequence:
                eff_i5 = CycleCalculator._get_effective_index_length(sample, 2)
                if eff_i5 and run.run_cycles.index2_cycles < eff_i5:
                    errors.append(
                        ConfigurationError(
                            severity=ValidationSeverity.ERROR,
                            category="index_exceeds_cycles",
                            message=(
                                f"Sample '{display_name}': i5 index length ({eff_i5}bp) "
                                f"exceeds run index2 cycles ({run.run_cycles.index2_cycles}). "
                                f"Index cycles must be >= index length."
                            ),
                            sample_names=[display_name],
                        )
                    )

        return errors

    @classmethod
    def _validate_duplicate_index_pairs(
        cls,
        run: SequencingRun,
        all_lanes: list[int],
    ) -> list[ConfigurationError]:
        """Check for exact duplicate i7+i5 index combinations in the same lane."""
        errors: list[ConfigurationError] = []
        lane_samples = cls._group_samples_by_lane(run, all_lanes)

        for lane, samples in sorted(lane_samples.items()):
            # Build a key of (i7_seq, i5_seq) for each sample
            seen: dict[tuple, list[str]] = defaultdict(list)
            for s in samples:
                # Key on the bases actually READ at demultiplexing (effective
                # index cycles), not the full stored sequence — two samples
                # whose masked tails differ but whose read cycles match
                # demultiplex identically and must be reported as duplicates.
                i7 = effective_index_sequence(s, 1, run)
                i5 = effective_index_sequence(s, 2, run)
                if not i7:
                    continue
                key = (i7, i5)
                display = s.sample_id or s.sample_name or s.id
                seen[key].append(display)

            for (i7, i5), names in seen.items():
                if len(names) > 1:
                    index_desc = f"i7={i7}" + (f", i5={i5}" if i5 else "")
                    errors.append(
                        ConfigurationError(
                            severity=ValidationSeverity.ERROR,
                            category="duplicate_index_pair",
                            message=(
                                f"Lane {lane}: {len(names)} samples share identical indexes "
                                f"({index_desc}): {', '.join(names[:5])}"
                                + (f" and {len(names) - 5} more" if len(names) > 5 else "")
                                + ". Demultiplexing cannot distinguish these samples."
                            ),
                            sample_names=names,
                            lane=lane,
                        )
                    )

        return errors

    @classmethod
    def _validate_mismatch_threshold(
        cls,
        run: SequencingRun,
        all_lanes: list[int],
    ) -> list[ConfigurationError]:
        """Warn when the barcode mismatch threshold is close to the minimum distance in a lane."""
        errors: list[ConfigurationError] = []
        lane_samples = cls._group_samples_by_lane(run, all_lanes)

        for lane, samples in sorted(lane_samples.items()):
            indexed = [s for s in samples if s.index1_sequence]
            if len(indexed) < 2:
                continue

            # Find minimum i7 distance in this lane
            min_i7_dist = None
            for i in range(len(indexed)):
                for j in range(i + 1, len(indexed)):
                    s1, s2 = indexed[i], indexed[j]
                    if s1.index1_sequence and s2.index1_sequence:
                        # Distance over the cycles actually read, not the
                        # full stored sequence (see _check_sample_pair_collision).
                        d = hamming_distance(
                            effective_index_sequence(s1, 1, run),
                            effective_index_sequence(s2, 1, run),
                        )
                        if min_i7_dist is None or d < min_i7_dist:
                            min_i7_dist = d

            if min_i7_dist is not None:
                # Get the effective mismatch for i7 in this lane
                # Use the maximum per-sample mismatch (or global default)
                max_mismatch_i7 = max(
                    (
                        s.barcode_mismatches_index1
                        if s.barcode_mismatches_index1 is not None
                        else run.barcode_mismatches_index1
                    )
                    for s in indexed
                )
                # Warning: minimum distance equals 2x mismatch threshold
                # (two samples could each have `mismatch` errors and still collide)
                if min_i7_dist <= 2 * max_mismatch_i7:
                    errors.append(
                        ConfigurationError(
                            severity=ValidationSeverity.WARNING,
                            category="mismatch_threshold_risk",
                            message=(
                                f"Lane {lane}: minimum i7 distance ({min_i7_dist}) is at or below "
                                f"2x the barcode mismatch threshold ({max_mismatch_i7}). "
                                f"Consider reducing the mismatch threshold to avoid misassignment."
                            ),
                            lane=lane,
                        )
                    )

        return errors

    @classmethod
    def _validate_samples_have_test_id(
        cls,
        run: SequencingRun,
    ) -> list[ConfigurationError]:
        """Require every sample to have a test_id when profile repos are configured.

        Without a test_id, the profile-driven SampleSheet v2 export path emits no
        BCLConvert_Data row for the sample (and no BCLConvert section at all when
        no sample has one). Block approval rather than ship an unusable sheet.
        """
        missing = [
            sample.sample_id or sample.sample_name or sample.id
            for sample in run.samples
            if not sample.test_id
        ]
        if not missing:
            return []

        preview = ", ".join(missing[:5])
        more = f" and {len(missing) - 5} more" if len(missing) > 5 else ""
        return [
            ConfigurationError(
                severity=ValidationSeverity.ERROR,
                category="missing_test_id",
                message=(
                    f"{len(missing)} sample(s) have no test_id assigned: {preview}{more}. "
                    f"A test_id is required to determine which application profiles "
                    f"(BCLConvert, DRAGEN, etc.) to apply during demultiplexing."
                ),
                sample_names=missing,
            )
        ]

    # -------------------------------------------------------------------------
    # Backward compatibility: expose validator classes and methods
    # -------------------------------------------------------------------------

    # Re-export for backward compatibility
    validate_index_collisions = IndexCollisionValidator.validate_index_collisions
    calculate_index_distances = IndexCollisionValidator.calculate_index_distances
    validate_dark_cycles = ColorAnalysisValidator.validate_dark_cycles
    build_dark_cycle_info = ColorAnalysisValidator.build_dark_cycle_info
    calculate_color_balance = ColorAnalysisValidator.calculate_color_balance
    validate_application_profiles = ApplicationProfileValidator.validate_application_profiles

    # Re-export constants
    I7_ONLY_MIN_DISTANCE = IndexCollisionValidator.I7_ONLY_MIN_DISTANCE
    COMBINED_MIN_DISTANCE = IndexCollisionValidator.COMBINED_MIN_DISTANCE
