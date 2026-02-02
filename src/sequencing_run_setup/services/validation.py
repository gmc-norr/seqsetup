"""Validation service for sequencing runs."""

from collections import defaultdict
from typing import Optional

from ..data.instruments import (
    get_channel_config,
    get_chemistry_type,
    get_i5_read_orientation,
    get_lanes_for_flowcell,
    get_onboard_applications_by_name,
    is_color_balance_enabled,
)
from ..models.sample import Sample
from ..models.sequencing_run import SequencingRun
import re

from ..models.validation import (
    ApplicationValidationError,
    ConfigurationError,
    DarkCycleError,
    IndexCollision,
    IndexColorBalance,
    IndexDistanceMatrix,
    LaneColorBalance,
    PositionColorBalance,
    SampleDarkCycleInfo,
    ValidationResult,
    ValidationSeverity,
)


class ValidationService:
    """Service for validating sequencing run configuration."""

    @classmethod
    def validate_run(
        cls,
        run: SequencingRun,
        test_profile_repo=None,
        app_profile_repo=None,
        instrument_config=None,
    ) -> ValidationResult:
        """
        Perform complete validation of a sequencing run.

        Args:
            run: Sequencing run to validate
            test_profile_repo: Optional TestProfileRepository for profile validation
            app_profile_repo: Optional ApplicationProfileRepository for profile validation
            instrument_config: Optional InstrumentConfig for DB overrides

        Returns:
            ValidationResult with all errors and per-lane distance matrices
        """
        duplicate_errors = cls.validate_sample_ids(run)
        collisions = cls.validate_index_collisions(run)
        distance_matrices = cls.calculate_index_distances(run) if run.samples else {}

        # Check if color balance analysis is enabled for this instrument
        color_balance_enabled = is_color_balance_enabled(run.instrument_platform)

        # Get channel configuration for this instrument
        channel_config = get_channel_config(run.instrument_platform)

        # Get i5 read orientation for this instrument
        i5_orientation = get_i5_read_orientation(run.instrument_platform)

        # Only calculate color balance for enabled instruments
        if color_balance_enabled and run.samples:
            color_balance = cls.calculate_color_balance(run, channel_config, i5_orientation)
            dark_cycle_errors = cls.validate_dark_cycles(run, channel_config, i5_orientation)
            dark_cycle_samples = cls.build_dark_cycle_info(run, channel_config, i5_orientation)
        else:
            color_balance = {}
            dark_cycle_errors = []
            dark_cycle_samples = []

        # Validate application profiles against instrument capabilities
        application_errors = []
        if test_profile_repo and app_profile_repo and run.samples:
            application_errors = cls.validate_application_profiles(
                run, test_profile_repo, app_profile_repo, instrument_config
            )

        # Validate run configuration (lane ranges, index lengths, etc.)
        configuration_errors = cls.validate_configuration(run, instrument_config)

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
            chemistry_type=chemistry.value,
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

    @classmethod
    def validate_index_collisions(cls, run: SequencingRun) -> list[IndexCollision]:
        """
        Detect index collisions within each lane.

        Indexes collide when their Hamming distance is <= the mismatch threshold.

        Args:
            run: Sequencing run to validate

        Returns:
            List of IndexCollision objects describing each collision
        """
        collisions = []

        # Determine total lanes from flowcell
        total_lanes = get_lanes_for_flowcell(run.instrument_platform, run.flowcell_type)
        all_lanes = list(range(1, total_lanes + 1))

        # Group samples by lane
        lane_samples: dict[int, list[Sample]] = defaultdict(list)

        for sample in run.samples:
            if not sample.has_index:
                continue  # Skip samples without indexes

            if sample.lanes:
                # Sample assigned to specific lanes
                for lane in sample.lanes:
                    lane_samples[lane].append(sample)
            else:
                # Empty lanes = all lanes
                for lane in all_lanes:
                    lane_samples[lane].append(sample)

        # Check collisions in each lane
        for lane, samples in lane_samples.items():
            lane_collisions = cls._check_lane_collisions(samples, lane, run)
            collisions.extend(lane_collisions)

        return collisions

    @classmethod
    def validate_dark_cycles(
        cls,
        run: SequencingRun,
        channel_config: Optional[dict] = None,
        i5_orientation: str = "forward",
    ) -> list[DarkCycleError]:
        """
        Check for indexes that start with two consecutive dark bases.

        On 2-color SBS instruments, a dark base produces no signal in either
        channel. If the first two bases of an index are both dark, the
        instrument cannot reliably detect the index read start. One dark base
        in the first two positions is acceptable; both dark is an error.

        Args:
            run: Sequencing run
            channel_config: Dye channel configuration (must contain "dark_base")
            i5_orientation: "forward" or "reverse-complement"

        Returns:
            List of DarkCycleError for each affected sample/index
        """
        if not channel_config:
            return []

        dark_base = channel_config.get("dark_base", "").upper()
        if not dark_base:
            return []

        errors = []
        for sample in run.samples:
            display_name = sample.sample_id or sample.sample_name or sample.id

            # Check i7 (index1)
            i7_seq = sample.index1_sequence
            if i7_seq and len(i7_seq) >= 2:
                if i7_seq[0].upper() == dark_base and i7_seq[1].upper() == dark_base:
                    errors.append(DarkCycleError(
                        sample_id=sample.id,
                        sample_name=display_name,
                        index_type="i7",
                        sequence=i7_seq,
                        dark_base=dark_base,
                    ))

            # Check i5 (index2) — use the read orientation the instrument sees
            i5_seq = sample.index2_sequence
            if i5_seq and len(i5_seq) >= 2:
                read_seq = (
                    cls._reverse_complement(i5_seq)
                    if i5_orientation == "reverse-complement"
                    else i5_seq
                )
                if read_seq[0].upper() == dark_base and read_seq[1].upper() == dark_base:
                    errors.append(DarkCycleError(
                        sample_id=sample.id,
                        sample_name=display_name,
                        index_type="i5",
                        sequence=i5_seq,
                        dark_base=dark_base,
                    ))

        return errors

    @classmethod
    def build_dark_cycle_info(
        cls,
        run: SequencingRun,
        channel_config: Optional[dict] = None,
        i5_orientation: str = "forward",
    ) -> list[SampleDarkCycleInfo]:
        """
        Build per-sample dark cycle information for visualization.

        Returns info for every sample that has at least one index sequence,
        including the number of leading dark bases for each index.
        """
        if not channel_config:
            return []

        dark_base = channel_config.get("dark_base", "").upper()
        if not dark_base:
            return []

        results = []
        for sample in run.samples:
            i7_seq = sample.index1_sequence or ""
            i5_seq = sample.index2_sequence or ""

            if not i7_seq and not i5_seq:
                continue

            display_name = sample.sample_id or sample.sample_name or sample.id

            # Compute i5 read sequence
            if i5_seq and i5_orientation == "reverse-complement":
                i5_read = cls._reverse_complement(i5_seq)
            else:
                i5_read = i5_seq

            # Count leading dark bases
            i7_leading = 0
            for base in i7_seq[:2]:
                if base.upper() == dark_base:
                    i7_leading += 1
                else:
                    break

            i5_leading = 0
            for base in i5_read[:2]:
                if base.upper() == dark_base:
                    i5_leading += 1
                else:
                    break

            results.append(SampleDarkCycleInfo(
                sample_id=sample.id,
                sample_name=display_name,
                i7_sequence=i7_seq,
                i5_sequence=i5_seq,
                i5_read_sequence=i5_read,
                dark_base=dark_base,
                i7_leading_dark=i7_leading,
                i5_leading_dark=i5_leading,
            ))

        return results

    # Minimum safe distances for collision detection
    I7_ONLY_MIN_DISTANCE = 3  # i7-only: safe if distance >= 3
    COMBINED_MIN_DISTANCE = 4  # i7+i5 combined: safe if distance >= 4

    @classmethod
    def _check_lane_collisions(
        cls,
        samples: list[Sample],
        lane: int,
        run: SequencingRun,
    ) -> list[IndexCollision]:
        """
        Check for index collisions among samples in a single lane.

        Collision thresholds:
        - i7 only (no i5): collision if i7 distance < 3
        - i7 + i5 combined: collision if combined distance < 4

        Args:
            samples: Samples in this lane
            lane: Lane number
            run: Parent run (unused, kept for API compatibility)

        Returns:
            List of collisions found in this lane
        """
        collisions = []
        n = len(samples)

        for i in range(n):
            for j in range(i + 1, n):
                sample1 = samples[i]
                sample2 = samples[j]

                collision = cls._check_sample_pair_collision(sample1, sample2, lane)
                if collision:
                    collisions.append(collision)

        return collisions

    @classmethod
    def _check_sample_pair_collision(
        cls,
        sample1: Sample,
        sample2: Sample,
        lane: int,
    ) -> Optional[IndexCollision]:
        """
        Check if two samples have colliding indexes.

        Uses combined distance when both samples have i5, otherwise i7-only distance.

        Thresholds:
        - i7 only: collision if distance < 3 (i.e., distance <= 2)
        - i7+i5 combined: collision if distance < 4 (i.e., distance <= 3)

        Args:
            sample1: First sample
            sample2: Second sample
            lane: Lane number

        Returns:
            IndexCollision if collision detected, None otherwise
        """
        i7_seq1 = sample1.index1_sequence
        i7_seq2 = sample2.index1_sequence
        i5_seq1 = sample1.index2_sequence
        i5_seq2 = sample2.index2_sequence

        # Skip if either sample lacks i7 index
        if not i7_seq1 or not i7_seq2:
            return None

        # Calculate i7 distance
        i7_distance = cls._hamming_distance(i7_seq1, i7_seq2)

        # Check if both samples have i5 indexes
        both_have_i5 = bool(i5_seq1 and i5_seq2)

        if both_have_i5:
            # Use combined distance with threshold of 4
            i5_distance = cls._hamming_distance(i5_seq1, i5_seq2)
            combined_distance = i7_distance + i5_distance
            threshold = cls.COMBINED_MIN_DISTANCE - 1  # collision if distance <= 3

            if combined_distance <= threshold:
                return IndexCollision(
                    sample1_id=sample1.id,
                    sample1_name=sample1.sample_id or sample1.sample_name or sample1.id,
                    sample2_id=sample2.id,
                    sample2_name=sample2.sample_id or sample2.sample_name or sample2.id,
                    lane=lane,
                    index_type="i7+i5",
                    sequence1=f"{i7_seq1}+{i5_seq1}",
                    sequence2=f"{i7_seq2}+{i5_seq2}",
                    hamming_distance=combined_distance,
                    mismatch_threshold=threshold,
                )
        else:
            # Use i7-only distance with threshold of 3
            threshold = cls.I7_ONLY_MIN_DISTANCE - 1  # collision if distance <= 2

            if i7_distance <= threshold:
                return IndexCollision(
                    sample1_id=sample1.id,
                    sample1_name=sample1.sample_id or sample1.sample_name or sample1.id,
                    sample2_id=sample2.id,
                    sample2_name=sample2.sample_id or sample2.sample_name or sample2.id,
                    lane=lane,
                    index_type="i7",
                    sequence1=i7_seq1,
                    sequence2=i7_seq2,
                    hamming_distance=i7_distance,
                    mismatch_threshold=threshold,
                )

        return None

    @classmethod
    def _hamming_distance(cls, seq1: str, seq2: str) -> int:
        """
        Calculate Hamming distance between two sequences.

        For sequences of different lengths, compares only up to the shorter length.
        This reflects how sequencing demultiplexing works - indexes are compared
        only for the number of cycles read.

        Args:
            seq1: First sequence
            seq2: Second sequence

        Returns:
            Number of positions where characters differ (up to shorter length)
        """
        # Compare up to shorter length only
        min_len = min(len(seq1), len(seq2))
        return sum(c1 != c2 for c1, c2 in zip(seq1[:min_len], seq2[:min_len]))

    @classmethod
    def calculate_index_distances(cls, run: SequencingRun) -> dict[int, IndexDistanceMatrix]:
        """
        Calculate all-vs-all index distances per lane for heatmap visualization.

        Args:
            run: Sequencing run

        Returns:
            Dict mapping lane number to IndexDistanceMatrix for samples in that lane
        """
        # Determine total lanes from flowcell
        total_lanes = get_lanes_for_flowcell(run.instrument_platform, run.flowcell_type)
        all_lanes = list(range(1, total_lanes + 1))

        # Group samples by lane
        lane_samples: dict[int, list[Sample]] = defaultdict(list)

        for sample in run.samples:
            if not sample.has_index:
                continue  # Skip samples without indexes

            if sample.lanes:
                # Sample assigned to specific lanes
                for lane in sample.lanes:
                    lane_samples[lane].append(sample)
            else:
                # Empty lanes = all lanes
                for lane in all_lanes:
                    lane_samples[lane].append(sample)

        # Calculate matrix for each lane
        matrices: dict[int, IndexDistanceMatrix] = {}

        for lane in sorted(lane_samples.keys()):
            samples = lane_samples[lane]
            if len(samples) >= 2:
                matrices[lane] = cls._calculate_lane_distances(samples)

        return matrices

    @classmethod
    def _calculate_lane_distances(cls, samples: list[Sample]) -> IndexDistanceMatrix:
        """
        Calculate distance matrix for samples in a single lane.

        Args:
            samples: Samples in this lane

        Returns:
            IndexDistanceMatrix with distances between sample pairs
        """
        n = len(samples)

        sample_ids = [s.id for s in samples]
        sample_names = [s.sample_id or s.sample_name or s.id for s in samples]

        # Initialize matrices with None (diagonal will stay None)
        i7_distances: list[list[Optional[int]]] = [[None for _ in range(n)] for _ in range(n)]
        i5_distances: list[list[Optional[int]]] = [[None for _ in range(n)] for _ in range(n)]
        combined_distances: list[list[Optional[int]]] = [[None for _ in range(n)] for _ in range(n)]

        for i in range(n):
            for j in range(i + 1, n):
                sample1 = samples[i]
                sample2 = samples[j]

                # Calculate i7 distance
                i7_dist = None
                if sample1.index1_sequence and sample2.index1_sequence:
                    i7_dist = cls._hamming_distance(
                        sample1.index1_sequence, sample2.index1_sequence
                    )
                i7_distances[i][j] = i7_dist
                i7_distances[j][i] = i7_dist  # Symmetric

                # Calculate i5 distance
                i5_dist = None
                if sample1.index2_sequence and sample2.index2_sequence:
                    i5_dist = cls._hamming_distance(
                        sample1.index2_sequence, sample2.index2_sequence
                    )
                i5_distances[i][j] = i5_dist
                i5_distances[j][i] = i5_dist  # Symmetric

                # Calculate combined distance (sum of i7 + i5)
                combined_dist = None
                if i7_dist is not None and i5_dist is not None:
                    combined_dist = i7_dist + i5_dist
                elif i7_dist is not None:
                    combined_dist = i7_dist
                elif i5_dist is not None:
                    combined_dist = i5_dist
                combined_distances[i][j] = combined_dist
                combined_distances[j][i] = combined_dist  # Symmetric

        return IndexDistanceMatrix(
            sample_ids=sample_ids,
            sample_names=sample_names,
            i7_distances=i7_distances,
            i5_distances=i5_distances,
            combined_distances=combined_distances,
        )

    @classmethod
    def validate_application_profiles(
        cls,
        run: SequencingRun,
        test_profile_repo,
        app_profile_repo,
        instrument_config=None,
    ) -> list[ApplicationValidationError]:
        """
        Validate that application profiles required by samples are available
        on the selected instrument.

        For each sample with a test_id:
        1. Look up the TestProfile by test_type
        2. Resolve each ApplicationProfileReference to an ApplicationProfile
        3. Check that the application_name exists in the instrument's onboard apps
        4. Check that the software version matches

        Args:
            run: Sequencing run
            test_profile_repo: TestProfileRepository
            app_profile_repo: ApplicationProfileRepository
            instrument_config: Optional InstrumentConfig for DB overrides

        Returns:
            List of ApplicationValidationError for each issue found
        """
        errors: list[ApplicationValidationError] = []
        instrument_name = run.instrument_platform.value

        # Get available onboard applications for this instrument
        onboard_apps = get_onboard_applications_by_name(instrument_name, instrument_config)
        available_app_names = {app["name"] for app in onboard_apps}
        # Build version lookup: app_name -> set of versions
        app_versions: dict[str, set[str]] = {}
        for app in onboard_apps:
            app_versions.setdefault(app["name"], set()).add(app.get("software_version", ""))

        # Cache lookups to avoid repeated DB queries
        test_profile_cache: dict[str, Optional[object]] = {}
        app_profile_cache: dict[tuple[str, str], Optional[object]] = {}

        # Collect unique test_ids to avoid duplicate errors for same test
        seen_test_ids: set[str] = set()

        # Track required versions per application across all samples
        # app_name -> {version: [profile_name, ...]}
        required_versions: dict[str, dict[str, list[str]]] = {}

        for sample in run.samples:
            if not sample.test_id:
                continue

            display_name = sample.sample_id or sample.sample_name or sample.id

            # Look up TestProfile (cached)
            if sample.test_id not in test_profile_cache:
                test_profile_cache[sample.test_id] = test_profile_repo.get_by_test_type(
                    sample.test_id
                )

            test_profile = test_profile_cache[sample.test_id]
            if test_profile is None:
                # Only report once per test_id
                if sample.test_id not in seen_test_ids:
                    seen_test_ids.add(sample.test_id)
                    errors.append(ApplicationValidationError(
                        sample_id=sample.id,
                        sample_name=display_name,
                        test_id=sample.test_id,
                        application_name="",
                        profile_name="",
                        error_type="test_profile_not_found",
                        detail=f"No test profile found for test type '{sample.test_id}'",
                    ))
                continue

            # Check each application profile reference
            for ref in test_profile.application_profiles:
                cache_key = (ref.profile_name, ref.profile_version)
                if cache_key not in app_profile_cache:
                    app_profile_cache[cache_key] = app_profile_repo.get_by_name_version(
                        ref.profile_name, ref.profile_version
                    )

                app_profile = app_profile_cache[cache_key]
                if app_profile is None:
                    errors.append(ApplicationValidationError(
                        sample_id=sample.id,
                        sample_name=display_name,
                        test_id=sample.test_id,
                        application_name="",
                        profile_name=ref.profile_name,
                        error_type="profile_not_found",
                        detail=(
                            f"Application profile '{ref.profile_name}' "
                            f"version '{ref.profile_version}' not found"
                        ),
                    ))
                    continue

                app_name = app_profile.application_name
                if app_name not in available_app_names:
                    errors.append(ApplicationValidationError(
                        sample_id=sample.id,
                        sample_name=display_name,
                        test_id=sample.test_id,
                        application_name=app_name,
                        profile_name=ref.profile_name,
                        error_type="app_not_available",
                        detail=(
                            f"Application '{app_name}' (from profile '{ref.profile_name}') "
                            f"is not available on {instrument_name}"
                        ),
                    ))
                    continue

                # Check software version compatibility
                profile_sw_version = app_profile.settings.get("SoftwareVersion", "")
                if profile_sw_version and app_versions.get(app_name):
                    instrument_versions = app_versions[app_name]
                    if profile_sw_version not in instrument_versions:
                        errors.append(ApplicationValidationError(
                            sample_id=sample.id,
                            sample_name=display_name,
                            test_id=sample.test_id,
                            application_name=app_name,
                            profile_name=ref.profile_name,
                            error_type="version_not_available",
                            detail=(
                                f"Application '{app_name}' version '{profile_sw_version}' "
                                f"(from profile '{ref.profile_name}') is not available on "
                                f"{instrument_name}. Available: "
                                f"{', '.join(sorted(instrument_versions))}"
                            ),
                        ))

                # Track the version this profile requires for cross-sample consistency
                if profile_sw_version:
                    required_versions.setdefault(app_name, {}).setdefault(
                        profile_sw_version, []
                    ).append(ref.profile_name)

        # Check cross-sample version consistency: each application must use
        # a single version across the entire run
        for app_name, versions_map in required_versions.items():
            if len(versions_map) > 1:
                version_details = ", ".join(
                    f"{ver} (from {', '.join(sorted(set(profiles)))})"
                    for ver, profiles in sorted(versions_map.items())
                )
                errors.append(ApplicationValidationError(
                    sample_id="",
                    sample_name="",
                    test_id="",
                    application_name=app_name,
                    profile_name="",
                    error_type="version_conflict",
                    detail=(
                        f"Application '{app_name}' requires multiple versions "
                        f"across samples: {version_details}. "
                        f"All samples in a run must use the same version."
                    ),
                ))

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
        if not run.samples:
            return errors

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
        errors.extend(cls._validate_duplicate_index_pairs(run, all_lanes))
        errors.extend(cls._validate_mismatch_threshold(run, all_lanes))

        return errors

    @classmethod
    def _validate_sample_id_characters(cls, run: SequencingRun) -> list[ConfigurationError]:
        """Check sample IDs for invalid characters."""
        errors: list[ConfigurationError] = []
        for sample in run.samples:
            sid = sample.sample_id
            if sid and not cls._SAMPLE_ID_PATTERN.match(sid):
                invalid_chars = set(c for c in sid if not re.match(r"[A-Za-z0-9_\-]", c))
                errors.append(ConfigurationError(
                    severity=ValidationSeverity.ERROR,
                    category="invalid_sample_id",
                    message=(
                        f"Sample ID '{sid}' contains invalid characters: "
                        f"{', '.join(repr(c) for c in sorted(invalid_chars))}. "
                        f"Only alphanumeric characters, hyphens, and underscores are allowed."
                    ),
                    sample_names=[sid],
                ))
        return errors

    @classmethod
    def _validate_lane_assignments(
        cls, run: SequencingRun, total_lanes: int,
    ) -> list[ConfigurationError]:
        """Check that lane assignments are within the flowcell's lane range."""
        errors: list[ConfigurationError] = []
        for sample in run.samples:
            display_name = sample.sample_id or sample.sample_name or sample.id
            for lane in sample.lanes:
                if lane < 1 or lane > total_lanes:
                    errors.append(ConfigurationError(
                        severity=ValidationSeverity.ERROR,
                        category="lane_out_of_range",
                        message=(
                            f"Sample '{display_name}' is assigned to lane {lane}, "
                            f"but the selected flowcell only has lanes 1–{total_lanes}."
                        ),
                        sample_names=[display_name],
                        lane=lane,
                    ))
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
            # Only warn if some samples have explicit lanes and others don't —
            # if none have lanes, they all go to all lanes and that's fine.
            errors.append(ConfigurationError(
                severity=ValidationSeverity.WARNING,
                category="no_lane_assignment",
                message=(
                    f"{len(no_lane)} sample(s) have no lane assignment and will be "
                    f"placed in all lanes: {', '.join(no_lane[:5])}"
                    + (f" and {len(no_lane) - 5} more" if len(no_lane) > 5 else "")
                ),
                sample_names=no_lane,
            ))
        return errors

    @classmethod
    def _group_samples_by_lane(
        cls, run: SequencingRun, all_lanes: list[int],
    ) -> dict[int, list[Sample]]:
        """Group samples by lane (empty lanes = all lanes)."""
        lane_samples: dict[int, list[Sample]] = defaultdict(list)
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
        cls, run: SequencingRun, all_lanes: list[int],
    ) -> list[ConfigurationError]:
        """Check that all samples in a lane have consistent index lengths."""
        errors: list[ConfigurationError] = []
        lane_samples = cls._group_samples_by_lane(run, all_lanes)

        for lane, samples in sorted(lane_samples.items()):
            indexed = [s for s in samples if s.has_index]
            if len(indexed) < 2:
                continue

            # Check i7 lengths
            i7_lengths: dict[int, list[str]] = defaultdict(list)
            for s in indexed:
                seq = s.index1_sequence
                if seq:
                    display = s.sample_id or s.sample_name or s.id
                    i7_lengths[len(seq)].append(display)

            if len(i7_lengths) > 1:
                length_detail = ", ".join(
                    f"{length}bp ({len(names)} samples)"
                    for length, names in sorted(i7_lengths.items())
                )
                errors.append(ConfigurationError(
                    severity=ValidationSeverity.ERROR,
                    category="index_length_mismatch",
                    message=(
                        f"Lane {lane}: i7 index lengths are inconsistent — {length_detail}. "
                        f"All samples in a lane must have the same index length."
                    ),
                    lane=lane,
                ))

            # Check i5 lengths (only among samples that have i5)
            i5_lengths: dict[int, list[str]] = defaultdict(list)
            for s in indexed:
                seq = s.index2_sequence
                if seq:
                    display = s.sample_id or s.sample_name or s.id
                    i5_lengths[len(seq)].append(display)

            if len(i5_lengths) > 1:
                length_detail = ", ".join(
                    f"{length}bp ({len(names)} samples)"
                    for length, names in sorted(i5_lengths.items())
                )
                errors.append(ConfigurationError(
                    severity=ValidationSeverity.ERROR,
                    category="index_length_mismatch",
                    message=(
                        f"Lane {lane}: i5 index lengths are inconsistent — {length_detail}. "
                        f"All samples in a lane must have the same index length."
                    ),
                    lane=lane,
                ))

        return errors

    @classmethod
    def _validate_mixed_indexing(
        cls, run: SequencingRun, all_lanes: list[int],
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
                    for s in indexed if s.index2_sequence
                ]
                single_names = [
                    s.sample_id or s.sample_name or s.id
                    for s in indexed if s.index1_sequence and not s.index2_sequence
                ]
                errors.append(ConfigurationError(
                    severity=ValidationSeverity.ERROR,
                    category="mixed_indexing",
                    message=(
                        f"Lane {lane}: mixed single-indexed ({len(single_names)} samples) "
                        f"and dual-indexed ({len(dual_names)} samples). "
                        f"All samples in a lane must use the same indexing mode."
                    ),
                    lane=lane,
                ))

        return errors

    @classmethod
    def _validate_run_cycles_vs_index_length(
        cls, run: SequencingRun,
    ) -> list[ConfigurationError]:
        """Check that run index cycles are >= each sample's index sequence length."""
        errors: list[ConfigurationError] = []
        if not run.run_cycles:
            return errors

        for sample in run.samples:
            display_name = sample.sample_id or sample.sample_name or sample.id

            # Check i7: run index1_cycles must be >= actual i7 sequence length
            i7_seq = sample.index1_sequence
            if i7_seq and run.run_cycles.index1_cycles < len(i7_seq):
                errors.append(ConfigurationError(
                    severity=ValidationSeverity.ERROR,
                    category="index_exceeds_cycles",
                    message=(
                        f"Sample '{display_name}': i7 index length ({len(i7_seq)}bp) "
                        f"exceeds run index1 cycles ({run.run_cycles.index1_cycles}). "
                        f"Index cycles must be >= index length."
                    ),
                    sample_names=[display_name],
                ))

            # Check i5: run index2_cycles must be >= actual i5 sequence length
            i5_seq = sample.index2_sequence
            if i5_seq and run.run_cycles.index2_cycles < len(i5_seq):
                errors.append(ConfigurationError(
                    severity=ValidationSeverity.ERROR,
                    category="index_exceeds_cycles",
                    message=(
                        f"Sample '{display_name}': i5 index length ({len(i5_seq)}bp) "
                        f"exceeds run index2 cycles ({run.run_cycles.index2_cycles}). "
                        f"Index cycles must be >= index length."
                    ),
                    sample_names=[display_name],
                ))

        return errors

    @classmethod
    def _validate_duplicate_index_pairs(
        cls, run: SequencingRun, all_lanes: list[int],
    ) -> list[ConfigurationError]:
        """Check for exact duplicate i7+i5 index combinations in the same lane."""
        errors: list[ConfigurationError] = []
        lane_samples = cls._group_samples_by_lane(run, all_lanes)

        for lane, samples in sorted(lane_samples.items()):
            # Build a key of (i7_seq, i5_seq) for each sample
            seen: dict[tuple, list[str]] = defaultdict(list)
            for s in samples:
                i7 = s.index1_sequence or ""
                i5 = s.index2_sequence or ""
                if not i7:
                    continue
                key = (i7, i5)
                display = s.sample_id or s.sample_name or s.id
                seen[key].append(display)

            for (i7, i5), names in seen.items():
                if len(names) > 1:
                    index_desc = f"i7={i7}" + (f", i5={i5}" if i5 else "")
                    errors.append(ConfigurationError(
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
                    ))

        return errors

    @classmethod
    def _validate_mismatch_threshold(
        cls, run: SequencingRun, all_lanes: list[int],
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
                        d = cls._hamming_distance(s1.index1_sequence, s2.index1_sequence)
                        if min_i7_dist is None or d < min_i7_dist:
                            min_i7_dist = d

            if min_i7_dist is not None:
                # Get the effective mismatch for i7 in this lane
                # Use the maximum per-sample mismatch (or global default)
                max_mismatch_i7 = max(
                    (s.barcode_mismatches_index1 if s.barcode_mismatches_index1 is not None
                     else run.barcode_mismatches_index1)
                    for s in indexed
                )
                # Warning: minimum distance equals 2x mismatch threshold
                # (two samples could each have `mismatch` errors and still collide)
                if min_i7_dist <= 2 * max_mismatch_i7:
                    errors.append(ConfigurationError(
                        severity=ValidationSeverity.WARNING,
                        category="mismatch_threshold_risk",
                        message=(
                            f"Lane {lane}: minimum i7 distance ({min_i7_dist}) is at or below "
                            f"2× the barcode mismatch threshold ({max_mismatch_i7}). "
                            f"Consider reducing the mismatch threshold to avoid misassignment."
                        ),
                        lane=lane,
                    ))

        return errors

    _COMPLEMENT = str.maketrans("ACGTacgt", "TGCAtgca")

    @classmethod
    def _reverse_complement(cls, seq: str) -> str:
        """Return the reverse complement of a DNA sequence."""
        return seq.translate(cls._COMPLEMENT)[::-1]

    @classmethod
    def calculate_color_balance(
        cls,
        run: SequencingRun,
        channel_config: Optional[dict] = None,
        i5_orientation: str = "forward",
    ) -> dict[int, LaneColorBalance]:
        """
        Calculate color balance for index positions per lane.

        Channel assignments are determined by the instrument's channel_config.
        i5 sequences are reverse-complemented when the instrument reads them
        in that orientation, so color balance reflects the actual bases seen
        by the sequencer at each cycle.

        Args:
            run: Sequencing run
            channel_config: Dye channel configuration from instruments.yaml
            i5_orientation: "forward" or "reverse-complement"

        Returns:
            Dict mapping lane number to LaneColorBalance
        """
        # Determine total lanes from flowcell
        total_lanes = get_lanes_for_flowcell(run.instrument_platform, run.flowcell_type)
        all_lanes = list(range(1, total_lanes + 1))

        # Group samples by lane
        lane_samples: dict[int, list[Sample]] = defaultdict(list)

        for sample in run.samples:
            if not sample.has_index:
                continue  # Skip samples without indexes

            if sample.lanes:
                for lane in sample.lanes:
                    lane_samples[lane].append(sample)
            else:
                # Empty lanes = all lanes
                for lane in all_lanes:
                    lane_samples[lane].append(sample)

        # Calculate color balance for each lane
        result: dict[int, LaneColorBalance] = {}

        for lane in sorted(lane_samples.keys()):
            samples = lane_samples[lane]
            if samples:
                result[lane] = cls._calculate_lane_color_balance(
                    lane, samples, channel_config, i5_orientation
                )

        return result

    @classmethod
    def _calculate_lane_color_balance(
        cls,
        lane: int,
        samples: list[Sample],
        channel_config: Optional[dict] = None,
        i5_orientation: str = "forward",
    ) -> LaneColorBalance:
        """
        Calculate color balance for a single lane.

        Args:
            lane: Lane number
            samples: Samples in this lane
            channel_config: Dye channel configuration
            i5_orientation: "forward" or "reverse-complement"

        Returns:
            LaneColorBalance with i7 and i5 balance data
        """
        # Collect all i7 and i5 sequences
        i7_sequences = [s.index1_sequence for s in samples if s.index1_sequence]
        i5_sequences = [s.index2_sequence for s in samples if s.index2_sequence]

        # Reverse-complement i5 sequences when the instrument reads them that way,
        # so color balance reflects the actual bases at each sequencing cycle
        if i5_orientation == "reverse-complement" and i5_sequences:
            i5_sequences = [cls._reverse_complement(seq) for seq in i5_sequences]

        i7_balance = cls._calculate_index_color_balance("i7", i7_sequences, channel_config) if i7_sequences else None
        i5_balance = cls._calculate_index_color_balance("i5", i5_sequences, channel_config) if i5_sequences else None

        return LaneColorBalance(
            lane=lane,
            sample_count=len(samples),
            i7_balance=i7_balance,
            i5_balance=i5_balance,
        )

    @classmethod
    def _calculate_index_color_balance(
        cls, index_type: str, sequences: list[str], channel_config: Optional[dict] = None
    ) -> IndexColorBalance:
        """
        Calculate color balance for an index type across all sequences.

        Args:
            index_type: "i7" or "i5"
            sequences: List of index sequences
            channel_config: Dye channel configuration

        Returns:
            IndexColorBalance with per-position base counts
        """
        if not sequences:
            return IndexColorBalance(index_type=index_type, positions=[])

        # Extract channel parameters from config
        if channel_config:
            ch1_name = channel_config["channel1_name"]
            ch1_bases = tuple(channel_config["channel1_bases"])
            ch2_name = channel_config["channel2_name"]
            ch2_bases = tuple(channel_config["channel2_bases"])
        else:
            # Fallback defaults (XLEAP Blue+Green)
            ch1_name = "Blue"
            ch1_bases = ("A", "C")
            ch2_name = "Green"
            ch2_bases = ("C", "T")

        # Find max length
        max_len = max(len(seq) for seq in sequences)

        positions = []
        for pos in range(max_len):
            pos_balance = PositionColorBalance(
                position=pos + 1,
                channel1_name=ch1_name,
                channel1_bases=ch1_bases,
                channel2_name=ch2_name,
                channel2_bases=ch2_bases,
            )

            for seq in sequences:
                if pos < len(seq):
                    base = seq[pos].upper()
                    if base == "A":
                        pos_balance.a_count += 1
                    elif base == "C":
                        pos_balance.c_count += 1
                    elif base == "G":
                        pos_balance.g_count += 1
                    elif base == "T":
                        pos_balance.t_count += 1

            positions.append(pos_balance)

        return IndexColorBalance(index_type=index_type, positions=positions)
