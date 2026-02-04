"""Application profile validation for sequencing runs.

Validates that application profiles required by samples are available
on the selected instrument with compatible software versions.
"""

from typing import Optional

from ..data.instruments import get_onboard_applications_by_name
from ..models.sequencing_run import SequencingRun
from ..models.validation import ApplicationValidationError


class ApplicationProfileValidator:
    """Validator for application profile compatibility with instruments."""

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
            app_versions.setdefault(app["name"], set()).add(
                app.get("software_version", "")
            )

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
                    errors.append(
                        ApplicationValidationError(
                            sample_id=sample.id,
                            sample_name=display_name,
                            test_id=sample.test_id,
                            application_name="",
                            profile_name="",
                            error_type="test_profile_not_found",
                            detail=f"No test profile found for test type '{sample.test_id}'",
                        )
                    )
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
                    errors.append(
                        ApplicationValidationError(
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
                        )
                    )
                    continue

                app_name = app_profile.application_name
                if app_name not in available_app_names:
                    errors.append(
                        ApplicationValidationError(
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
                        )
                    )
                    continue

                # Check software version compatibility
                profile_sw_version = app_profile.settings.get("SoftwareVersion", "")
                if profile_sw_version and app_versions.get(app_name):
                    instrument_versions = app_versions[app_name]
                    if profile_sw_version not in instrument_versions:
                        errors.append(
                            ApplicationValidationError(
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
                            )
                        )

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
                errors.append(
                    ApplicationValidationError(
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
                    )
                )

        return errors
