"""Validator for instrument definition YAML files."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ValidationError:
    """A single validation error."""

    field: str
    message: str
    value: Optional[str] = None

    def __str__(self) -> str:
        if self.value is not None:
            return f"{self.field}: {self.message} (got: {self.value!r})"
        return f"{self.field}: {self.message}"


@dataclass
class ValidationResult:
    """Result of validating an instrument definition."""

    is_valid: bool
    errors: list[ValidationError] = field(default_factory=list)
    warnings: list[ValidationError] = field(default_factory=list)
    instrument_name: str = ""
    source_file: str = ""

    def add_error(self, field: str, message: str, value: Optional[str] = None) -> None:
        """Add a validation error."""
        self.errors.append(ValidationError(field, message, value))
        self.is_valid = False

    def add_warning(self, field: str, message: str, value: Optional[str] = None) -> None:
        """Add a validation warning."""
        self.warnings.append(ValidationError(field, message, value))


# Valid values for enum-like fields
VALID_CHEMISTRY_TYPES = {"2-color", "4-color"}
VALID_ORIENTATIONS = {"forward", "reverse-complement"}
VALID_BASES = {"A", "C", "G", "T"}
VALID_DYE_CHANNELS = {"Blue", "Green", "Red", "Yellow"}


def validate_instrument_yaml(yaml_data: dict, source_file: str = "") -> ValidationResult:
    """Validate an instrument definition YAML structure.

    Args:
        yaml_data: Parsed YAML data for a single instrument
        source_file: Source filename for error reporting

    Returns:
        ValidationResult with any errors or warnings
    """
    result = ValidationResult(
        is_valid=True,
        source_file=source_file,
        instrument_name=yaml_data.get("name", ""),
    )

    # Required fields
    _validate_required_string(result, yaml_data, "name", "Instrument name is required")
    _validate_required_string(result, yaml_data, "samplesheet_name", "Samplesheet name is required")

    # Version field (required for synced instruments)
    if "version" not in yaml_data or not yaml_data.get("version"):
        result.add_warning("version", "Version field is missing or empty")

    # Chemistry type
    chemistry_type = yaml_data.get("chemistry_type", "2-color")
    if chemistry_type not in VALID_CHEMISTRY_TYPES:
        result.add_error(
            "chemistry_type",
            f"Must be one of: {', '.join(sorted(VALID_CHEMISTRY_TYPES))}",
            chemistry_type,
        )

    # i5 orientation fields
    i5_read = yaml_data.get("i5_read_orientation", "forward")
    if i5_read not in VALID_ORIENTATIONS:
        result.add_error(
            "i5_read_orientation",
            f"Must be one of: {', '.join(sorted(VALID_ORIENTATIONS))}",
            i5_read,
        )

    v2_i5 = yaml_data.get("samplesheet_v2_i5_orientation", "forward")
    if v2_i5 not in VALID_ORIENTATIONS:
        result.add_error(
            "samplesheet_v2_i5_orientation",
            f"Must be one of: {', '.join(sorted(VALID_ORIENTATIONS))}",
            v2_i5,
        )

    # Boolean fields
    _validate_boolean(result, yaml_data, "has_dragen_onboard")
    _validate_boolean(result, yaml_data, "color_balance_enabled")

    # Color balance fields (required for 2-color with color_balance_enabled)
    if chemistry_type == "2-color" and yaml_data.get("color_balance_enabled", False):
        _validate_color_balance_config(result, yaml_data)

    # Flowcells
    _validate_flowcells(result, yaml_data)

    # Onboard applications
    _validate_onboard_applications(result, yaml_data)

    # Samplesheet versions
    _validate_samplesheet_versions(result, yaml_data)

    return result


def _validate_required_string(
    result: ValidationResult,
    data: dict,
    field: str,
    message: str,
) -> None:
    """Validate that a required string field exists and is non-empty."""
    value = data.get(field)
    if not value or not isinstance(value, str):
        result.add_error(field, message, str(value) if value else None)


def _validate_boolean(result: ValidationResult, data: dict, field: str) -> None:
    """Validate a boolean field if present."""
    if field in data:
        value = data[field]
        if not isinstance(value, bool):
            result.add_error(field, "Must be a boolean (true/false)", str(value))


def _validate_color_balance_config(result: ValidationResult, data: dict) -> None:
    """Validate color balance configuration for 2-color instruments."""
    # Dye channels
    dye_channels = data.get("dye_channels", [])
    if not dye_channels:
        result.add_warning("dye_channels", "Missing dye_channels for 2-color instrument with color_balance_enabled")
    elif not isinstance(dye_channels, list):
        result.add_error("dye_channels", "Must be a list of channel names", str(type(dye_channels)))
    else:
        for channel in dye_channels:
            if channel not in VALID_DYE_CHANNELS:
                result.add_warning("dye_channels", f"Unusual channel name: {channel}")

    # Base colors
    base_colors = data.get("base_colors", {})
    if not base_colors:
        result.add_warning("base_colors", "Missing base_colors for 2-color instrument")
    elif not isinstance(base_colors, dict):
        result.add_error("base_colors", "Must be a mapping of base to color", str(type(base_colors)))
    else:
        for base in base_colors:
            if base not in VALID_BASES:
                result.add_error("base_colors", f"Invalid base: {base}")

    # Channel bases
    channel1_bases = data.get("channel1_bases", [])
    channel2_bases = data.get("channel2_bases", [])

    if not channel1_bases:
        result.add_warning("channel1_bases", "Missing channel1_bases")
    else:
        for base in channel1_bases:
            if base not in VALID_BASES:
                result.add_error("channel1_bases", f"Invalid base: {base}")

    if not channel2_bases:
        result.add_warning("channel2_bases", "Missing channel2_bases")
    else:
        for base in channel2_bases:
            if base not in VALID_BASES:
                result.add_error("channel2_bases", f"Invalid base: {base}")

    # Dark base
    dark_base = data.get("dark_base", "")
    if dark_base and dark_base not in VALID_BASES:
        result.add_error("dark_base", f"Invalid base: {dark_base}")


def _validate_flowcells(result: ValidationResult, data: dict) -> None:
    """Validate flowcell definitions."""
    flowcells = data.get("flowcells", {})

    if not flowcells:
        result.add_error("flowcells", "At least one flowcell must be defined")
        return

    if not isinstance(flowcells, dict):
        result.add_error("flowcells", "Must be a mapping of flowcell name to configuration")
        return

    for fc_name, fc_config in flowcells.items():
        if not fc_name:
            result.add_error("flowcells", "Flowcell name cannot be empty")
            continue

        if not isinstance(fc_config, dict):
            result.add_error(f"flowcells.{fc_name}", "Must be a configuration object")
            continue

        # Validate lanes
        lanes = fc_config.get("lanes", 1)
        if not isinstance(lanes, int) or lanes < 1:
            result.add_error(f"flowcells.{fc_name}.lanes", "Must be a positive integer", str(lanes))

        # Validate reads (optional but must be non-negative if present)
        reads = fc_config.get("reads", 0)
        if not isinstance(reads, int) or reads < 0:
            result.add_error(f"flowcells.{fc_name}.reads", "Must be a non-negative integer", str(reads))

        # Validate reagent_kits
        reagent_kits = fc_config.get("reagent_kits", [])
        if not isinstance(reagent_kits, list):
            result.add_error(f"flowcells.{fc_name}.reagent_kits", "Must be a list of integers")
        else:
            for kit in reagent_kits:
                if not isinstance(kit, int) or kit <= 0:
                    result.add_error(
                        f"flowcells.{fc_name}.reagent_kits",
                        "All reagent kit values must be positive integers",
                        str(kit),
                    )
                    break


def _validate_onboard_applications(result: ValidationResult, data: dict) -> None:
    """Validate onboard application definitions."""
    apps = data.get("onboard_applications", {})

    if not isinstance(apps, dict):
        result.add_error("onboard_applications", "Must be a mapping of application name to configuration")
        return

    for app_name, app_config in apps.items():
        if not app_name:
            result.add_error("onboard_applications", "Application name cannot be empty")
            continue

        if not isinstance(app_config, dict):
            result.add_error(f"onboard_applications.{app_name}", "Must be a configuration object")
            continue

        # software_version is optional but should be a string if present
        version = app_config.get("software_version")
        if version is not None and not isinstance(version, str):
            result.add_error(
                f"onboard_applications.{app_name}.software_version",
                "Must be a string",
                str(version),
            )


def _validate_samplesheet_versions(result: ValidationResult, data: dict) -> None:
    """Validate samplesheet_versions field."""
    versions = data.get("samplesheet_versions")

    if versions is None:
        # Not specified, will default to [2]
        return

    if not isinstance(versions, list):
        result.add_error("samplesheet_versions", "Must be a list of integers", str(type(versions)))
        return

    valid_versions = {1, 2}
    for v in versions:
        if not isinstance(v, int):
            result.add_error("samplesheet_versions", "All values must be integers", str(v))
        elif v not in valid_versions:
            result.add_error(
                "samplesheet_versions",
                f"Invalid version: {v}. Supported versions are: {sorted(valid_versions)}",
            )


def validate_instruments_collection(
    instruments: list[dict],
    source_files: Optional[list[str]] = None,
) -> list[ValidationResult]:
    """Validate a collection of instrument definitions.

    Args:
        instruments: List of instrument YAML data dicts
        source_files: Optional list of source filenames (parallel to instruments)

    Returns:
        List of ValidationResult for each instrument
    """
    results = []
    source_files = source_files or [""] * len(instruments)

    for inst, source_file in zip(instruments, source_files):
        result = validate_instrument_yaml(inst, source_file)
        results.append(result)

    # Check for duplicate names
    names_seen = {}
    for i, inst in enumerate(instruments):
        name = inst.get("name", "")
        if name:
            if name in names_seen:
                # Add error to both
                results[names_seen[name]].add_error(
                    "name",
                    f"Duplicate instrument name (also in {source_files[i] or 'another file'})",
                )
                results[i].add_error(
                    "name",
                    f"Duplicate instrument name (also in {source_files[names_seen[name]] or 'another file'})",
                )
            else:
                names_seen[name] = i

    return results


def format_validation_results(results: list[ValidationResult]) -> str:
    """Format validation results as a human-readable string.

    Args:
        results: List of ValidationResult objects

    Returns:
        Formatted string describing all errors and warnings
    """
    lines = []
    error_count = 0
    warning_count = 0

    for result in results:
        if not result.errors and not result.warnings:
            continue

        header = result.instrument_name or result.source_file or "Unknown instrument"
        lines.append(f"\n{header}:")

        for error in result.errors:
            lines.append(f"  ERROR: {error}")
            error_count += 1

        for warning in result.warnings:
            lines.append(f"  WARNING: {warning}")
            warning_count += 1

    if not lines:
        return "All instruments validated successfully."

    summary = f"\nValidation complete: {error_count} error(s), {warning_count} warning(s)"
    return "\n".join(lines) + summary
