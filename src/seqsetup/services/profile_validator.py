"""Validators for TestProfile and ApplicationProfile YAML data."""

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version


class ProfileValidationError(Exception):
    """Raised when profile YAML data fails validation."""

    def __init__(self, errors: list[str], source_file: str = ""):
        self.errors = errors
        self.source_file = source_file
        msg = f"Profile validation failed for '{source_file}': " if source_file else "Profile validation failed: "
        msg += "; ".join(errors)
        super().__init__(msg)


def validate_test_profile_yaml(yaml_data: dict, source_file: str = "") -> None:
    """Validate test profile YAML data.

    Required fields:
        - TestType (str)
        - TestName (str)
        - Description (str)
        - Version (valid PEP 440 version)
        - ApplicationProfiles (list of dicts, each with
          ApplicationProfileName and ApplicationProfileVersion)

    Raises:
        ProfileValidationError: If validation fails.
    """
    errors: list[str] = []

    # Required top-level fields
    for field in ("TestType", "TestName", "Description", "Version"):
        if field not in yaml_data:
            errors.append(f"Missing required field '{field}'")
        elif not str(yaml_data[field]).strip():
            errors.append(f"Field '{field}' must not be empty")

    # Validate Version is PEP 440 compliant
    version_val = yaml_data.get("Version")
    if version_val is not None and str(version_val).strip():
        try:
            Version(str(version_val))
        except InvalidVersion:
            errors.append(f"Field 'Version' is not a valid PEP 440 version: '{version_val}'")

    # ApplicationProfiles section
    app_profiles = yaml_data.get("ApplicationProfiles")
    if app_profiles is None:
        errors.append("Missing required field 'ApplicationProfiles'")
    elif not isinstance(app_profiles, list):
        errors.append("Field 'ApplicationProfiles' must be a list")
    elif len(app_profiles) == 0:
        errors.append("Field 'ApplicationProfiles' must contain at least one entry")
    else:
        for i, entry in enumerate(app_profiles):
            if not isinstance(entry, dict):
                errors.append(f"ApplicationProfiles[{i}] must be a mapping")
                continue

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

    if errors:
        raise ProfileValidationError(errors, source_file)


def validate_application_profile_yaml(yaml_data: dict, source_file: str = "") -> None:
    """Validate application profile YAML data.

    Required fields:
        - ApplicationProfileName (str)
        - ApplicationProfileVersion (valid PEP 440 version)
        - ApplicationName (str)
        - ApplicationType (str)

    If ApplicationType is "Dragen", also required:
        - Settings (dict)
        - Data (dict)
        - DataFields (list)

    Raises:
        ProfileValidationError: If validation fails.
    """
    errors: list[str] = []

    # Required top-level fields
    for field in ("ApplicationProfileName", "ApplicationProfileVersion", "ApplicationName", "ApplicationType"):
        if field not in yaml_data:
            errors.append(f"Missing required field '{field}'")
        elif not str(yaml_data[field]).strip():
            errors.append(f"Field '{field}' must not be empty")

    # Validate ApplicationProfileVersion is PEP 440 compliant
    version_val = yaml_data.get("ApplicationProfileVersion")
    if version_val is not None and str(version_val).strip():
        try:
            Version(str(version_val))
        except InvalidVersion:
            errors.append(
                f"Field 'ApplicationProfileVersion' is not a valid PEP 440 version: '{version_val}'"
            )

    # Dragen-specific required sections
    app_type = yaml_data.get("ApplicationType", "")
    if str(app_type).strip().lower() == "dragen":
        if "Settings" not in yaml_data:
            errors.append("Missing required field 'Settings' (required for ApplicationType 'Dragen')")
        elif not isinstance(yaml_data["Settings"], dict):
            errors.append("Field 'Settings' must be a mapping")

        if "Data" not in yaml_data:
            errors.append("Missing required field 'Data' (required for ApplicationType 'Dragen')")
        elif not isinstance(yaml_data["Data"], dict):
            errors.append("Field 'Data' must be a mapping")

        if "DataFields" not in yaml_data:
            errors.append("Missing required field 'DataFields' (required for ApplicationType 'Dragen')")
        elif not isinstance(yaml_data["DataFields"], list):
            errors.append("Field 'DataFields' must be a list")

    if errors:
        raise ProfileValidationError(errors, source_file)


def _validate_version_constraint(value: str, field_path: str, errors: list[str]) -> None:
    """Validate that a string is either a valid PEP 440 specifier or version."""
    # Try as specifier first (e.g., "~=1.0.0", ">=1.0,<2.0")
    try:
        SpecifierSet(value)
        return
    except InvalidSpecifier:
        pass

    # Try as exact version (e.g., "1.0.0")
    try:
        Version(value)
        return
    except InvalidVersion:
        pass

    errors.append(f"'{field_path}' is not a valid PEP 440 version or specifier: '{value}'")
