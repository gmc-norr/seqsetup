"""Validators for TestProfile and ApplicationProfile YAML data."""

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from .sheet_text import PLAIN_NAME_RE, describe, hidden_characters, starts_a_section


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

    if errors:
        raise ProfileValidationError(errors, source_file)


def _is_plain_name(value) -> bool:
    """True for text made only of letters, digits, '_' and '-'."""
    return isinstance(value, str) and PLAIN_NAME_RE.fullmatch(value) is not None


def _hidden_in(value) -> list[str]:
    """The distinct hidden characters anywhere in a YAML value, looking
    inside nested lists and mappings (keys included)."""
    if value is None:
        return []
    if isinstance(value, dict):
        parts = [c for k, v in value.items() for c in _hidden_in(k) + _hidden_in(v)]
    elif isinstance(value, list):
        parts = [c for item in value for c in _hidden_in(item)]
    else:
        parts = hidden_characters(str(value))
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
    mapping, a list, a date, bytes or a set would be written in Python's own
    form. Only text, whole numbers and true/false are written as they are
    (spec 2026-09-29 Sample Sheet follow-ups, §1)."""
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
    if not isinstance(value, (str, int)):
        # true/false is a bool, which is an int. YAML reads 2024-01-01 as a
        # date, and !!binary or !!set as bytes or a set.
        return (
            f"{where} is not text, a whole number or true/false: YAML read it as "
            f"{type(value).__name__} ({value!r}). Put the value in quotes."
        )
    return None


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
        elif _is_empty(yaml_data[field]):
            errors.append(f"Field '{field}' must not be empty")

    # ApplicationName becomes a Sample Sheet section name ([<name>_Settings]),
    # written as is, so it may hold only letters, digits, '_' and '-'.
    app_name = yaml_data.get("ApplicationName")
    if app_name is not None and str(app_name).strip() and not _is_plain_name(app_name):
        errors.append(
            "Field 'ApplicationName' may only contain letters, digits, '_' and '-': "
            f"{app_name!r}"
        )

    # The Sample Sheet writer reads Settings, Data and Translate as mappings
    # and DataFields as a list, for every ApplicationType. Empty is allowed
    # here; the Dragen check below still requires the first three.
    for field, kind, name in (
        ("Settings", dict, "a mapping"),
        ("Data", dict, "a mapping"),
        ("DataFields", list, "a list"),
        ("Translate", dict, "a mapping"),
    ):
        value = yaml_data.get(field)
        if value is not None and not isinstance(value, kind):
            errors.append(f"Field '{field}' must be {name}")

    # Settings, Data, DataFields and Translate are written into the Sample
    # Sheet as cells. A quoted line break still starts a new line for a
    # line-oriented reader, so no hidden character is allowed in them.
    for field in ("Settings", "Data", "DataFields", "Translate"):
        value = yaml_data.get(field)
        if isinstance(value, dict):
            entries = [(key, {key: item}) for key, item in value.items()]
        elif isinstance(value, list):
            entries = [(item, item) for item in value]
        else:
            continue
        for where, part in entries:
            chars = _hidden_in(part)
            if chars:
                errors.append(
                    f"Field '{field}' has a hidden character in {str(where)!r}: "
                    f"{describe(chars)}"
                )

    # Every name becomes a line start (a setting) or a column name. Quoting
    # cannot stop a name like '[BCLConvert_Data]' from starting a new
    # section, so names may hold only letters, digits, '_' and '-'. A name
    # with a hidden character is already reported above.
    settings = yaml_data.get("Settings")
    data = yaml_data.get("Data")
    data_fields = yaml_data.get("DataFields")
    translate = yaml_data.get("Translate")
    names = []
    if isinstance(settings, dict):
        names += [("Settings", key) for key in settings]
    if isinstance(data, dict):
        names += [("Data", key) for key in data]
    if isinstance(data_fields, list):
        names += [("DataFields", item) for item in data_fields]
    if isinstance(translate, dict):
        names += [("Translate", n) for key, value in translate.items() for n in (key, value)]
    for field, name in names:
        if not _is_plain_name(name) and not _hidden_in(name):
            errors.append(
                f"Field '{field}' has a name that may only contain letters, digits, "
                f"'_' and '-': {name!r}"
            )

    # A value is written as a cell, as text. First on its line (a data
    # default in the first column), a value starting with '[' would start a
    # new section.
    values = []
    if isinstance(settings, dict):
        values += [("Settings", key, value) for key, value in settings.items()]
    if isinstance(data, dict):
        values += [("Data", key, value) for key, value in data.items()]
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

    # Validate ApplicationProfileVersion is PEP 440 compliant
    version_val = yaml_data.get("ApplicationProfileVersion")
    if version_val is not None and str(version_val).strip():
        try:
            Version(str(version_val))
        except InvalidVersion:
            errors.append(
                f"Field 'ApplicationProfileVersion' is not a valid PEP 440 version: '{version_val}'"
            )
    if isinstance(version_val, float):
        errors.append(_decimal_version("ApplicationProfileVersion"))

    # Dragen-specific required sections
    app_type = yaml_data.get("ApplicationType", "")
    if str(app_type).strip().lower() == "dragen":
        # A wrong shape is reported above; here only an empty value.
        if "Settings" not in yaml_data:
            errors.append("Missing required field 'Settings' (required for ApplicationType 'Dragen')")
        elif yaml_data["Settings"] is None:
            errors.append("Field 'Settings' must be a mapping")

        if "Data" not in yaml_data:
            errors.append("Missing required field 'Data' (required for ApplicationType 'Dragen')")
        elif yaml_data["Data"] is None:
            errors.append("Field 'Data' must be a mapping")

        if "DataFields" not in yaml_data:
            errors.append("Missing required field 'DataFields' (required for ApplicationType 'Dragen')")
        elif yaml_data["DataFields"] is None:
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
