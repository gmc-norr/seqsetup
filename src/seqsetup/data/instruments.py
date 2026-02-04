"""Instrument and flowcell specifications.

Configuration can come from two sources:
1. GitHub-synced instruments (preferred when available)
2. Local config/instruments.yaml file (fallback)

To sync instruments from GitHub, configure the repository in Admin > Profiles.
"""

import os
from enum import Enum
from pathlib import Path
from typing import Optional, TYPE_CHECKING

import yaml

if TYPE_CHECKING:
    from ..repositories.instrument_definition_repo import InstrumentDefinitionRepository


class ChemistryType(Enum):
    """Illumina sequencing chemistry types."""

    TWO_COLOR = "2-color"  # 2-channel SBS (various channel configurations)
    FOUR_COLOR = "4-color"  # 4-channel SBS - each base has distinct color


# Module-level reference to instrument definition repository (set at app startup)
_instrument_definition_repo: Optional["InstrumentDefinitionRepository"] = None
_synced_instruments_cache: Optional[dict] = None  # Cache synced instruments


def set_instrument_definition_repo(repo: "InstrumentDefinitionRepository") -> None:
    """Set the instrument definition repository for synced instruments.

    Call this at app startup to enable synced instrument support.
    """
    global _instrument_definition_repo, _synced_instruments_cache
    _instrument_definition_repo = repo
    _synced_instruments_cache = None  # Clear cache when repo changes


def clear_synced_instruments_cache() -> None:
    """Clear the synced instruments cache.

    Call this after a sync operation to pick up new instruments.
    """
    global _synced_instruments_cache
    _synced_instruments_cache = None


def _get_synced_instruments() -> dict:
    """Get synced instruments from database, with caching.

    Returns dict keyed by instrument name, or empty dict if no synced instruments.
    """
    global _synced_instruments_cache

    if _synced_instruments_cache is not None:
        return _synced_instruments_cache

    if _instrument_definition_repo is None:
        return {}

    try:
        instruments = _instrument_definition_repo.list_all()
        if instruments:
            _synced_instruments_cache = {
                inst.name: inst for inst in instruments
            }
            return _synced_instruments_cache
    except Exception:
        # Silently fall back to YAML if DB unavailable
        pass

    return {}


def has_synced_instruments() -> bool:
    """Check if synced instruments are available."""
    return bool(_get_synced_instruments())


# Find config file path relative to project root
def _find_config_path() -> Path:
    """Find the instruments.yaml config file."""
    # Try relative to this file's location (src/seqsetup/data/)
    module_dir = Path(__file__).parent

    # Go up to project root and look in config/
    project_root = module_dir.parent.parent.parent
    config_path = project_root / "config" / "instruments.yaml"

    if config_path.exists():
        return config_path

    # Fallback: check current working directory
    cwd_config = Path.cwd() / "config" / "instruments.yaml"
    if cwd_config.exists():
        return cwd_config

    # Fallback: check environment variable
    env_config = os.environ.get("INSTRUMENTS_CONFIG")
    if env_config:
        env_path = Path(env_config)
        if env_path.exists():
            return env_path

    raise FileNotFoundError(
        f"Could not find instruments.yaml config file. "
        f"Searched: {config_path}, {cwd_config}"
    )


def _load_config() -> dict:
    """Load instrument configuration from YAML file."""
    config_path = _find_config_path()
    with open(config_path) as f:
        return yaml.safe_load(f)


# Load configuration at module import time
_config: dict = {}
_instruments: dict = {}
_default_cycles: dict = {}
_index_cycle_options: list = []


def _initialize_config():
    """Initialize configuration from YAML file."""
    global _config, _instruments, _default_cycles, _index_cycle_options

    _config = _load_config()
    _instruments = _config.get("instruments", {})
    _default_cycles = _config.get("default_cycles", {})
    _index_cycle_options = _config.get("index_cycle_options", [8, 10, 12, 17, 24])


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


def reload_config():
    """Reload configuration from YAML file.

    Call this after modifying the config file to pick up changes
    without restarting the application.
    """
    _initialize_config()


def get_instrument_names() -> list[str]:
    """Get list of all configured instrument names.

    Returns synced instrument names if available, otherwise YAML names.
    """
    synced = _get_synced_instruments()
    if synced:
        return list(synced.keys())
    return list(_instruments.keys())


def get_instrument_config(name: str) -> Optional[dict]:
    """Get configuration for a specific instrument by name.

    Checks synced instruments first, falls back to YAML.
    """
    # Check synced instruments first
    synced = _get_synced_instruments()
    if synced and name in synced:
        inst = synced[name]
        # Convert to dict format expected by rest of module
        return _synced_instrument_to_config(inst)

    return _instruments.get(name)


def _synced_instrument_to_config(inst) -> dict:
    """Convert InstrumentDefinition to the dict format used internally."""
    return {
        "samplesheet_name": inst.samplesheet_name,
        "chemistry_type": inst.chemistry_type,
        "sbs_chemistry": inst.sbs_chemistry,
        "has_dragen_onboard": inst.has_dragen_onboard,
        "i5_read_orientation": inst.i5_read_orientation,
        "samplesheet_v2_i5_orientation": inst.samplesheet_v2_i5_orientation,
        "color_balance_enabled": inst.color_balance_enabled,
        "dye_channels": inst.dye_channels,
        "base_colors": inst.base_colors,
        "channel1_name": inst.channel1_name,
        "channel1_bases": inst.channel1_bases,
        "channel2_name": inst.channel2_name,
        "channel2_bases": inst.channel2_bases,
        "dark_base": inst.dark_base,
        "error_tendencies": inst.error_tendencies,
        "samplesheet_versions": inst.samplesheet_versions,
        "flowcells": {
            fc.name: {
                "lanes": fc.lanes,
                "reads": fc.reads,
                "reagent_kits": fc.reagent_kits,
                "description": fc.description,
            }
            for fc in inst.flowcells
        },
        "onboard_applications": {
            app.name: {"software_version": app.software_version}
            for app in inst.onboard_applications
        },
    }


def get_flowcells_for_instrument_name(name: str, instrument_config=None) -> dict:
    """Get available flowcells for an instrument by name.

    When instrument_config is provided and has custom flowcells for this
    instrument, returns those instead of YAML defaults.

    Returns dict keyed by flowcell name, each value has "lanes", "reads",
    "reagent_kits", and optionally "description".
    """
    # Check DB overrides first
    if instrument_config:
        custom = instrument_config.get_custom_flowcells(name)
        if custom:
            return {
                fc["name"]: {
                    "lanes": fc.get("lanes", 1),
                    "reads": fc.get("reads", 0),
                    "reagent_kits": fc.get("reagent_kits", []),
                }
                for fc in custom
            }

    config = get_instrument_config(name)
    if config:
        return config.get("flowcells", {})
    return {}


def get_flowcells_list_for_instrument_name(name: str, instrument_config=None) -> list[dict]:
    """Get flowcells as a list of dicts for an instrument.

    Returns list of {"name", "lanes", "reads", "reagent_kits"} dicts.
    When instrument_config has custom entries, returns those; otherwise
    converts YAML format to list format.
    """
    if instrument_config:
        custom = instrument_config.get_custom_flowcells(name)
        if custom:
            return custom

    config = get_instrument_config(name)
    if not config:
        return []

    yaml_flowcells = config.get("flowcells", {})
    return [
        {
            "name": fc_name,
            "lanes": fc_data.get("lanes", 1),
            "reads": fc_data.get("reads", 0),
            "reagent_kits": fc_data.get("reagent_kits", []),
        }
        for fc_name, fc_data in yaml_flowcells.items()
    ]


def get_reagent_kits_for_flowcell_by_name(
    instrument_name: str, flowcell_type: str, instrument_config=None
) -> list[int]:
    """Get available reagent kit cycles for a flowcell type."""
    flowcells = get_flowcells_for_instrument_name(instrument_name, instrument_config)
    if flowcell_type in flowcells:
        return flowcells[flowcell_type].get("reagent_kits", [])
    return []


def get_lanes_for_flowcell_by_name(
    instrument_name: str, flowcell_type: str, instrument_config=None
) -> int:
    """Get number of lanes for a flowcell type."""
    flowcells = get_flowcells_for_instrument_name(instrument_name, instrument_config)
    if flowcell_type in flowcells:
        return flowcells[flowcell_type].get("lanes", 1)
    return 1


def get_chemistry_type_by_name(name: str) -> ChemistryType:
    """Get the chemistry type for an instrument by name."""
    config = get_instrument_config(name)
    if config:
        chemistry_str = config.get("chemistry_type", "2-color")
        if chemistry_str == "4-color":
            return ChemistryType.FOUR_COLOR
        return ChemistryType.TWO_COLOR
    return ChemistryType.TWO_COLOR


def is_color_balance_enabled_by_name(name: str) -> bool:
    """Check if color balance analysis is enabled for an instrument by name."""
    config = get_instrument_config(name)
    if config:
        return config.get("color_balance_enabled", False)
    return False


def get_i5_read_orientation_by_name(name: str) -> str:
    """Get i5 (Index 2) read orientation for an instrument by name.

    Returns:
        "forward" - i5 is read as written in the sample sheet
        "reverse-complement" - i5 is read as the reverse complement
    """
    config = get_instrument_config(name)
    if config:
        return config.get("i5_read_orientation", "forward")
    return "forward"


def get_channel_config_by_name(name: str) -> Optional[dict]:
    """Get dye channel configuration for an instrument by name.

    Returns a dict with keys:
    - channel1_name: Name of the first dye channel (e.g. "Blue", "Red")
    - channel1_bases: List of bases that produce signal in channel 1
    - channel2_name: Name of the second dye channel (e.g. "Green")
    - channel2_bases: List of bases that produce signal in channel 2
    - dark_base: Base that produces no signal (e.g. "G")
    - sbs_chemistry: SBS chemistry group name

    Returns None for 4-color instruments or if channel data is not configured.
    """
    config = get_instrument_config(name)
    if not config:
        return None

    # Only 2-color instruments have channel configuration
    if config.get("chemistry_type") != "2-color":
        return None

    channel1_bases = config.get("channel1_bases")
    if not channel1_bases:
        return None

    return {
        "channel1_name": config.get("channel1_name", "Channel 1"),
        "channel1_bases": channel1_bases,
        "channel2_name": config.get("channel2_name", "Channel 2"),
        "channel2_bases": config.get("channel2_bases", []),
        "dark_base": config.get("dark_base", ""),
        "sbs_chemistry": config.get("sbs_chemistry", ""),
    }


def has_dragen_onboard_by_name(name: str) -> bool:
    """Check if an instrument has DRAGEN onboard hardware.

    Returns True for instruments with has_dragen_onboard: true in config.
    """
    config = get_instrument_config(name)
    if config:
        return config.get("has_dragen_onboard", False)
    return False


def get_onboard_applications_by_name(name: str, instrument_config=None) -> list[dict]:
    """Get onboard applications and their software versions for an instrument.

    Returns a list of dicts, each with "name" and "software_version" keys.
    Multiple entries with the same name but different versions are allowed.

    When instrument_config is provided and has entries for this instrument,
    the DB entries are the authoritative list. Otherwise, YAML defaults are
    converted to list format and returned.

    Args:
        name: Instrument name
        instrument_config: Optional InstrumentConfig with DB entries

    Returns:
        List of application entries. Empty list if instrument not found.
    """
    config = get_instrument_config(name)
    if not config:
        return []

    # If DB has entries for this instrument, use those
    if instrument_config:
        db_entries = instrument_config.get_onboard_applications(name)
        if db_entries:
            return db_entries

    # Convert YAML dict format to list format
    yaml_apps = config.get("onboard_applications", {})
    return [
        {"name": app_name, "software_version": app_config.get("software_version", "")}
        for app_name, app_config in yaml_apps.items()
    ]


def get_yaml_onboard_application_names(name: str) -> list[str]:
    """Get the application names defined in YAML for an instrument.

    Used to provide suggestions in the admin UI.
    """
    config = get_instrument_config(name)
    if not config:
        return []
    return list(config.get("onboard_applications", {}).keys())


def get_default_cycles(reagent_kit: int) -> dict:
    """Get default cycle configuration for a reagent kit."""
    # Convert reagent_kit to string for YAML key lookup
    cycles = _default_cycles.get(reagent_kit) or _default_cycles.get(str(reagent_kit))
    if cycles:
        return {
            "read1": cycles.get("read1", 150),
            "read2": cycles.get("read2", 150),
            "index1": cycles.get("index1", 10),
            "index2": cycles.get("index2", 10),
        }
    # Fallback defaults
    return {"read1": 151, "read2": 151, "index1": 10, "index2": 10}


def get_index_cycle_options() -> list[int]:
    """Get list of common index cycle options."""
    return _index_cycle_options.copy()


def get_enabled_instruments(instrument_config) -> list[dict]:
    """Get list of instruments filtered by admin visibility settings.

    Args:
        instrument_config: InstrumentConfig object from repository

    Returns:
        Filtered list of instrument dicts (same format as get_all_instruments).
        If no config exists (empty dict), returns all instruments.
    """
    all_instruments = get_all_instruments_with_custom(instrument_config)
    if not instrument_config.enabled_instruments:
        return all_instruments
    return [
        inst for inst in all_instruments
        if instrument_config.is_instrument_enabled(inst["name"])
    ]


def get_all_instruments_with_custom(instrument_config) -> list[dict]:
    """Get all instruments including custom ones from database.

    Args:
        instrument_config: InstrumentConfig object with custom instruments

    Returns:
        Combined list of YAML instruments and custom database instruments.
    """
    # Start with YAML-defined instruments
    yaml_instruments = get_all_instruments()

    if instrument_config is None:
        return yaml_instruments

    # Add custom instruments from database
    custom_instruments = instrument_config.get_custom_instruments()
    for custom in custom_instruments:
        # Check if this overrides a YAML instrument
        existing_idx = next(
            (i for i, inst in enumerate(yaml_instruments) if inst["name"] == custom.get("name")),
            None
        )
        if existing_idx is not None:
            # Replace YAML definition with custom
            yaml_instruments[existing_idx] = _format_custom_instrument(custom)
        else:
            # Add new custom instrument
            yaml_instruments.append(_format_custom_instrument(custom))

    return yaml_instruments


def _format_custom_instrument(custom: dict) -> dict:
    """Format a custom instrument dict for use in the system."""
    flowcells = custom.get("flowcells", [])
    return {
        "name": custom.get("name", ""),
        "platform": None,  # Custom instruments don't have enum platform
        "flowcells": [fc.get("name") for fc in flowcells],
        "chemistry_type": custom.get("chemistry_type", "2-color"),
        "color_balance_enabled": custom.get("color_balance_enabled", False),
        "onboard_applications": {},
        "has_dragen_onboard": custom.get("has_dragen_onboard", False),
        "is_custom": True,  # Flag to identify custom instruments
        "samplesheet_name": custom.get("samplesheet_name", custom.get("name", "")),
        "i5_read_orientation": custom.get("i5_read_orientation", "forward"),
        "samplesheet_v2_i5_orientation": custom.get("samplesheet_v2_i5_orientation", "forward"),
    }


def get_all_instruments() -> list[dict]:
    """Get list of all supported instruments with their flowcells.

    Uses synced instruments if available, otherwise falls back to YAML.

    Returns list of dicts with keys:
    - name: Display name of the instrument
    - platform: InstrumentPlatform enum value (for backwards compatibility, None for synced)
    - flowcells: List of flowcell type names
    - chemistry_type: "2-color" or "4-color"
    - color_balance_enabled: Whether color balance analysis is enabled
    """
    # Import here to avoid circular imports at module level
    from ..models.sequencing_run import InstrumentPlatform

    # Check for synced instruments first
    synced = _get_synced_instruments()
    if synced:
        # Build mapping from name to enum for compatibility
        name_to_platform = {p.value: p for p in InstrumentPlatform}

        result = []
        for name, inst in synced.items():
            platform = name_to_platform.get(name)  # May be None for new instruments
            result.append({
                "name": name,
                "platform": platform,
                "flowcells": [fc.name for fc in inst.flowcells],
                "chemistry_type": inst.chemistry_type,
                "color_balance_enabled": inst.color_balance_enabled,
                "onboard_applications": {
                    app.name: {"software_version": app.software_version}
                    for app in inst.onboard_applications
                },
                "has_dragen_onboard": inst.has_dragen_onboard,
                "is_synced": True,
                "samplesheet_name": inst.samplesheet_name,
                "i5_read_orientation": inst.i5_read_orientation,
                "samplesheet_v2_i5_orientation": inst.samplesheet_v2_i5_orientation,
            })
        return result

    # Fall back to YAML-based instruments
    # Build mapping from name to enum
    name_to_platform = {p.value: p for p in InstrumentPlatform}

    result = []
    for name, config in _instruments.items():
        flowcells = config.get("flowcells", {})
        # Only include instruments that have a corresponding enum
        platform = name_to_platform.get(name)
        if platform is None:
            continue
        result.append({
            "name": name,
            "platform": platform,
            "flowcells": list(flowcells.keys()),
            "chemistry_type": config.get("chemistry_type", "2-color"),
            "color_balance_enabled": config.get("color_balance_enabled", False),
            "onboard_applications": config.get("onboard_applications", {}),
            "has_dragen_onboard": config.get("has_dragen_onboard", False),
        })
    return result


# =============================================================================
# Legacy compatibility layer for InstrumentPlatform enum
# =============================================================================
# The code previously used an enum for instrument platforms. These functions
# provide backwards compatibility by mapping enum values to config names.

# Import here to avoid circular imports
from ..models.sequencing_run import InstrumentPlatform


def _platform_to_name(platform: InstrumentPlatform) -> str:
    """Convert InstrumentPlatform enum to config instrument name."""
    # The enum value is the display name used in the config
    return platform.value


def get_flowcells_for_instrument(platform: InstrumentPlatform, instrument_config=None) -> dict:
    """Get available flowcells for an instrument platform (legacy)."""
    return get_flowcells_for_instrument_name(_platform_to_name(platform), instrument_config)


def get_reagent_kits_for_flowcell(
    platform: InstrumentPlatform, flowcell_type: str, instrument_config=None
) -> list[int]:
    """Get available reagent kit cycles for a flowcell type (legacy)."""
    return get_reagent_kits_for_flowcell_by_name(
        _platform_to_name(platform), flowcell_type, instrument_config
    )


def get_lanes_for_flowcell(platform: InstrumentPlatform, flowcell_type: str, instrument_config=None) -> int:
    """Get number of lanes for a flowcell type (legacy)."""
    return get_lanes_for_flowcell_by_name(_platform_to_name(platform), flowcell_type, instrument_config)


def get_chemistry_type(platform: InstrumentPlatform) -> ChemistryType:
    """Get the chemistry type for an instrument platform (legacy)."""
    return get_chemistry_type_by_name(_platform_to_name(platform))


def is_two_color_chemistry(platform: InstrumentPlatform) -> bool:
    """Check if an instrument uses 2-color chemistry (legacy)."""
    return get_chemistry_type(platform) == ChemistryType.TWO_COLOR


def is_color_balance_enabled(platform: InstrumentPlatform) -> bool:
    """Check if color balance analysis is enabled for an instrument (legacy)."""
    return is_color_balance_enabled_by_name(_platform_to_name(platform))


def get_channel_config(platform: InstrumentPlatform) -> Optional[dict]:
    """Get dye channel configuration for an instrument platform (legacy)."""
    return get_channel_config_by_name(_platform_to_name(platform))


def get_i5_read_orientation(platform: InstrumentPlatform) -> str:
    """Get i5 (Index 2) read orientation for an instrument platform (legacy)."""
    return get_i5_read_orientation_by_name(_platform_to_name(platform))


def get_samplesheet_v2_i5_orientation(platform: InstrumentPlatform) -> str:
    """Get i5 orientation expected by BCL Convert for SampleSheet v2.

    This differs from the physical i5 read orientation for some instruments.
    For example, NovaSeq X physically reads i5 in reverse-complement, but
    BCL Convert expects forward i5 in the sample sheet.

    Returns:
        "forward" or "reverse-complement"
    """
    return get_samplesheet_v2_i5_orientation_by_name(_platform_to_name(platform))


def get_samplesheet_v2_i5_orientation_by_name(name: str) -> str:
    """Get i5 orientation expected by BCL Convert for SampleSheet v2 by instrument name.

    Falls back to i5_read_orientation if samplesheet_v2_i5_orientation is not set.

    Returns:
        "forward" or "reverse-complement"
    """
    config = get_instrument_config(name)
    if config:
        # Use explicit v2 orientation if set, otherwise fall back to physical orientation
        return config.get("samplesheet_v2_i5_orientation",
                          config.get("i5_read_orientation", "forward"))
    return "forward"


def get_samplesheet_versions(platform: InstrumentPlatform) -> list[int]:
    """Get supported samplesheet versions for an instrument platform.

    Returns list of supported versions (e.g. [1, 2] or [2]).
    Defaults to [2] if not specified in config.
    """
    config = get_instrument_config(_platform_to_name(platform))
    if config:
        return config.get("samplesheet_versions", [2])
    return [2]


def get_samplesheet_platform_name(platform: InstrumentPlatform) -> str:
    """Get the Illumina sample sheet format name for a platform.

    This returns the name format expected by Illumina sample sheets
    (e.g., "NovaSeqXSeries" instead of "NovaSeq X Series").

    Falls back to the platform display name if not configured.
    """
    config = get_instrument_config(_platform_to_name(platform))
    if config:
        return config.get("samplesheet_name", platform.value)
    return platform.value


def get_bclconvert_software_version(platform: InstrumentPlatform) -> Optional[str]:
    """Get the BCLConvert software version for a platform.

    Returns the software_version from the BCLConvert onboard_applications config,
    or None if not configured.
    """
    config = get_instrument_config(_platform_to_name(platform))
    if config:
        onboard_apps = config.get("onboard_applications", {})
        bclconvert = onboard_apps.get("BCLConvert", {})
        return bclconvert.get("software_version")
    return None


def get_onboard_applications(platform: InstrumentPlatform, instrument_config=None) -> list[dict]:
    """Get onboard applications for an instrument platform (legacy)."""
    return get_onboard_applications_by_name(_platform_to_name(platform), instrument_config)
