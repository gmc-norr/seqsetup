"""Instrument and flowcell specifications.

Configuration is loaded from config/instruments.yaml at module load time.
To add new instruments or modify settings, edit the YAML file.
"""

import os
from enum import Enum
from pathlib import Path
from typing import Optional

import yaml


class ChemistryType(Enum):
    """Illumina sequencing chemistry types."""

    TWO_COLOR = "2-color"  # 2-channel SBS (various channel configurations)
    FOUR_COLOR = "4-color"  # 4-channel SBS - each base has distinct color


# Find config file path relative to project root
def _find_config_path() -> Path:
    """Find the instruments.yaml config file."""
    # Try relative to this file's location (src/sequencing_run_setup/data/)
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
    """Get list of all configured instrument names."""
    return list(_instruments.keys())


def get_instrument_config(name: str) -> Optional[dict]:
    """Get configuration for a specific instrument by name."""
    return _instruments.get(name)


def get_flowcells_for_instrument_name(name: str) -> dict:
    """Get available flowcells for an instrument by name."""
    config = get_instrument_config(name)
    if config:
        return config.get("flowcells", {})
    return {}


def get_reagent_kits_for_flowcell_by_name(
    instrument_name: str, flowcell_type: str
) -> list[int]:
    """Get available reagent kit cycles for a flowcell type."""
    flowcells = get_flowcells_for_instrument_name(instrument_name)
    if flowcell_type in flowcells:
        return flowcells[flowcell_type].get("reagent_kits", [])
    return []


def get_lanes_for_flowcell_by_name(instrument_name: str, flowcell_type: str) -> int:
    """Get number of lanes for a flowcell type."""
    flowcells = get_flowcells_for_instrument_name(instrument_name)
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
    all_instruments = get_all_instruments()
    if not instrument_config.enabled_instruments:
        return all_instruments
    return [
        inst for inst in all_instruments
        if instrument_config.is_instrument_enabled(inst["name"])
    ]


def get_all_instruments() -> list[dict]:
    """Get list of all supported instruments with their flowcells.

    Returns list of dicts with keys:
    - name: Display name of the instrument
    - platform: InstrumentPlatform enum value (for backwards compatibility)
    - flowcells: List of flowcell type names
    - chemistry_type: "2-color" or "4-color"
    - color_balance_enabled: Whether color balance analysis is enabled
    """
    # Import here to avoid circular imports at module level
    from ..models.sequencing_run import InstrumentPlatform

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


def get_flowcells_for_instrument(platform: InstrumentPlatform) -> dict:
    """Get available flowcells for an instrument platform (legacy)."""
    return get_flowcells_for_instrument_name(_platform_to_name(platform))


def get_reagent_kits_for_flowcell(
    platform: InstrumentPlatform, flowcell_type: str
) -> list[int]:
    """Get available reagent kit cycles for a flowcell type (legacy)."""
    return get_reagent_kits_for_flowcell_by_name(
        _platform_to_name(platform), flowcell_type
    )


def get_lanes_for_flowcell(platform: InstrumentPlatform, flowcell_type: str) -> int:
    """Get number of lanes for a flowcell type (legacy)."""
    return get_lanes_for_flowcell_by_name(_platform_to_name(platform), flowcell_type)


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
