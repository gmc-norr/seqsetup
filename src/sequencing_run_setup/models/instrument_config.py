"""Instrument visibility configuration model."""

from dataclasses import dataclass, field


@dataclass
class InstrumentConfig:
    """Configuration for which instruments are visible in run setup."""

    # Dictionary: instrument name -> enabled status
    enabled_instruments: dict[str, bool] = field(default_factory=dict)

    # Dictionary: instrument name -> list of {"name": str, "software_version": str}
    # Multiple entries with the same name but different versions are allowed.
    onboard_applications: dict[str, list[dict]] = field(default_factory=dict)

    # Dictionary: instrument name -> list of flowcell dicts
    # Each: {"name": str, "lanes": int, "reads": int, "reagent_kits": list[int]}
    # When set, overrides YAML defaults for the instrument.
    custom_flowcells: dict[str, list[dict]] = field(default_factory=dict)

    def is_instrument_enabled(self, instrument_name: str) -> bool:
        """Check if instrument is enabled. Defaults to True for backward compatibility."""
        return self.enabled_instruments.get(instrument_name, True)

    def set_instrument_enabled(self, instrument_name: str, enabled: bool) -> None:
        """Set instrument enabled status."""
        self.enabled_instruments[instrument_name] = enabled

    def get_onboard_applications(self, instrument_name: str) -> list[dict]:
        """Get onboard application entries for an instrument.

        Returns list of dicts with "name" and "software_version" keys,
        or empty list if no entries configured.
        """
        return self.onboard_applications.get(instrument_name, [])

    def set_onboard_applications(self, instrument_name: str, apps: list[dict]) -> None:
        """Set onboard application entries for an instrument."""
        self.onboard_applications[instrument_name] = apps

    def get_custom_flowcells(self, instrument_name: str) -> list[dict]:
        """Get custom flowcell entries for an instrument.

        Returns list of dicts with "name", "lanes", "reads", "reagent_kits" keys,
        or empty list if no custom entries configured.
        """
        return self.custom_flowcells.get(instrument_name, [])

    def set_custom_flowcells(self, instrument_name: str, flowcells: list[dict]) -> None:
        """Set custom flowcell entries for an instrument."""
        self.custom_flowcells[instrument_name] = flowcells

    def to_dict(self) -> dict:
        """Convert to dictionary for storage."""
        return {
            "enabled_instruments": self.enabled_instruments,
            "onboard_applications": self.onboard_applications,
            "custom_flowcells": self.custom_flowcells,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "InstrumentConfig":
        """Create from dictionary."""
        return cls(
            enabled_instruments=data.get("enabled_instruments", {}),
            onboard_applications=data.get("onboard_applications", {}),
            custom_flowcells=data.get("custom_flowcells", {}),
        )
