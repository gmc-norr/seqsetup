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

    # List of custom instruments defined via admin UI
    # Each: {"name": str, "samplesheet_name": str, "chemistry_type": str,
    #        "has_dragen_onboard": bool, "i5_read_orientation": str,
    #        "color_balance_enabled": bool, ...}
    custom_instruments: list[dict] = field(default_factory=list)

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

    def get_custom_instruments(self) -> list[dict]:
        """Get list of custom instruments defined via admin UI."""
        return self.custom_instruments.copy()

    def add_custom_instrument(self, instrument: dict) -> None:
        """Add a custom instrument."""
        # Remove existing instrument with same name if present
        self.custom_instruments = [
            i for i in self.custom_instruments if i.get("name") != instrument.get("name")
        ]
        self.custom_instruments.append(instrument)

    def remove_custom_instrument(self, instrument_name: str) -> None:
        """Remove a custom instrument by name."""
        self.custom_instruments = [
            i for i in self.custom_instruments if i.get("name") != instrument_name
        ]

    def get_custom_instrument(self, instrument_name: str) -> dict | None:
        """Get a custom instrument by name."""
        for inst in self.custom_instruments:
            if inst.get("name") == instrument_name:
                return inst
        return None

    def to_dict(self) -> dict:
        """Convert to dictionary for storage."""
        return {
            "enabled_instruments": self.enabled_instruments,
            "onboard_applications": self.onboard_applications,
            "custom_flowcells": self.custom_flowcells,
            "custom_instruments": self.custom_instruments,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "InstrumentConfig":
        """Create from dictionary."""
        return cls(
            enabled_instruments=data.get("enabled_instruments", {}),
            onboard_applications=data.get("onboard_applications", {}),
            custom_flowcells=data.get("custom_flowcells", {}),
            custom_instruments=data.get("custom_instruments", []),
        )
