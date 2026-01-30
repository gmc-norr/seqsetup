"""Instrument visibility configuration model."""

from dataclasses import dataclass, field


@dataclass
class InstrumentConfig:
    """Configuration for which instruments are visible in run setup."""

    # Dictionary: instrument name -> enabled status
    enabled_instruments: dict[str, bool] = field(default_factory=dict)

    def is_instrument_enabled(self, instrument_name: str) -> bool:
        """Check if instrument is enabled. Defaults to True for backward compatibility."""
        return self.enabled_instruments.get(instrument_name, True)

    def set_instrument_enabled(self, instrument_name: str, enabled: bool) -> None:
        """Set instrument enabled status."""
        self.enabled_instruments[instrument_name] = enabled

    def to_dict(self) -> dict:
        """Convert to dictionary for storage."""
        return {"enabled_instruments": self.enabled_instruments}

    @classmethod
    def from_dict(cls, data: dict) -> "InstrumentConfig":
        """Create from dictionary."""
        return cls(enabled_instruments=data.get("enabled_instruments", {}))
