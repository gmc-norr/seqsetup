"""Instrument definition model for synced instruments from GitHub."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import uuid


@dataclass
class FlowcellDefinition:
    """Flowcell type definition."""

    name: str
    lanes: int = 1
    reads: int = 0
    reagent_kits: list[int] = field(default_factory=list)
    description: str = ""

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "lanes": self.lanes,
            "reads": self.reads,
            "reagent_kits": self.reagent_kits,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "FlowcellDefinition":
        """Create from dictionary."""
        return cls(
            name=data.get("name", ""),
            lanes=data.get("lanes", 1),
            reads=data.get("reads", 0),
            reagent_kits=data.get("reagent_kits", []),
            description=data.get("description", ""),
        )


@dataclass
class OnboardApplication:
    """Onboard application definition."""

    name: str
    software_version: str = ""

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "software_version": self.software_version,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "OnboardApplication":
        """Create from dictionary."""
        return cls(
            name=data.get("name", ""),
            software_version=data.get("software_version", ""),
        )


@dataclass
class InstrumentDefinition:
    """Instrument definition synced from GitHub.

    This model represents a complete instrument configuration including
    flowcells, chemistry settings, and onboard applications.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""  # Display name (e.g., "NovaSeq X Series")
    samplesheet_name: str = ""  # Name used in samplesheet (e.g., "NovaSeqXSeries")
    version: str = ""  # Version of the instrument definition (e.g., "1.0.0")

    # Chemistry settings
    chemistry_type: str = "2-color"  # "2-color" or "4-color"
    sbs_chemistry: str = ""  # Description (e.g., "Two-color SBS (Blue+Green, XLEAP)")
    has_dragen_onboard: bool = False

    # i5 orientation settings
    i5_read_orientation: str = "forward"  # "forward" or "reverse-complement"
    samplesheet_v2_i5_orientation: str = "forward"  # BCL Convert expectation

    # Color balance settings
    color_balance_enabled: bool = False
    dye_channels: list[str] = field(default_factory=list)  # e.g., ["Blue", "Green"]
    base_colors: dict = field(default_factory=dict)  # e.g., {"A": "Blue", "C": "Blue+Green", ...}
    channel1_name: str = ""
    channel1_bases: list[str] = field(default_factory=list)
    channel2_name: str = ""
    channel2_bases: list[str] = field(default_factory=list)
    dark_base: str = ""
    error_tendencies: str = ""

    # Samplesheet version support
    samplesheet_versions: list[int] = field(default_factory=lambda: [2])

    # Flowcells and applications
    flowcells: list[FlowcellDefinition] = field(default_factory=list)
    onboard_applications: list[OnboardApplication] = field(default_factory=list)

    # Sync metadata
    source_file: str = ""
    synced_at: Optional[datetime] = None
    enabled: bool = True  # Whether this instrument is available for use

    def to_dict(self) -> dict:
        """Convert to dictionary for MongoDB storage."""
        return {
            "id": self.id,
            "name": self.name,
            "samplesheet_name": self.samplesheet_name,
            "version": self.version,
            "chemistry_type": self.chemistry_type,
            "sbs_chemistry": self.sbs_chemistry,
            "has_dragen_onboard": self.has_dragen_onboard,
            "i5_read_orientation": self.i5_read_orientation,
            "samplesheet_v2_i5_orientation": self.samplesheet_v2_i5_orientation,
            "color_balance_enabled": self.color_balance_enabled,
            "dye_channels": self.dye_channels,
            "base_colors": self.base_colors,
            "channel1_name": self.channel1_name,
            "channel1_bases": self.channel1_bases,
            "channel2_name": self.channel2_name,
            "channel2_bases": self.channel2_bases,
            "dark_base": self.dark_base,
            "error_tendencies": self.error_tendencies,
            "samplesheet_versions": self.samplesheet_versions,
            "flowcells": [fc.to_dict() for fc in self.flowcells],
            "onboard_applications": [app.to_dict() for app in self.onboard_applications],
            "source_file": self.source_file,
            "synced_at": self.synced_at.isoformat() if self.synced_at else None,
            "enabled": self.enabled,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "InstrumentDefinition":
        """Create from dictionary (MongoDB storage)."""
        synced_at = data.get("synced_at")
        if isinstance(synced_at, str):
            synced_at = datetime.fromisoformat(synced_at)

        return cls(
            id=data.get("_id") or data.get("id", str(uuid.uuid4())),
            name=data.get("name", ""),
            samplesheet_name=data.get("samplesheet_name", ""),
            version=data.get("version", ""),
            chemistry_type=data.get("chemistry_type", "2-color"),
            sbs_chemistry=data.get("sbs_chemistry", ""),
            has_dragen_onboard=data.get("has_dragen_onboard", False),
            i5_read_orientation=data.get("i5_read_orientation", "forward"),
            samplesheet_v2_i5_orientation=data.get("samplesheet_v2_i5_orientation", "forward"),
            color_balance_enabled=data.get("color_balance_enabled", False),
            dye_channels=data.get("dye_channels", []),
            base_colors=data.get("base_colors", {}),
            channel1_name=data.get("channel1_name", ""),
            channel1_bases=data.get("channel1_bases", []),
            channel2_name=data.get("channel2_name", ""),
            channel2_bases=data.get("channel2_bases", []),
            dark_base=data.get("dark_base", ""),
            error_tendencies=data.get("error_tendencies", ""),
            samplesheet_versions=data.get("samplesheet_versions", [2]),
            flowcells=[FlowcellDefinition.from_dict(fc) for fc in data.get("flowcells", [])],
            onboard_applications=[OnboardApplication.from_dict(app) for app in data.get("onboard_applications", [])],
            source_file=data.get("source_file", ""),
            synced_at=synced_at,
            enabled=data.get("enabled", True),
        )

    @classmethod
    def from_yaml(cls, yaml_data: dict, source_file: str) -> "InstrumentDefinition":
        """Create from YAML data (GitHub sync).

        The YAML format matches the instruments.yaml structure where
        each instrument is a top-level key with its configuration nested inside.
        This method expects the instrument config dict directly (not the wrapper).

        Args:
            yaml_data: Dict containing instrument configuration
            source_file: Filename for tracking source

        Returns:
            InstrumentDefinition instance
        """
        # Parse flowcells
        flowcells = []
        flowcells_data = yaml_data.get("flowcells", {})
        if isinstance(flowcells_data, dict):
            for fc_name, fc_config in flowcells_data.items():
                flowcells.append(FlowcellDefinition(
                    name=fc_name,
                    lanes=fc_config.get("lanes", 1),
                    reads=fc_config.get("reads", 0),
                    reagent_kits=fc_config.get("reagent_kits", []),
                    description=fc_config.get("description", ""),
                ))

        # Parse onboard applications
        onboard_apps = []
        apps_data = yaml_data.get("onboard_applications", {})
        if isinstance(apps_data, dict):
            for app_name, app_config in apps_data.items():
                onboard_apps.append(OnboardApplication(
                    name=app_name,
                    software_version=app_config.get("software_version", "") if isinstance(app_config, dict) else "",
                ))

        return cls(
            name=yaml_data.get("name", ""),  # May be set by caller
            samplesheet_name=yaml_data.get("samplesheet_name", ""),
            version=yaml_data.get("version", ""),
            chemistry_type=yaml_data.get("chemistry_type", "2-color"),
            sbs_chemistry=yaml_data.get("sbs_chemistry", ""),
            has_dragen_onboard=yaml_data.get("has_dragen_onboard", False),
            i5_read_orientation=yaml_data.get("i5_read_orientation", "forward"),
            samplesheet_v2_i5_orientation=yaml_data.get("samplesheet_v2_i5_orientation", "forward"),
            color_balance_enabled=yaml_data.get("color_balance_enabled", False),
            dye_channels=yaml_data.get("dye_channels", []),
            base_colors=yaml_data.get("base_colors", {}),
            channel1_name=yaml_data.get("channel1_name", ""),
            channel1_bases=yaml_data.get("channel1_bases", []),
            channel2_name=yaml_data.get("channel2_name", ""),
            channel2_bases=yaml_data.get("channel2_bases", []),
            dark_base=yaml_data.get("dark_base", ""),
            error_tendencies=yaml_data.get("error_tendencies", ""),
            samplesheet_versions=yaml_data.get("samplesheet_versions", [2]),
            flowcells=flowcells,
            onboard_applications=onboard_apps,
            source_file=source_file,
            synced_at=datetime.now(),
        )

    def to_instruments_format(self) -> dict:
        """Convert to the format expected by instruments.py functions.

        This returns a dict compatible with the existing get_all_instruments()
        format for backward compatibility.
        """
        return {
            "name": self.name,
            "platform": None,  # Synced instruments don't use enum platform
            "flowcells": [fc.name for fc in self.flowcells],
            "chemistry_type": self.chemistry_type,
            "color_balance_enabled": self.color_balance_enabled,
            "onboard_applications": {
                app.name: {"software_version": app.software_version}
                for app in self.onboard_applications
            },
            "has_dragen_onboard": self.has_dragen_onboard,
            "is_synced": True,  # Flag to identify synced instruments
            "samplesheet_name": self.samplesheet_name,
            "i5_read_orientation": self.i5_read_orientation,
            "samplesheet_v2_i5_orientation": self.samplesheet_v2_i5_orientation,
            "samplesheet_versions": self.samplesheet_versions,
            # Additional fields for validation
            "sbs_chemistry": self.sbs_chemistry,
            "dye_channels": self.dye_channels,
            "base_colors": self.base_colors,
            "channel1_name": self.channel1_name,
            "channel1_bases": self.channel1_bases,
            "channel2_name": self.channel2_name,
            "channel2_bases": self.channel2_bases,
            "dark_base": self.dark_base,
            "error_tendencies": self.error_tendencies,
        }

    def get_flowcell(self, name: str) -> Optional[FlowcellDefinition]:
        """Get a flowcell by name."""
        for fc in self.flowcells:
            if fc.name == name:
                return fc
        return None
