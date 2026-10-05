"""Instrument definition model for synced instruments from GitHub."""

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import uuid

from ..utils.clock import utcnow


class InstrumentRecordError(ValueError):
    """An instrument file or stored record that cannot be used. The message
    names the record and the problem (spec 2026-10-04 group A2, §1)."""


I5_READ_ORIENTATIONS = ("forward", "reverse-complement")
OLD_I5_KEYS = ("i5_read_orientation", "samplesheet_v2_i5_orientation")
OLD_I5_KEY_MESSAGE = (
    "Replaced by i5_workflows and runinfo_marks_i5_reversed; "
    "see Instruments in the admin guide"
)
_I5_WORKFLOW_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}")
_I5_WORKFLOW_NAME_RULE = (
    "A workflow name must be 1-64 characters: letters, digits, spaces, '.', '_' "
    "or '-', starting with a letter or digit"
)


def _problem_text(field_name: str, message: str, value: Optional[str] = None) -> str:
    """The text the instrument validator gives for one error."""
    if value is not None:
        return f"{field_name}: {message} (got: {value!r})"
    return f"{field_name}: {message}"


def _i5_workflow_entry_problems(name, orientation) -> list[tuple[str, Optional[str]]]:
    problems = []
    if not isinstance(name, str) or not _I5_WORKFLOW_NAME_RE.fullmatch(name):
        problems.append((_I5_WORKFLOW_NAME_RULE, str(name)))
    if orientation not in I5_READ_ORIENTATIONS:
        problems.append(
            ("i5_read_orientation must be forward or reverse-complement", str(orientation))
        )
    return problems


def _i5_workflows_problems(value) -> list[tuple[str, Optional[str]]]:
    """What is wrong with an ``i5_workflows`` value, as (message, value)."""
    if not isinstance(value, (list, tuple)) or not value:
        return [("Must be a non-empty list of workflows, the standard one first", None)]
    problems = []
    seen = set()
    for entry in value:
        if isinstance(entry, I5Workflow):
            name, orientation = entry.name, entry.i5_read_orientation
        elif isinstance(entry, dict) and set(entry) == {"name", "i5_read_orientation"}:
            name, orientation = entry["name"], entry["i5_read_orientation"]
        else:
            problems.append(
                ("Each workflow must have exactly the keys name and i5_read_orientation", None)
            )
            continue
        entry_problems = _i5_workflow_entry_problems(name, orientation)
        problems += entry_problems
        if not entry_problems:
            if name.lower() in seen:
                problems.append(("A workflow name is listed twice (ignoring case)", name))
            seen.add(name.lower())
    return problems


def i5_fact_problems(data: dict) -> list[tuple[str, str, Optional[str]]]:
    """The two i5 facts of an instrument file or stored record, and the old
    keys they replaced, as (field, message, value). The validator and the
    model both use this, so they accept and refuse the same inputs."""
    problems = [(key, OLD_I5_KEY_MESSAGE, None) for key in OLD_I5_KEYS if key in data]
    if "i5_workflows" not in data:
        problems.append((
            "i5_workflows",
            "Required: the instrument's i5 workflows (name and i5_read_orientation each), "
            "the standard one first",
            None,
        ))
    else:
        problems += [
            ("i5_workflows", message, value)
            for message, value in _i5_workflows_problems(data["i5_workflows"])
        ]
    if "runinfo_marks_i5_reversed" not in data:
        problems.append(("runinfo_marks_i5_reversed", "Required: true or false", None))
    elif not isinstance(data["runinfo_marks_i5_reversed"], bool):
        problems.append((
            "runinfo_marks_i5_reversed", "Must be true or false",
            str(data["runinfo_marks_i5_reversed"]),
        ))
    return problems


@dataclass(frozen=True)
class I5Workflow:
    """One way an instrument runs: its name and how it reads the i5 then."""

    name: str
    i5_read_orientation: str

    def __post_init__(self):
        problems = _i5_workflow_entry_problems(self.name, self.i5_read_orientation)
        if problems:
            raise ValueError(_problem_text("i5_workflows", *problems[0]))


def checked_i5_workflows(value) -> tuple[I5Workflow, ...]:
    """``i5_workflows`` checked as a whole: workflows or their mappings in, a
    tuple of frozen workflows out, so they cannot be changed in place."""
    problems = _i5_workflows_problems(value)
    if problems:
        raise ValueError(_problem_text("i5_workflows", *problems[0]))
    return tuple(
        entry if isinstance(entry, I5Workflow)
        else I5Workflow(entry["name"], entry["i5_read_orientation"])
        for entry in value
    )


def _record_name(data, fallback: str = "") -> str:
    name = data.get("name") if isinstance(data, dict) else None
    return str(name or fallback or "an instrument record")[:100]


def _refuse_bad_i5_facts(data: dict, record: str) -> None:
    problems = i5_fact_problems(data)
    if problems:
        raise InstrumentRecordError(
            f"{record}: " + "; ".join(_problem_text(*problem) for problem in problems)
        )


def checked_kit_cycle_limits(limits) -> dict[int, int]:
    """Check ``reagent_kit_max_cycles``: kit label -> most cycles allowed,
    all reads together. Labels may arrive as strings from MongoDB (BSON keys
    are strings). Raises ValueError for anything that is not a positive
    whole-number label with a whole-number limit no smaller than the label:
    this number decides whether a run's cycles fit its kit."""
    if not isinstance(limits, dict):
        raise ValueError(
            f"reagent_kit_max_cycles must be a mapping of kit label to cycles, got {limits!r}"
        )
    checked = {}
    for label, limit in limits.items():
        if isinstance(label, str) and label.isdigit():
            label = int(label)
        if (isinstance(label, bool) or not isinstance(label, int) or label <= 0
                or isinstance(limit, bool) or not isinstance(limit, int)
                or limit < label):
            raise ValueError(
                f"reagent_kit_max_cycles: {label!r}: {limit!r} is not a kit label "
                f"with a whole-number limit no smaller than the label"
            )
        checked[label] = limit
    return checked


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

    # The two i5 facts, with no defaults (spec 2026-10-04 group A2, §1): how
    # the instrument reads the i5 in each workflow (the first is the standard
    # one), and whether its RunInfo.xml marks a reversed i5 read.
    i5_workflows: tuple[I5Workflow, ...] = field(kw_only=True)
    runinfo_marks_i5_reversed: bool = field(kw_only=True)

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

    # Most cycles each reagent kit allows (kit label -> cycles, all reads
    # together), entered by the lab from the kit's documentation. A kit
    # without a number is not checked.
    reagent_kit_max_cycles: dict[int, int] = field(default_factory=dict)

    # Sync metadata
    source_file: str = ""
    synced_at: Optional[datetime] = None
    enabled: bool = True  # Whether this instrument is available for use

    # Validated enums — string fields used by validators via equality. Keeping
    # them as plain ``str`` for serialization simplicity, but enforced on every
    # assignment so a future caller can't silently store "5-color" and have
    # the color-balance checks silently mis-classify the instrument.
    _ALLOWED_CHEMISTRY_TYPES = ("2-color", "4-color")

    def __setattr__(self, name, value):
        if name == "chemistry_type" and value not in self._ALLOWED_CHEMISTRY_TYPES:
            raise ValueError(
                f"InstrumentDefinition.chemistry_type must be one of "
                f"{self._ALLOWED_CHEMISTRY_TYPES}, got {value!r}"
            )
        if name == "i5_workflows":
            value = checked_i5_workflows(value)
        if name == "runinfo_marks_i5_reversed" and not isinstance(value, bool):
            raise ValueError(
                _problem_text("runinfo_marks_i5_reversed", "Must be true or false", str(value))
            )
        if name == "reagent_kit_max_cycles":
            value = checked_kit_cycle_limits(value)
        object.__setattr__(self, name, value)

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
            "i5_workflows": [
                {"name": w.name, "i5_read_orientation": w.i5_read_orientation}
                for w in self.i5_workflows
            ],
            "runinfo_marks_i5_reversed": self.runinfo_marks_i5_reversed,
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
            "reagent_kit_max_cycles": {
                str(label): limit for label, limit in self.reagent_kit_max_cycles.items()
            },
            "source_file": self.source_file,
            "synced_at": self.synced_at.isoformat() if self.synced_at else None,
            "enabled": self.enabled,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "InstrumentDefinition":
        """Create from dictionary (MongoDB storage). Raises
        InstrumentRecordError, naming the record, for a record that lacks a
        fact, carries an old key, or cannot be built (spec 2026-10-04 group
        A2, §1): a damaged record never escapes as another error."""
        record = _record_name(data)
        _refuse_bad_i5_facts(data, record)
        try:
            return cls._from_stored(data)
        except (ValueError, TypeError, KeyError, AttributeError) as e:
            raise InstrumentRecordError(f"{record}: {e}") from e

    @classmethod
    def _from_stored(cls, data: dict) -> "InstrumentDefinition":
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
            i5_workflows=data["i5_workflows"],
            runinfo_marks_i5_reversed=data["runinfo_marks_i5_reversed"],
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
            reagent_kit_max_cycles=data.get("reagent_kit_max_cycles") or {},
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

        Raises:
            InstrumentRecordError: naming the instrument, for a file that
                lacks a fact, carries an old key, or cannot be built.
        """
        record = _record_name(yaml_data, source_file)
        _refuse_bad_i5_facts(yaml_data, record)
        try:
            return cls._from_file(yaml_data, source_file)
        except (ValueError, TypeError, KeyError, AttributeError) as e:
            raise InstrumentRecordError(f"{record}: {e}") from e

    @classmethod
    def _from_file(cls, yaml_data: dict, source_file: str) -> "InstrumentDefinition":
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
            i5_workflows=yaml_data["i5_workflows"],
            runinfo_marks_i5_reversed=yaml_data["runinfo_marks_i5_reversed"],
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
            reagent_kit_max_cycles=yaml_data.get("reagent_kit_max_cycles") or {},
            source_file=source_file,
            synced_at=utcnow(),
        )

    def get_flowcell(self, name: str) -> Optional[FlowcellDefinition]:
        """Get a flowcell by name."""
        for fc in self.flowcells:
            if fc.name == name:
                return fc
        return None
