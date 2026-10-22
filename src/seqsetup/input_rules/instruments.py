"""The rulebook for instrument files: the synced ones (one instrument per file,
or several under ``instruments:``) and the local ``config/instruments.yaml``
(docs/design/2026-10-18-input-rules-design.md, "Step 1").

An instrument file decides a run's lanes, its colour balance check and the i5
direction of every Sample Sheet. Every key is named here; an unknown one is
refused (``lane: 2`` once gave a flow cell one lane, ``colour_balance_enabled``
left the colour balance check off). A fact that changes a sheet or a check
must be written out. The one named exception is ``samplesheet_versions``,
which may be left out and then means ``[2]``, as the admin guide says.

Every whole number has the range its consumers accept unchanged:
- a flow cell's ``lanes``: 1-8. The run page draws a box per lane, and no
  Illumina flow cell has more than eight lanes.
- a reagent kit's cycles (``reagent_kits``, the keys of
  ``reagent_kit_max_cycles`` and ``default_cycles``): 1-2000, the reagent kit
  field's own range (``routes/runs.py``: ``max(1, min(..., 2000))``); a kit
  above it would be read as 2000.
- ``default_cycles``: read 1 from 1, read 2 and both indexes from 0, all to 600
  -- what a run's cycle fields accept (``routes/runs.py`` ``_MAX_CYCLES``);
  read 2 = 0 is a single-end run.
- ``index_cycle_options``: 1-600, an index cycle count a run accepts.
- a flow cell's ``reads`` and a kit's most cycles: up to MongoDB's 64-bit
  limit (``STORAGE_MAX_INT``); nothing else reads them as a bound.
"""

from typing import Annotated, Literal, Optional

from pydantic import AfterValidator, Field

from ..models.sequencing_run import InstrumentPlatform
from ..models.instrument_definition import (
    _I5_WORKFLOW_NAME_RE,
    _I5_WORKFLOW_NAME_RULE,
    I5_READ_ORIENTATIONS,
    OLD_I5_KEY_MESSAGE,
    OLD_I5_KEYS,
    InstrumentDefinition,
)
from .base import (
    ExactName256,
    IlluminaApplicationName,
    Label,
    PlainName,
    PlainVersion,
    StrictRules,
    Text256,
    whole,
)
from .check import CheckResult, Finding, check_data, reader_refusal
from .reader import read_yaml

# The instruments SeqSetup has a place for. An instrument file naming another
# one was stored and counted by the sync, then skipped by get_all_instruments
# with a log line only -- and since synced records are the only ones that
# count, the instrument the file was meant to describe was gone too.
PLATFORM_NAMES = tuple(p.value for p in InstrumentPlatform)

BASES = ("A", "C", "G", "T")
USUAL_DYE_CHANNELS = ("Blue", "Green", "Red", "Yellow")
COLOUR_FIELDS = ("dye_channels", "base_colors", "channel1_name", "channel1_bases",
                 "channel2_name", "channel2_bases", "dark_base")
RETIRED_KEYS = {key: OLD_I5_KEY_MESSAGE for key in OLD_I5_KEYS}

KIT_CYCLES = whole(1, 2000)


def _distinct(items: list) -> list:
    seen = set()
    for item in items:
        if item in seen:
            raise ValueError(f"lists {item} twice")
        seen.add(item)
    return items


def _workflow_name(value: str) -> str:
    # The name is picked on the run page and decides which way every i5 is
    # written, so _I5_WORKFLOW_NAME_RE refuses a name ending in a space too.
    if not _I5_WORKFLOW_NAME_RE.fullmatch(value):
        raise ValueError(_I5_WORKFLOW_NAME_RULE)
    return value


Base = Literal[BASES]


class FlowcellRules(StrictRules):
    lanes: whole(1, 8)
    reagent_kits: Annotated[list[KIT_CYCLES], AfterValidator(_distinct)]
    reads: whole(0) = 0
    description: Label = ""


class OnboardApplicationRules(StrictRules):
    software_version: PlainVersion


class I5WorkflowRules(StrictRules):
    name: Annotated[str, AfterValidator(_workflow_name)]
    i5_read_orientation: Literal[I5_READ_ORIENTATIONS]


class InstrumentRules(StrictRules):
    """One instrument. ``name`` and ``version`` are required or not by the
    document that holds it (see the checks below)."""

    # A name people pick: the instrument's own name, and each flow cell's.
    name: Optional[ExactName256] = None
    samplesheet_name: PlainName
    version: Optional[Text256] = None
    chemistry_type: Literal[InstrumentDefinition._ALLOWED_CHEMISTRY_TYPES]
    sbs_chemistry: Label = ""
    has_dragen_onboard: bool
    i5_workflows: Annotated[list[I5WorkflowRules], Field(min_length=1)]
    runinfo_marks_i5_reversed: bool
    color_balance_enabled: bool
    dye_channels: Optional[list[Text256]] = None
    base_colors: Optional[dict[Base, Text256]] = None
    channel1_name: Optional[Text256] = None
    channel1_bases: Optional[list[Base]] = None
    channel2_name: Optional[Text256] = None
    channel2_bases: Optional[list[Base]] = None
    dark_base: Optional[Base] = None
    error_tendencies: Label = ""
    samplesheet_versions: Annotated[
        list[whole(1, 2)], Field(min_length=1), AfterValidator(_distinct)
    ] = [2]
    onboard_applications: dict[IlluminaApplicationName, OnboardApplicationRules]
    flowcells: Annotated[dict[ExactName256, FlowcellRules], Field(min_length=1)]
    reagent_kit_max_cycles: dict[KIT_CYCLES, whole(1)] = {}


class InstrumentsFileRules(StrictRules):
    """A synced file holding several instruments under ``instruments:``,
    and nothing beside it."""

    instruments: Annotated[dict[ExactName256, InstrumentRules], Field(min_length=1)]


class CycleDefaultsRules(StrictRules):
    read1: whole(1, 600)
    read2: whole(0, 600)
    index1: whole(0, 600)
    index2: whole(0, 600)


class LocalInstrumentsFileRules(StrictRules):
    """The local ``config/instruments.yaml``."""

    instruments: Annotated[dict[ExactName256, InstrumentRules], Field(min_length=1)]
    default_cycles: Annotated[dict[KIT_CYCLES, CycleDefaultsRules], Field(min_length=1)]
    index_cycle_options: Annotated[
        list[whole(1, 600)], Field(min_length=1), AfterValidator(_distinct)
    ]


def _colour_findings(instrument: "InstrumentRules", at: tuple) -> list[Finding]:
    """``base_colors``, the two channels and ``dark_base`` describe one
    chemistry, so they must agree. ``dark_base`` decides the GG dark-start
    error and each channel's bases are what the colour balance counts: a file
    saying G is Dark while ``dark_base`` says T switched that error off, and a
    base listed twice in a channel would be counted twice."""
    colours = instrument.base_colors
    names = (instrument.channel1_name, instrument.channel2_name)
    channels = (instrument.channel1_bases, instrument.channel2_bases)
    if colours is None or None in names or None in channels or instrument.dark_base is None:
        return []

    found, lit = [], {}
    for base, colour in colours.items():
        parts = [part.strip() for part in colour.split("+")]
        unknown = [part for part in parts
                   if part not in names and part.lower() != "dark"]
        if unknown:
            found.append(Finding(
                (*at, "base_colors", base),
                f"names {unknown[0]!r}, which is neither channel1_name "
                f"({names[0]!r}) nor channel2_name ({names[1]!r}) nor Dark",
            ))
            continue
        lit[base] = (names[0] in parts, names[1] in parts,
                     any(part.lower() == "dark" for part in parts))
    if found:
        return found

    for which, (key, name) in enumerate((("channel1_bases", names[0]),
                                         ("channel2_bases", names[1]))):
        want = sorted(base for base, flags in lit.items() if flags[which])
        if sorted(channels[which]) != want:
            found.append(Finding(
                (*at, key),
                f"must be the bases base_colors lights in {name!r} "
                f"({', '.join(want) if want else 'none'}), each once",
            ))
    dark = sorted(base for base, flags in lit.items() if flags[2])
    if len(dark) > 1:
        found.append(Finding(
            (*at, "base_colors"),
            f"calls more than one base Dark ({', '.join(dark)}); a 2-color chemistry "
            "has one dark base",
        ))
    elif dark != [instrument.dark_base]:
        found.append(Finding(
            (*at, "dark_base"),
            f"must be the base base_colors calls Dark ({dark[0]})" if dark
            else "names a base base_colors does not call Dark",
        ))
    for base, flags in lit.items():
        if flags[2] and (flags[0] or flags[1]):
            found.append(Finding((*at, "base_colors", base),
                                 "is Dark and lit in a channel at once"))
    return found


def _instrument_findings(instrument: InstrumentRules, at: tuple, *, needs_name: bool,
                         needs_version: bool, map_key: Optional[str] = None) -> list[Finding]:
    found = []
    if needs_name and instrument.name is None:
        found.append(Finding((*at, "name"), "is required"))
    if map_key is not None and instrument.name is not None and instrument.name != map_key:
        found.append(Finding(
            (*at, "name"),
            f"must be the name it is listed under ({map_key!r}), or left out",
        ))
    if needs_version and instrument.version is None:
        found.append(Finding((*at, "version"), "is required"))
    named = map_key if map_key is not None else instrument.name
    if named is not None and named not in PLATFORM_NAMES:
        found.append(Finding(
            (*at,) if map_key is not None else (*at, "name"),
            f"is not one of the instruments SeqSetup has ({', '.join(PLATFORM_NAMES)})",
        ))

    written = instrument.model_fields_set
    colour_problems = len(found)
    for key in COLOUR_FIELDS:
        present = key in written
        value = getattr(instrument, key)
        if instrument.chemistry_type == "4-color":
            if present:
                found.append(Finding((*at, key), "is not read on a 4-color instrument: remove it"))
        elif instrument.color_balance_enabled and value is None:
            found.append(Finding(
                (*at, key), "is required when colour balance is on (color_balance_enabled: true)"))
        elif instrument.color_balance_enabled and isinstance(value, (list, dict)) and not value:
            # An empty list once switched the dark-cycle check off unseen.
            found.append(Finding(
                (*at, key), "must not be empty when colour balance is on (color_balance_enabled: true)"))
        elif present and value is None:
            found.append(Finding((*at, key), "needs a value"))
    if instrument.chemistry_type == "4-color" and instrument.color_balance_enabled:
        # A 4-color instrument states no channels and no dark base, so the
        # colour balance and dark-cycle checks would run on made-up ones.
        found.append(Finding(
            (*at, "color_balance_enabled"),
            "must be false on a 4-color instrument: the colour balance and dark-cycle "
            "checks need two channels and a dark base, which only a 2-color instrument states",
        ))
    if instrument.chemistry_type == "2-color" and instrument.base_colors is not None:
        if set(instrument.base_colors) != set(BASES):
            found.append(Finding((*at, "base_colors"), "must name each of A, C, G and T once"))
        elif len(found) == colour_problems:
            # Only once every colour fact is there and not empty: the findings
            # above already name a missing or empty one.
            found.extend(_colour_findings(instrument, at))

    seen = set()
    for index, workflow in enumerate(instrument.i5_workflows):
        if workflow.name.lower() in seen:
            found.append(Finding(
                (*at, "i5_workflows", index, "name"),
                f"lists the workflow {workflow.name!r} twice (ignoring case)",
            ))
        seen.add(workflow.name.lower())

    for label, limit in instrument.reagent_kit_max_cycles.items():
        if limit < label:
            found.append(Finding(
                (*at, "reagent_kit_max_cycles", label),
                f"must be at least the kit's own cycles ({label})",
            ))
    return found


def _instrument_warnings(instrument: InstrumentRules, at: tuple) -> list[Finding]:
    found = []
    for index, channel in enumerate(instrument.dye_channels or []):
        if channel not in USUAL_DYE_CHANNELS:
            found.append(Finding(
                (*at, "dye_channels", index),
                "is not a usual dye channel name (" + ", ".join(USUAL_DYE_CHANNELS) + ")",
            ))
    offered = {kit for flowcell in instrument.flowcells.values() for kit in flowcell.reagent_kits}
    for label in instrument.reagent_kit_max_cycles:
        if label not in offered:
            found.append(Finding((*at, "reagent_kit_max_cycles", label),
                                 "names a reagent kit no flow cell offers"))
    return found


def _listed(value) -> list[tuple[tuple, str, InstrumentRules]]:
    """(path, map key, instrument) for each instrument a document holds."""
    return [(("instruments", name), name, instrument) for name, instrument in value.instruments.items()]


def check_synced_instrument_file(text: str, file: str) -> CheckResult:
    """Check one instrument file from the configuration sync: one instrument
    at the top level, or several under ``instruments:`` and nothing else.
    Every synced instrument states its ``version``."""
    read = read_yaml(text, file, values_safe=True)
    if read.problems:
        return reader_refusal(read.problems, InstrumentRules)
    if isinstance(read.data, dict) and "instruments" in read.data:
        return check_data(
            read.data, read.locations, file, InstrumentsFileRules,
            cross_checks=[lambda value: [
                finding for at, key, instrument in _listed(value)
                for finding in _instrument_findings(
                    instrument, at, needs_name=False, needs_version=True, map_key=key)
            ]],
            warnings=lambda value: [
                finding for at, _key, instrument in _listed(value)
                for finding in _instrument_warnings(instrument, at)
            ],
            retired_keys=RETIRED_KEYS,
        )
    return check_data(
        read.data, read.locations, file, InstrumentRules,
        cross_checks=[lambda value: _instrument_findings(
            value, (), needs_name=True, needs_version=True)],
        warnings=lambda value: _instrument_warnings(value, ()),
        retired_keys=RETIRED_KEYS,
    )


def check_local_instruments_file(text: str, file: str) -> CheckResult:
    """Check the local instruments file. Its instruments carry no
    ``version``: the file is versioned with the installation."""
    read = read_yaml(text, file, values_safe=True)
    if read.problems:
        return reader_refusal(read.problems, LocalInstrumentsFileRules)
    return check_data(
        read.data, read.locations, file, LocalInstrumentsFileRules,
        cross_checks=[lambda value: [
            finding for at, key, instrument in _listed(value)
            for finding in _instrument_findings(
                instrument, at, needs_name=False, needs_version=False, map_key=key)
        ]],
        warnings=lambda value: [
            finding for at, _key, instrument in _listed(value)
            for finding in _instrument_warnings(instrument, at)
        ],
        retired_keys=RETIRED_KEYS,
    )


def definitions_from(value, file: str) -> list[InstrumentDefinition]:
    """The instruments a checked synced file describes, built from the
    checked value only (a fresh copy of every list and map in it)."""
    if isinstance(value, InstrumentsFileRules):
        entries = list(value.instruments.items())
    else:
        entries = [(value.name, value)]
    definitions = []
    for name, instrument in entries:
        data = instrument.model_dump(exclude_unset=True)
        data["name"] = name
        definitions.append(InstrumentDefinition.from_yaml(data, file))
    return definitions


def local_config(value: LocalInstrumentsFileRules) -> dict:
    """The checked local file as the plain data ``data/instruments.py``
    keeps: exactly the keys written, nothing added."""
    return value.model_dump(exclude_unset=True)


def duplicate_instruments(instruments: list[InstrumentDefinition]) -> list[str]:
    """Two instrument files may not give the same name or Sample Sheet name
    (spec 2026-10-04 group A2, §1). Needs no database: the sync and the
    settings command both use it."""
    problems = []
    for field_name in ("name", "samplesheet_name"):
        seen: dict[str, str] = {}
        for instrument in instruments:
            value = getattr(instrument, field_name)
            if value in seen:
                problems.append(
                    f"{seen[value]} and {instrument.source_file} both give {field_name} {value!r}"
                )
            else:
                seen[value] = instrument.source_file
    return problems
