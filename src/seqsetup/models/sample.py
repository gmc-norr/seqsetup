"""Sample data model."""

import re
from dataclasses import dataclass, field
from typing import Any, Optional
import uuid

from .index import Index, IndexPair, IndexType


# Illumina override-cycle notation: Y (read), I (index), U (UMI), N (mask),
# digits (counts), `*` (remaining-cycles wildcard), `;` (segment separator).
# A comma is also tolerated for legacy stored values that used commas as
# segment separators.
_VALID_OVERRIDE_CYCLES_RE = re.compile(r'^[YIUN0-9*;,]*$')

# A per-read/per-index override PATTERN is a single segment (no ';'/',' joiner)
# in the same Y/I/U/N/digit/* alphabet — e.g. "Y*", "N2Y*", "U8Y*", "I8N2".
# ``\Z`` (not ``$``) so a trailing newline can't sneak past, per project convention.
_VALID_OVERRIDE_PATTERN_RE = re.compile(r'^[YIUN0-9*]*\Z')


@dataclass
class Sample:
    """A sequencing sample with assigned indexes."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    sample_id: str = ""  # User-provided sample identifier
    sample_name: str = ""
    project: str = ""
    test_id: str = ""  # Associated test identifier
    worksheet_id: str = ""  # Source worksheet ID (from LIMS import)
    lanes: list[int] = field(default_factory=list)  # Lane assignments (empty = all lanes)

    # Assigned index pair (for unique_dual mode)
    index_pair: Optional[IndexPair] = None

    # Individual indexes (for combinatorial/single mode)
    index1: Optional[Index] = None  # i7 index
    index2: Optional[Index] = None  # i5 index (combinatorial mode only)

    # Track which kit the assigned indexes came from
    index_kit_name: Optional[str] = None

    # Per-sample override cycles (if different from global)
    override_cycles: Optional[str] = None

    # Per-sample barcode mismatches (default: 1)
    barcode_mismatches_index1: Optional[int] = 1
    barcode_mismatches_index2: Optional[int] = 1

    # Effective index cycles for override cycles calculation.
    # If set, these override the actual sequence lengths when calculating override cycles.
    # Populated from kit defaults when index is assigned, but can be overridden per-sample.
    # None = use actual sequence length
    index1_cycles: Optional[int] = None  # Effective i7 length for override cycles
    index2_cycles: Optional[int] = None  # Effective i5 length for override cycles

    # Index override patterns resolved from kit defaults and run cycles.
    # Populated when indexes are assigned, using the effective index length and run index cycles.
    # Examples: "I10" (full match), "I8N2" (8bp read + 2 masked), "N10" (no index)
    # None = not yet computed
    index1_override_pattern: Optional[str] = None
    index2_override_pattern: Optional[str] = None

    # Read override patterns using Illumina override cycle notation with * wildcard.
    # Populated from kit defaults when index is assigned.
    # Uses Y (read), I (index), U (UMI), N (mask/skip) with * for remaining cycles.
    # Examples: "N2Y*" (skip 2, read rest), "U8Y*" (8 UMI then read), "Y*" (read all)
    # None = use default Y{cycles}
    read1_override_pattern: Optional[str] = None
    read2_override_pattern: Optional[str] = None

    # Analysis assignments (list of analysis IDs)
    analyses: list[str] = field(default_factory=list)

    # Additional metadata
    description: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        # All clamping is in ``__setattr__`` so it covers both construction
        # (dataclass-generated ``__init__`` uses setattr per field) and direct
        # attribute assignment from route handlers.
        pass

    def __setattr__(self, name: str, value: Any) -> None:
        """Enforce model invariants on every assignment — construction AND
        post-construction mutation.

        Dataclasses run ``__post_init__`` only at construction time, so
        attribute assignments after the object exists would otherwise bypass
        the checks below. Routes do ``sample.override_cycles = ...`` and
        ``sample.barcode_mismatches_index1 = ...`` directly; pushing the
        validation here is what makes the project's "self-validating on every
        assignment" Hard Rule actually true for this model.

        Invariants enforced (matches the previous ``__post_init__`` set):
          - ``barcode_mismatches_index1`` / ``barcode_mismatches_index2``
            clamped to [0, 3].
          - ``index1_cycles`` / ``index2_cycles`` clamped to >= 1.
          - ``lanes`` filtered to positive non-bool ints.
          - ``override_cycles`` uppercased + rejected if outside the
            override-notation alphabet.
          - ``description`` capped at 4096 chars; ``metadata`` rejected if
            not a dict (defense-in-depth: free-form fields could otherwise
            balloon the document).
          - Free-form string identifiers capped at 256.
        """
        if value is not None:
            if name in ("barcode_mismatches_index1", "barcode_mismatches_index2"):
                value = max(0, min(3, value))
            elif name in ("index1_cycles", "index2_cycles"):
                value = max(1, value)
            elif name == "override_cycles":
                value = self._normalize_override_cycles(value)
            elif name in (
                "read1_override_pattern", "read2_override_pattern",
                "index1_override_pattern", "index2_override_pattern",
            ) and isinstance(value, str):
                value = self._normalize_override_pattern(name, value)
            elif name == "lanes" and value:
                value = [
                    lane for lane in value
                    if isinstance(lane, int) and not isinstance(lane, bool) and lane > 0
                ]
            elif name == "description" and isinstance(value, str):
                value = value[:4096]
            elif name == "metadata":
                if not isinstance(value, dict):
                    raise ValueError(
                        "Sample.metadata must be a dict; got "
                        f"{type(value).__name__}"
                    )
            elif name in (
                "sample_id", "sample_name", "project", "test_id",
                "worksheet_id", "index_kit_name",
            ) and isinstance(value, str):
                value = value[:256]
        object.__setattr__(self, name, value)

    @staticmethod
    def _normalize_override_cycles(value: str) -> str:
        """Uppercase + reject any character outside the override-cycle alphabet.

        Free-form text would flow into the Sample Sheet and shift columns,
        so we refuse it at the model boundary regardless of ingest path.
        """
        upper = value.upper()
        if not _VALID_OVERRIDE_CYCLES_RE.match(upper):
            bad = sorted(set(upper) - set("YIUN0123456789*;,"))
            raise ValueError(
                f"Invalid characters in override_cycles "
                f"({''.join(repr(c) for c in bad)}). "
                f"Allowed: Y, I, U, N, digits, '*', ';', ','."
            )
        return upper

    @staticmethod
    def _normalize_override_pattern(name: str, value: str) -> str:
        """Uppercase + reject any character outside the single-segment override
        alphabet (Y/I/U/N/digits/*). A read/index override pattern shapes the
        OverrideCycles instruction emitted to the sequencer, so free-form text
        must be refused at the model boundary regardless of ingest path."""
        upper = value.upper()
        if not _VALID_OVERRIDE_PATTERN_RE.match(upper):
            bad = sorted(set(upper) - set("YIUN0123456789*"))
            raise ValueError(
                f"Invalid characters in {name} "
                f"({''.join(repr(c) for c in bad)}). "
                f"Allowed: Y, I, U, N, digits, '*'."
            )
        return upper

    @property
    def index1_sequence(self) -> Optional[str]:
        """Get index1 (i7) sequence if assigned."""
        if self.index_pair:
            return self.index_pair.index1_sequence
        if self.index1:
            return self.index1.sequence
        return None

    @property
    def index2_sequence(self) -> Optional[str]:
        """Get index2 (i5) sequence if assigned."""
        if self.index_pair:
            return self.index_pair.index2_sequence
        if self.index2:
            return self.index2.sequence
        return None

    @property
    def index1_name(self) -> Optional[str]:
        """Get index1 (i7) name if assigned."""
        if self.index_pair:
            return self.index_pair.index1.name
        if self.index1:
            return self.index1.name
        return None

    @property
    def index2_name(self) -> Optional[str]:
        """Get index2 (i5) name if assigned."""
        if self.index_pair and self.index_pair.index2:
            return self.index_pair.index2.name
        if self.index2:
            return self.index2.name
        return None

    @property
    def index1_well_position(self) -> Optional[str]:
        """Get index1 (i7) well position if assigned."""
        if self.index_pair:
            # For unique dual, use the pair's well position or the index's well position
            return self.index_pair.well_position or (self.index_pair.index1.well_position if self.index_pair.index1 else None)
        if self.index1:
            return self.index1.well_position
        return None

    @property
    def index2_well_position(self) -> Optional[str]:
        """Get index2 (i5) well position if assigned."""
        if self.index_pair:
            # For unique dual, use the pair's well position or the index's well position
            return self.index_pair.well_position or (self.index_pair.index2.well_position if self.index_pair.index2 else None)
        if self.index2:
            return self.index2.well_position
        return None

    @property
    def has_index(self) -> bool:
        """Check if sample has an index assigned (pair or individual i7)."""
        return self.index_pair is not None or self.index1 is not None

    @property
    def has_full_index(self) -> bool:
        """Check if sample has complete indexes (pair or both i7 and i5)."""
        if self.index_pair:
            return True
        # For single mode, having just index1 is complete
        # For combinatorial, we need both - but this depends on kit mode
        # This property returns True if we have index1 (can be refined based on kit mode)
        return self.index1 is not None

    def assign_index(self, index_pair: IndexPair) -> None:
        """Assign an index pair to this sample (unique_dual mode)."""
        self.index_pair = index_pair
        # Clear individual indexes when assigning a pair
        self.index1 = None
        self.index2 = None

    def assign_index1(self, index: Index) -> None:
        """Assign an i7 index to this sample (combinatorial/single mode)."""
        # The slot is authoritative: an i5 in the i7 (Index) column silently
        # misroutes reads at demultiplexing. Mirror IndexPair's enforcement
        # rather than trusting a caller-supplied slot choice.
        if index is not None and index.index_type != IndexType.I7:
            raise ValueError(
                f"assign_index1 requires an i7 index, got "
                f"index_type={index.index_type.value}"
            )
        self.index1 = index
        # Clear index pair when using individual indexes
        self.index_pair = None

    def assign_index2(self, index: Index) -> None:
        """Assign an i5 index to this sample (combinatorial mode)."""
        if index is not None and index.index_type != IndexType.I5:
            raise ValueError(
                f"assign_index2 requires an i5 index, got "
                f"index_type={index.index_type.value}"
            )
        self.index2 = index
        # Clear index pair when using individual indexes
        self.index_pair = None

    def clear_index(self) -> None:
        """Remove all assigned indexes from this sample."""
        self.index_pair = None
        self.index1 = None
        self.index2 = None
        self.index_kit_name = None
        self.override_cycles = None
        self.index1_override_pattern = None
        self.index2_override_pattern = None

    def clear_index1(self) -> None:
        """Remove the assigned i7 index from this sample."""
        self.index1 = None
        self.index1_override_pattern = None
        if not self.index2:
            self.index_kit_name = None
            self.override_cycles = None

    def clear_index2(self) -> None:
        """Remove the assigned i5 index from this sample."""
        self.index2 = None
        self.index2_override_pattern = None
        if not self.index1:
            self.index_kit_name = None

    @property
    def lanes_display(self) -> str:
        """Get a display string for assigned lanes."""
        if not self.lanes:
            return "All"
        return ",".join(str(lane) for lane in sorted(self.lanes))

    def to_dict(self) -> dict:
        """Convert to dictionary for MongoDB storage."""
        return {
            "id": self.id,
            "sample_id": self.sample_id,
            "sample_name": self.sample_name,
            "project": self.project,
            "test_id": self.test_id,
            "worksheet_id": self.worksheet_id,
            "lanes": list(self.lanes),
            "index_pair": self.index_pair.to_dict() if self.index_pair else None,
            "index1": self.index1.to_dict() if self.index1 else None,
            "index2": self.index2.to_dict() if self.index2 else None,
            "index_kit_name": self.index_kit_name,
            "override_cycles": self.override_cycles,
            "barcode_mismatches_index1": self.barcode_mismatches_index1,
            "barcode_mismatches_index2": self.barcode_mismatches_index2,
            "index1_cycles": self.index1_cycles,
            "index2_cycles": self.index2_cycles,
            "index1_override_pattern": self.index1_override_pattern,
            "index2_override_pattern": self.index2_override_pattern,
            "read1_override_pattern": self.read1_override_pattern,
            "read2_override_pattern": self.read2_override_pattern,
            "analyses": list(self.analyses),
            "description": self.description,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Sample":
        """Create from dictionary.

        Legacy-data recovery: ``override_cycles`` is now regex-enforced on
        every assignment. Historical records may contain values that were
        accepted under earlier (more permissive) code. Rather than make
        the entire run unloadable in that case, we catch the ``ValueError``
        on the field-specific assignment, log the corruption (so it leaves
        a forensic trail), drop it to ``None`` (the safe default that
        triggers auto-recomputation downstream), and continue. Routes that
        later overwrite the field still validate via ``__setattr__``.
        """
        # Handle backward compatibility: old 'lane' field -> new 'lanes' list
        lanes = data.get("lanes", [])
        if not lanes and data.get("lane") is not None:
            lanes = [data["lane"]]

        stored_override_cycles = data.get("override_cycles")
        try:
            override_cycles = stored_override_cycles
            if stored_override_cycles is not None:
                # Probe the invariant once so we can recover gracefully on
                # legacy bad data. ``_normalize_override_cycles`` raises on
                # any character outside the allowed alphabet.
                cls._normalize_override_cycles(stored_override_cycles)
        except ValueError:
            import logging
            logging.getLogger(__name__).warning(
                "Sample %r has invalid override_cycles %r in stored data; "
                "loading with override_cycles=None. Re-save the run to drop "
                "the corruption from the document.",
                data.get("id"), stored_override_cycles,
            )
            override_cycles = None

        def _recover_pattern(field_name):
            """Legacy override-PATTERN fields were stored without the grammar
            check now enforced in __setattr__; recover (drop to None + log)
            rather than make the whole run unloadable on a legacy bad value."""
            value = data.get(field_name)
            if value is None:
                return None
            try:
                cls._normalize_override_pattern(field_name, value)
                return value
            except ValueError:
                import logging
                logging.getLogger(__name__).warning(
                    "Sample %r has invalid %s %r in stored data; loading with "
                    "%s=None. Re-save the run to drop the corruption.",
                    data.get("id"), field_name, value, field_name,
                )
                return None

        return cls(
            id=data["id"],
            sample_id=data.get("sample_id", ""),
            sample_name=data.get("sample_name", ""),
            project=data.get("project", ""),
            test_id=data.get("test_id", ""),
            worksheet_id=data.get("worksheet_id", ""),
            lanes=lanes,
            index_pair=IndexPair.from_dict(data["index_pair"]) if data.get("index_pair") else None,
            index1=Index.from_dict(data["index1"]) if data.get("index1") else None,
            index2=Index.from_dict(data["index2"]) if data.get("index2") else None,
            index_kit_name=data.get("index_kit_name"),
            override_cycles=override_cycles,
            barcode_mismatches_index1=data["barcode_mismatches_index1"] if "barcode_mismatches_index1" in data else 1,
            barcode_mismatches_index2=data["barcode_mismatches_index2"] if "barcode_mismatches_index2" in data else 1,
            index1_cycles=data.get("index1_cycles"),
            index2_cycles=data.get("index2_cycles"),
            index1_override_pattern=_recover_pattern("index1_override_pattern"),
            index2_override_pattern=_recover_pattern("index2_override_pattern"),
            read1_override_pattern=_recover_pattern("read1_override_pattern"),
            read2_override_pattern=_recover_pattern("read2_override_pattern"),
            analyses=data.get("analyses", []),
            description=data.get("description", ""),
            metadata=data.get("metadata", {}),
        )
