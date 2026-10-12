"""Validators for index kit CSV data, dependent on index mode."""

import re
from dataclasses import dataclass, field

from packaging.version import InvalidVersion, Version

from ..models.index import IndexKit, IndexMode

# Valid DNA characters (IUPAC codes commonly used in index sequences)
_DNA_PATTERN = re.compile(r"^[ACGTNacgtn]+$")


@dataclass
class IndexValidationResult:
    """Result of validating an index kit."""

    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        return len(self.errors) == 0

    def add_error(self, message: str) -> None:
        self.errors.append(message)

    def add_warning(self, message: str) -> None:
        self.warnings.append(message)


class IndexValidator:
    """Validate parsed IndexKit data based on index mode."""

    @classmethod
    def validate(cls, kit: IndexKit) -> IndexValidationResult:
        """
        Validate an IndexKit based on its index mode.

        Args:
            kit: Parsed IndexKit to validate

        Returns:
            IndexValidationResult with any errors/warnings
        """
        result = IndexValidationResult()

        # Common validations
        cls._validate_kit_metadata(kit, result)
        cls._validate_index_cycles(kit, result)

        # Mode-specific validations
        if kit.index_mode == IndexMode.UNIQUE_DUAL:
            cls._validate_unique_dual(kit, result)
        elif kit.index_mode == IndexMode.COMBINATORIAL:
            cls._validate_combinatorial(kit, result)
        elif kit.index_mode == IndexMode.SINGLE:
            cls._validate_single(kit, result)

        return result

    @classmethod
    def _validate_kit_metadata(cls, kit: IndexKit, result: IndexValidationResult) -> None:
        """Validate common kit metadata."""
        if not kit.name or not kit.name.strip():
            result.add_error("Index kit name is required.")

        # Validate version follows semantic versioning (PEP 440)
        if kit.version:
            try:
                Version(kit.version)
            except InvalidVersion:
                result.add_error(
                    f"Version '{kit.version}' is not a valid semantic version. "
                    "Use formats like 1.0, 1.0.0, 2.1.3, etc."
                )

        # Validate adapter sequences if provided
        if kit.adapter_read1 and not _DNA_PATTERN.match(kit.adapter_read1):
            result.add_error(
                f"AdapterRead1 contains invalid characters: '{kit.adapter_read1}'. "
                "Only A, C, G, T, N are allowed."
            )
        if kit.adapter_read2 and not _DNA_PATTERN.match(kit.adapter_read2):
            result.add_error(
                f"AdapterRead2 contains invalid characters: '{kit.adapter_read2}'. "
                "Only A, C, G, T, N are allowed."
            )

    @classmethod
    def _validate_index_cycles(cls, kit: IndexKit, result: IndexValidationResult) -> None:
        """A slot's default index cycles must be the length of every index in
        it. The cycles read decide which bases the demultiplexer compares, so
        an index must have as many bases as the cycles read for it (spec
        2026-10-05 group A3, §4). A kit that says FEWER cycles than its
        indexes have bases makes Mark Ready refuse every run that uses it,
        naming each sample instead of the kit. One that says MORE is refused
        the same way except when the run's own index cycles cap the
        OverrideCycles back to the index length, and then the run passes —
        measured with 8-base indexes and a kit saying 10: a run reading 8
        index cycles passes, and runs reading 6, 10 or 12 do not. A slot with
        no indexes is not checked — no sample takes one from it.
        """
        for slot, cycles, lengths in (
            ("i7", kit.default_index1_cycles, cls._index_lengths(kit, 1)),
            ("i5", kit.default_index2_cycles, cls._index_lengths(kit, 2)),
        ):
            if cycles is None or not lengths:
                continue
            if lengths != {cycles}:
                shown = ", ".join(str(n) for n in sorted(lengths))
                result.add_error(
                    f"Index kit '{kit.name}': {slot} index cycles is {cycles}, but its "
                    f"{slot} indexes are {shown} bases long. An index is read over as "
                    f"many cycles as it has bases, so set it to the index's length or "
                    f"leave it empty."
                )

    @staticmethod
    def _index_lengths(kit: IndexKit, slot: int) -> set[int]:
        """The lengths of every index in the kit's i7 (slot 1) or i5 (slot 2),
        wherever they sit: on their own, or in a pair."""
        indexes = list(kit.i7_indexes if slot == 1 else kit.i5_indexes)
        for pair in kit.index_pairs:
            index = pair.index1 if slot == 1 else pair.index2
            if index is not None:
                indexes.append(index)
        return {len(index.sequence) for index in indexes if index.sequence}

    @classmethod
    def _validate_unique_dual(cls, kit: IndexKit, result: IndexValidationResult) -> None:
        """Validate unique dual index kit."""
        if not kit.index_pairs:
            result.add_error("Unique dual index kit must contain at least one index pair.")
            return

        seen_names: set[str] = set()
        seen_sequences: dict[tuple, str] = {}  # (i7_seq, i5_seq) -> first pair name

        for pair in kit.index_pairs:
            # Check pair name
            if not pair.name or not pair.name.strip():
                result.add_error("Each index pair must have a name.")
                continue

            # Check duplicate pair names
            if pair.name in seen_names:
                result.add_error(f"Duplicate index pair name: '{pair.name}'.")
            seen_names.add(pair.name)

            # Warn on duplicate SEQUENCES under different names — physically
            # indistinguishable indexes (likely a data-entry error). A warning,
            # not an error, since deliberate aliasing is occasionally valid.
            i7_seq = pair.index1.sequence if pair.index1 else None
            i5_seq = pair.index2.sequence if pair.index2 else None
            if i7_seq:
                key = (i7_seq, i5_seq)
                if key in seen_sequences and seen_sequences[key] != pair.name:
                    result.add_warning(
                        f"Pairs '{seen_sequences[key]}' and '{pair.name}' have identical "
                        f"index sequences; they are indistinguishable at demultiplexing."
                    )
                else:
                    seen_sequences.setdefault(key, pair.name)

            # Validate i7 (index1) - required
            if not pair.index1 or not pair.index1.sequence:
                result.add_error(f"Pair '{pair.name}': i7 (Index1) sequence is required.")
            elif not _DNA_PATTERN.match(pair.index1.sequence):
                result.add_error(
                    f"Pair '{pair.name}': i7 sequence '{pair.index1.sequence}' "
                    "contains invalid characters. Only A, C, G, T, N are allowed."
                )

            # Validate i5 (index2) - required for unique dual
            if not pair.index2 or not pair.index2.sequence:
                result.add_error(f"Pair '{pair.name}': i5 (Index2) sequence is required for unique dual mode.")
            elif not _DNA_PATTERN.match(pair.index2.sequence):
                result.add_error(
                    f"Pair '{pair.name}': i5 sequence '{pair.index2.sequence}' "
                    "contains invalid characters. Only A, C, G, T, N are allowed."
                )

        # Check consistent sequence lengths
        cls._check_consistent_lengths(kit, result)

        # Warn if kit has i7/i5 individual indexes (wrong structure for this mode)
        if kit.i7_indexes or kit.i5_indexes:
            result.add_warning(
                "Unique dual kit has individual i7/i5 indexes, which are unused in this mode."
            )

    @classmethod
    def _validate_combinatorial(cls, kit: IndexKit, result: IndexValidationResult) -> None:
        """Validate combinatorial index kit."""
        if not kit.i7_indexes:
            result.add_error("Combinatorial index kit must contain at least one i7 index.")

        if not kit.i5_indexes:
            result.add_error("Combinatorial index kit must contain at least one i5 index.")

        # Validate i7 indexes
        seen_i7: set[str] = set()
        seen_i7_seq: dict[str, str] = {}  # sequence -> first index name
        for idx in kit.i7_indexes:
            if not idx.name or not idx.name.strip():
                result.add_error("Each i7 index must have a name.")
                continue

            if idx.name in seen_i7:
                result.add_error(f"Duplicate i7 index name: '{idx.name}'.")
            seen_i7.add(idx.name)

            if idx.sequence:
                if idx.sequence in seen_i7_seq and seen_i7_seq[idx.sequence] != idx.name:
                    result.add_warning(
                        f"i7 indexes '{seen_i7_seq[idx.sequence]}' and '{idx.name}' have "
                        f"identical sequences; they are indistinguishable at demultiplexing."
                    )
                else:
                    seen_i7_seq.setdefault(idx.sequence, idx.name)

            if not idx.sequence:
                result.add_error(f"i7 index '{idx.name}': sequence is required.")
            elif not _DNA_PATTERN.match(idx.sequence):
                result.add_error(
                    f"i7 index '{idx.name}': sequence '{idx.sequence}' "
                    "contains invalid characters. Only A, C, G, T, N are allowed."
                )

        # Validate i5 indexes
        seen_i5: set[str] = set()
        seen_i5_seq: dict[str, str] = {}  # sequence -> first index name
        for idx in kit.i5_indexes:
            if not idx.name or not idx.name.strip():
                result.add_error("Each i5 index must have a name.")
                continue

            if idx.name in seen_i5:
                result.add_error(f"Duplicate i5 index name: '{idx.name}'.")
            seen_i5.add(idx.name)

            if idx.sequence:
                if idx.sequence in seen_i5_seq and seen_i5_seq[idx.sequence] != idx.name:
                    result.add_warning(
                        f"i5 indexes '{seen_i5_seq[idx.sequence]}' and '{idx.name}' have "
                        f"identical sequences; they are indistinguishable at demultiplexing."
                    )
                else:
                    seen_i5_seq.setdefault(idx.sequence, idx.name)

            if not idx.sequence:
                result.add_error(f"i5 index '{idx.name}': sequence is required.")
            elif not _DNA_PATTERN.match(idx.sequence):
                result.add_error(
                    f"i5 index '{idx.name}': sequence '{idx.sequence}' "
                    "contains invalid characters. Only A, C, G, T, N are allowed."
                )

        # Check consistent lengths within each group
        if kit.i7_indexes:
            i7_lengths = {idx.length for idx in kit.i7_indexes if idx.sequence}
            if len(i7_lengths) > 1:
                result.add_warning(
                    f"i7 indexes have inconsistent lengths: {sorted(i7_lengths)}."
                )

        if kit.i5_indexes:
            i5_lengths = {idx.length for idx in kit.i5_indexes if idx.sequence}
            if len(i5_lengths) > 1:
                result.add_warning(
                    f"i5 indexes have inconsistent lengths: {sorted(i5_lengths)}."
                )

        # Warn if kit has index pairs (wrong structure for this mode)
        if kit.index_pairs:
            result.add_warning(
                "Combinatorial kit has index pairs, which are unused in this mode."
            )

    @classmethod
    def _validate_single(cls, kit: IndexKit, result: IndexValidationResult) -> None:
        """Validate single index kit (i7 only)."""
        if not kit.i7_indexes:
            result.add_error("Single index kit must contain at least one i7 index.")

        # Validate i7 indexes
        seen_names: set[str] = set()
        for idx in kit.i7_indexes:
            if not idx.name or not idx.name.strip():
                result.add_error("Each i7 index must have a name.")
                continue

            if idx.name in seen_names:
                result.add_error(f"Duplicate i7 index name: '{idx.name}'.")
            seen_names.add(idx.name)

            if not idx.sequence:
                result.add_error(f"i7 index '{idx.name}': sequence is required.")
            elif not _DNA_PATTERN.match(idx.sequence):
                result.add_error(
                    f"i7 index '{idx.name}': sequence '{idx.sequence}' "
                    "contains invalid characters. Only A, C, G, T, N are allowed."
                )

        # Check consistent lengths
        if kit.i7_indexes:
            i7_lengths = {idx.length for idx in kit.i7_indexes if idx.sequence}
            if len(i7_lengths) > 1:
                result.add_warning(
                    f"i7 indexes have inconsistent lengths: {sorted(i7_lengths)}."
                )

        # Warn if i5 data is present
        if kit.i5_indexes:
            result.add_warning(
                "Single index kit has i5 indexes, which are unused in this mode."
            )

        if kit.index_pairs:
            result.add_warning(
                "Single index kit has index pairs, which are unused in this mode."
            )

    @classmethod
    def _check_consistent_lengths(cls, kit: IndexKit, result: IndexValidationResult) -> None:
        """Check that index sequences have consistent lengths within a unique dual kit."""
        if not kit.index_pairs:
            return

        i7_lengths: set[int] = set()
        i5_lengths: set[int] = set()

        for pair in kit.index_pairs:
            if pair.index1 and pair.index1.sequence:
                i7_lengths.add(pair.index1.length)
            if pair.index2 and pair.index2.sequence:
                i5_lengths.add(pair.index2.length)

        if len(i7_lengths) > 1:
            result.add_warning(
                f"i7 (Index1) sequences have inconsistent lengths: {sorted(i7_lengths)}."
            )
        if len(i5_lengths) > 1:
            result.add_warning(
                f"i5 (Index2) sequences have inconsistent lengths: {sorted(i5_lengths)}."
            )
