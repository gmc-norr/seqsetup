"""Read one index kit YAML file from the configuration sync.

The file goes through the input rules: the reader (one plain spelling per
value, no tags or anchors, a key given twice refused, every problem with its
line and column) and the one canonical kit rulebook
(``input_rules/kits.py``). See docs/design/2026-10-18-input-rules-design.md,
"Step 3: index kit files, every format".
"""

import logging
from typing import Optional

from ..input_rules.check import CheckResult
from ..input_rules.kits import KitFileProblems, build_kit, check_index_kit_file
from ..models.index import IndexKit

logger = logging.getLogger(__name__)


class KitListsNotRead(ValueError):
    """Kept for callers outside this module: the rule it named -- an index
    list the file's own ``index_mode`` does not read -- is now one of the kit
    rulebook's checks, and ``KitFileProblems`` carries it with its line."""


class IndexKitSyncParser:
    """Check and build one synced index kit file.

    The sync YAML format is the canonical kit shape, the one
    ``IndexKitYamlExporter`` writes:

    ```yaml
    name: "Kit Name"            # required
    version: "1.0"              # required
    index_mode: unique_dual     # required: unique_dual | combinatorial | single
    description: "Description"
    comments: "Notes"
    is_fixed_layout: true
    adapter_read1: "SEQUENCE"
    adapter_read2: "SEQUENCE"
    default_index1_cycles: 8
    default_index2_cycles: 8
    default_read1_override: "Y*"
    default_read2_override: "Y*"

    # For unique_dual mode:
    index_pairs:
      - name: "Pair1"
        well_position: "A01"
        index1:
          name: "i7-name"
          sequence: "ATCGATCG"
        index2:
          name: "i5-name"
          sequence: "GCTAGCTA"

    # For combinatorial/single mode:
    i7_indexes:
      - name: "N701"
        sequence: "ATTACTCG"
        well_position: "A01"
    i5_indexes:  # Only for combinatorial mode
      - name: "S501"
        sequence: "TATAGCCT"
    ```
    """

    @classmethod
    def check(cls, yaml_content: str, source_file: str) -> CheckResult:
        """Every problem of the file, each with its line, and the checked
        value when there is none. The sync uses this and puts the problems on
        the Config Sync page and in its audit row; one exception could carry
        only the first."""
        return check_index_kit_file(yaml_content, source_file)

    @classmethod
    def parse(cls, yaml_content: str, source_file: str) -> Optional[IndexKit]:
        """The kit the file describes.

        ``None`` when the file could not be read at all -- it is empty, or it
        is not YAML -- as before. Anything the rules refuse raises
        ``KitFileProblems``, which lists every problem with its line, so the
        sync's refusal carries them to the Config Sync page. Before, a
        repeated key and an unread index list raised while a misspelt key, a
        missing name, version or mode and a value of the wrong kind were read
        as something else or dropped with only a log line.
        """
        result = cls.check(yaml_content, source_file)
        if result.ok:
            return build_kit(result.value, created_by="github_sync", source="github")
        if all(problem.path == () for problem in result.problems):
            # Nothing about any key: the file is empty, or not YAML at all.
            for problem in result.problems:
                logger.warning(f"Could not read index kit {source_file}: {problem.message}")
            return None
        raise KitFileProblems(result.problems, source_file)
