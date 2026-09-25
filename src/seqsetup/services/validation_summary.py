"""Plain-language view of a ValidationResult: every blocking error as one
sentence, and which samples each error names.

Read-only: never changes the run or the result. The Mark-Ready refusal,
the validation PDF and the run page's row marks all use these, so they
always list the same errors.
"""

from collections import defaultdict

from ..models.sequencing_run import SequencingRun
from ..models.validation import ValidationResult, ValidationSeverity


def error_messages(result: ValidationResult) -> list[str]:
    """Every blocking error as one sentence; one per ``result.error_count``."""
    msgs = list(result.duplicate_sample_ids)
    msgs.extend(c.collision_description for c in result.index_collisions)
    msgs.extend(e.description for e in result.dark_cycle_errors)
    msgs.extend(e.detail for e in result.application_errors)
    msgs.extend(
        e.message for e in result.configuration_errors
        if e.severity == ValidationSeverity.ERROR
    )
    return msgs


def waiting_for_samples(run: SequencingRun, result: ValidationResult) -> bool:
    """True when the run has no samples and that is its only error.

    The run page then shows Check as "not reached yet" instead of as an
    error. Display only: Mark Ready still refuses a run with no samples.
    """
    if run.samples:
        return False
    no_samples = sum(
        1 for e in result.configuration_errors
        if e.severity == ValidationSeverity.ERROR and e.category == "prerequisite_no_samples"
    )
    return result.error_count == no_samples


def errors_by_sample(run: SequencingRun, result: ValidationResult) -> dict[str, list[str]]:
    """Blocking errors per sample, keyed by the sample's internal id.

    Collision, dark-cycle and application errors carry sample ids.
    Configuration errors name samples by display name (sample_id, else
    sample_name, else id), as the validators do; a name shared by several
    samples marks all of them. Duplicate-ID errors mark every copy.
    """
    by_id: dict[str, list[str]] = defaultdict(list)

    ids_by_sample_id: dict[str, list[str]] = defaultdict(list)
    ids_by_name: dict[str, list[str]] = defaultdict(list)
    for s in run.samples:
        if s.sample_id:
            ids_by_sample_id[s.sample_id].append(s.id)
        ids_by_name[s.sample_id or s.sample_name or s.id].append(s.id)

    for sample_id, ids in ids_by_sample_id.items():
        if len(ids) < 2:
            continue
        msg = next((m for m in result.duplicate_sample_ids if f"'{sample_id}'" in m), None)
        if msg:
            for sid in ids:
                by_id[sid].append(msg)

    for c in result.index_collisions:
        by_id[c.sample1_id].append(c.collision_description)
        by_id[c.sample2_id].append(c.collision_description)
    for e in result.dark_cycle_errors:
        by_id[e.sample_id].append(e.description)
    for e in result.application_errors:
        by_id[e.sample_id].append(e.detail)
    for e in result.configuration_errors:
        if e.severity != ValidationSeverity.ERROR:
            continue
        for name in e.sample_names:
            for sid in ids_by_name.get(name, []):
                by_id[sid].append(e.message)

    # A sample named twice by one error (e.g. in two collisions with the
    # same text) lists that message once.
    return {sid: list(dict.fromkeys(msgs)) for sid, msgs in by_id.items()}
