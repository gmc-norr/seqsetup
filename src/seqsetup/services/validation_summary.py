"""Plain-language view of a ValidationResult: every blocking error as one
sentence, and which samples each error names.

Read-only: never changes the run or the result. The Mark-Ready refusal,
the validation PDF and the run page's row marks all use these, so they
always list the same errors.
"""

from collections import Counter, defaultdict

from ..models.sequencing_run import SequencingRun
from ..models.validation import ValidationResult, ValidationSeverity


#: How many index-collision messages one sample's row carries. A sample can
#: be within the tolerance of many different sequences; the rest are counted
#: in one line, never dropped without a word (docs/design/
#: 2026-10-17-collision-report-grouped-design.md).
MAX_SAMPLE_ERROR_MESSAGES = 20


def error_messages(result: ValidationResult) -> list[str]:
    """Every blocking error as one sentence; one per ``result.error_count``."""
    msgs = list(result.duplicate_sample_ids)
    msgs.extend(g.collision_description for g in result.index_collision_groups)
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


def grouped_messages(messages: list[str]) -> list[tuple[str, int]]:
    """Each different message once, in the order first seen, with how many
    times it appears.

    An application profile problem is one error per sample that uses the
    profile, and its message names no sample, so a run of 8 samples said
    one problem 8 times over. The Mark Ready refusal and the Check panel
    list each message once with its count; the number of errors they give
    is still every error (practice deploy 2026-10-17).
    """
    return list(Counter(messages).items())


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

    # Every sample a collision finding names is marked — the whole
    # membership, not only the names its message lists. A sample in more
    # findings than MAX_SAMPLE_ERROR_MESSAGES keeps the first of them and
    # one line saying exactly how many more there are.
    collisions_by_id: dict[str, list[str]] = defaultdict(list)
    for group in result.index_collision_groups:
        description = group.collision_description
        for sid in group.sample_ids:
            collisions_by_id[sid].append(description)
    for sid, descriptions in collisions_by_id.items():
        kept = list(dict.fromkeys(descriptions))
        if len(kept) > MAX_SAMPLE_ERROR_MESSAGES:
            hidden = len(kept) - MAX_SAMPLE_ERROR_MESSAGES
            kept = kept[:MAX_SAMPLE_ERROR_MESSAGES] + [
                f"and {hidden} more index collisions on this sample - "
                f"open the validation page."
            ]
        by_id[sid].extend(kept)
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


def issue_rows(result: ValidationResult) -> tuple[list[tuple], list[tuple]]:
    """The Issues tab's error and warning rows, as (kind, item) pairs.

    Built here rather than in the template: the Jinja version grew its list
    with ``ns.errors = ns.errors + [...]`` inside a loop, which copies the
    whole list on every error and made a large report quadratic
    (docs/design/2026-10-17-collision-report-grouped-design.md).

    ``errors`` has one row per ``result.error_count``, in the same order as
    ``error_messages``.
    """
    errors: list[tuple] = [("duplicate", message) for message in result.duplicate_sample_ids]
    errors += [("collision", group) for group in result.index_collision_groups]
    errors += [("dark_cycle", error) for error in result.dark_cycle_errors]
    errors += [("application", error) for error in result.application_errors]
    errors += [("config", error) for error in result.configuration_errors
               if error.severity == ValidationSeverity.ERROR]
    warnings: list[tuple] = [
        ("config_warning", error) for error in result.configuration_errors
        if error.severity == ValidationSeverity.WARNING
    ]
    return errors, warnings
