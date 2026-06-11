"""Pure field-level diff of two SequencingRun.to_dict() snapshots.

Produces (field_changes, sample_changes) for the change-history feature.
No DB, no model imports — operates only on plain dicts so it is trivially
unit-tested.
"""

# Top-level run keys excluded from the config diff: volatile outputs, per-touch
# metadata, the optimistic-lock token, transient UI state, the doc id, and
# `samples` (handled separately, deep). Mirrors _FINGERPRINT_IGNORED_KEYS in
# routes/runs.py plus wizard_step and samples.
RUN_DIFF_IGNORED_KEYS = {
    "_id", "id", "samples",
    "updated_at", "updated_by", "_loaded_updated_at", "wizard_step",
    "generated_samplesheet_v2", "generated_samplesheet_v1", "generated_json",
    "generated_validation_json", "generated_validation_pdf",
}

# Sample keys excluded from the per-sample diff: only the pairing uuid. Every
# other persisted field is tracked (a DENYLIST — an allowlist would silently
# drop fields the way audit drift does, which is exactly what this prevents).
SAMPLE_IGNORED_KEYS = {"id"}


def _config_changes(before: dict, after: dict) -> list:
    changes = []
    keys = (set(before) | set(after)) - RUN_DIFF_IGNORED_KEYS
    for k in sorted(keys):
        b, a = before.get(k), after.get(k)
        if b != a:
            changes.append({"field": k, "before": b, "after": a})
    return changes


def _sample_field_changes(before_s: dict, after_s: dict) -> list:
    fields = []
    keys = (set(before_s) | set(after_s)) - SAMPLE_IGNORED_KEYS
    for k in sorted(keys):
        b, a = before_s.get(k), after_s.get(k)
        if b != a:
            fields.append({"name": k, "before": b, "after": a})
    return fields


def _snapshot_fields(sample: dict, *, present_key: str) -> list:
    """All tracked fields of a sample as before/after, for added/removed.

    present_key is 'after' for an added sample, 'before' for a removed one;
    the opposite side is None.
    """
    other = "before" if present_key == "after" else "after"
    fields = []
    for k in sorted(set(sample) - SAMPLE_IGNORED_KEYS):
        fields.append({"name": k, present_key: sample[k], other: None})
    return fields


def _sample_changes(before: dict, after: dict) -> list:
    before_by_id = {s["id"]: s for s in before.get("samples", [])}
    after_by_id = {s["id"]: s for s in after.get("samples", [])}
    changes = []
    for sid in sorted(set(before_by_id) - set(after_by_id)):
        s = before_by_id[sid]
        changes.append({"sample_id": s.get("sample_id"), "kind": "removed",
                        "fields": _snapshot_fields(s, present_key="before")})
    for sid in sorted(set(after_by_id) - set(before_by_id)):
        s = after_by_id[sid]
        changes.append({"sample_id": s.get("sample_id"), "kind": "added",
                        "fields": _snapshot_fields(s, present_key="after")})
    for sid in sorted(set(before_by_id) & set(after_by_id)):
        diff = _sample_field_changes(before_by_id[sid], after_by_id[sid])
        if diff:
            changes.append({"sample_id": after_by_id[sid].get("sample_id"),
                            "kind": "modified", "fields": diff})
    return changes


def diff_run(before: dict, after: dict) -> tuple:
    """Return (field_changes, sample_changes) between two run dicts."""
    return _config_changes(before, after), _sample_changes(before, after)


def is_empty(field_changes: list, sample_changes: list) -> bool:
    return not field_changes and not sample_changes
