"""Seed a Ready run's export files the way Mark Ready stores them.

Shared by the integration and browser suites: a run marked Ready by this
release carries a manifest and keeps each file in its own record, so a test
that seeds the ``generated_*`` fields tests only the older shape
(docs/design/2026-10-16-export-files-own-records-design.md).
"""

import hashlib
import uuid

from seqsetup.models.sequencing_run import EXPORT_KINDS


def seed_stored_exports(ctx, run_id: str, **files) -> dict:
    """Write ``files`` (kind=content) into their own records and return the
    manifest to put on the run's ``exports``.

    Every kind a manifest must name has to be given: a manifest with only
    some of them is a *damaged* run, which read_export refuses, and a fixture
    that seeded one would hand a later test a 500 that reads like an
    application bug (review 1, P3-4). Pass ``allow_partial=True`` for a test
    that means to seed a damaged run.
    """
    from seqsetup.services.run_exports import _ALWAYS_REQUIRED
    if not files.pop("allow_partial", False):
        missing = [kind for kind in _ALWAYS_REQUIRED if kind not in files]
        assert not missing, (
            f"a seeded manifest must name {sorted(_ALWAYS_REQUIRED)}; missing {missing}. "
            f"Pass allow_partial=True to seed a damaged run on purpose.")
    manifest = {}
    for kind, content in files.items():
        assert kind in EXPORT_KINDS, kind
        raw = content.encode("utf-8") if isinstance(content, str) else content
        file_id = uuid.uuid4().hex
        sha256 = hashlib.sha256(raw).hexdigest()
        ctx.run_export_repo.insert({
            "_id": file_id, "run_id": run_id, "kind": kind, "content": content,
            "sha256": sha256, "size": len(raw),
            "created_at": "2026-10-16T00:00:00", "created_by": "seed",
        })
        manifest[kind] = {"id": file_id, "sha256": sha256, "size": len(raw)}
    return manifest
