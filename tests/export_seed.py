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
    manifest to put on the run's ``exports``."""
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
