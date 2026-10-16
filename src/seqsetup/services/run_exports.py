"""Reading a Ready run's export files — the one function every reader uses.

A Ready run serves exactly the bytes its checks passed (CLAUDE.md, Run state
integrity). Mark Ready writes each file into its own record and keeps an id,
a SHA-256 and a length for it in the run document's ``exports`` manifest.
This module is the only place that turns that manifest back into bytes:

  * A run with a manifest is served from it and from nothing else. The
    function hashes the bytes it is about to hand back and compares them with
    the manifest's hash and length -- it does not compare the record's own
    sha256 and size fields, which a hand edit of the content leaves exactly
    as they were. Anything that does not add up raises ``ExportDamaged``: the
    legacy field is never read, and nothing is generated afresh.
  * A run stored before the files moved out of the run document has no
    manifest. It is served from the field it carries the file in, and the UI
    keeps its live fallback for runs older than pre-generation.

docs/design/2026-10-16-export-files-own-records-design.md
"""

import hashlib
from typing import Optional, Union

from ..models.sequencing_run import EXPORT_KINDS, LEGACY_EXPORT_FIELDS
from .audit_log import audit
from .samplesheet_v1_exporter import SampleSheetV1Exporter


# What each file is called in a message to a person.
EXPORT_LABELS = {
    "samplesheet_v2": "Sample Sheet v2",
    "samplesheet_v1": "Sample Sheet v1",
    "json": "JSON export",
    "validation_json": "check report (JSON)",
    "validation_pdf": "check report (PDF)",
}
# The kinds every Ready run must name. The v1 sheet is required too when the
# instrument writes one and Mark Ready did not record why it made none.
_ALWAYS_REQUIRED = ("samplesheet_v2", "json", "validation_json", "validation_pdf")


class ExportDamaged(Exception):
    """A run's manifest names a file that cannot be served as it was stored.

    Answered with 500 and this message: the alternative -- serving a legacy
    field or a fresh export -- would hand out bytes no check passed.
    """

    def __init__(self, run_id: str, kind: str, why: str):
        self.run_id = run_id
        self.kind = kind
        self.why = why
        super().__init__(
            f"This run's {EXPORT_LABELS[kind]} cannot be served: {why}. "
            f"Nothing was changed and no other version of the file was used. "
            f"Tell your SeqSetup administrator."
        )


def required_kinds(run) -> tuple:
    """The kinds this run's manifest must name, if it has one."""
    kinds = list(_ALWAYS_REQUIRED)
    if (SampleSheetV1Exporter.supports(run.instrument_platform)
            and not run.samplesheet_v1_withheld):
        kinds.append("samplesheet_v1")
    return tuple(kinds)


def _damaged(run_id: str, kind: str, why: str, actor: str) -> ExportDamaged:
    audit("run.export.damaged", actor=actor, target=run_id, outcome="failure",
          kind=kind, reason=why)
    return ExportDamaged(run_id, kind, why)


def read_export(ctx, run, kind: str, *, actor: str = "") -> Optional[Union[str, bytes]]:
    """The stored bytes of ``kind`` for ``run``, or None when it has none.

    None means "nothing is stored, legitimately": a run with no manifest that
    never stored this file (the caller may generate one live, as the UI does
    for runs older than pre-generation), or a v1 sheet this run was never
    going to have. A manifest that should name the file but does not, or
    bytes that are not the ones it names, raise ``ExportDamaged``.
    """
    if kind not in EXPORT_KINDS:
        raise ValueError(f"{kind!r} is not one of the export kinds {EXPORT_KINDS}")

    if not run.exports:
        # A run stored before the files moved out of the run document.
        return getattr(run, LEGACY_EXPORT_FIELDS[kind])

    entry = run.exports.get(kind)
    if entry is None:
        if kind in required_kinds(run):
            raise _damaged(run.id, kind, "the run names no such file", actor)
        return None

    record = ctx.run_export_repo.get(entry["id"])
    if record is None:
        raise _damaged(run.id, kind, f"its file record {entry['id']} is not there", actor)
    if record.get("run_id") != run.id:
        raise _damaged(run.id, kind, "its file record belongs to another run", actor)
    if record.get("kind") != kind:
        raise _damaged(run.id, kind, "its file record holds another kind of file", actor)

    content = record.get("content")
    if kind == "validation_pdf":
        if not isinstance(content, (bytes, bytearray)):
            raise _damaged(run.id, kind, "its file record holds no bytes", actor)
        raw = bytes(content)
        content = raw
    else:
        if not isinstance(content, str):
            raise _damaged(run.id, kind, "its file record holds no text", actor)
        raw = content.encode("utf-8")

    if len(raw) != entry["size"]:
        raise _damaged(
            run.id, kind,
            f"it is {len(raw)} bytes where the run says {entry['size']}", actor)
    if hashlib.sha256(raw).hexdigest() != entry["sha256"]:
        raise _damaged(run.id, kind, "its bytes are not the ones the run names", actor)
    return content
