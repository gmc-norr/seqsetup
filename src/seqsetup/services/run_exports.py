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
import logging
import uuid
from typing import Optional, Union

from bson import BSON

from ..models.sequencing_run import EXPORT_KINDS, LEGACY_EXPORT_FIELDS
from ..utils.clock import utcnow
from .audit_log import audit
from .samplesheet_v1_exporter import SampleSheetV1Exporter


logger = logging.getLogger(__name__)

# MongoDB refuses a document over 16 MiB. One file now has that whole budget
# to itself, so the size of a run's files is no longer a limit on the run as
# a whole (the run document is still measured for its own settings and
# samples: routes/runs.py). What is measured here is the whole record, every
# field included, so the margin covers nothing in particular -- it is slack,
# so a record measured just under the line cannot be refused by the server
# instead.
MAX_EXPORT_FILE = 16 * 1024 * 1024
EXPORT_FILE_MARGIN = 64 * 1024


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


class ExportFileTooBig(Exception):
    """One export file would not fit a MongoDB document. Raised before any
    file is written, so nothing of the attempt is stored."""

    def __init__(self, kind: str, size: int):
        self.kind = kind
        self.size = size
        super().__init__(f"{kind} is {size} bytes")


class ExportFileMissing(Exception):
    """A file every Ready run must have was not there to write — an exporter
    returned nothing. Raised before any file is written: Ready is the last
    step, and a reader must never see a Ready run whose files are not all
    stored (review 1, P3-2)."""

    def __init__(self, kinds):
        self.kinds = tuple(kinds)
        super().__init__(f"nothing to store for {', '.join(self.kinds)}")


class ExportFileNotStored(Exception):
    """A file was written but did not read back as the bytes that were
    written. Mark Ready is refused: a run must never go Ready naming a file
    that cannot be served."""

    def __init__(self, kind: str, why: str):
        self.kind = kind
        self.why = why
        super().__init__(f"{kind} did not read back: {why}")


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


def export_file_too_big_message(kind: str, size: int) -> str:
    return (
        f"This run's {EXPORT_LABELS[kind]} would be {size / 1024 / 1024:.1f} MB, and "
        f"SeqSetup stores at most {MAX_EXPORT_FILE // 1024 // 1024} MB in one file. This "
        "is a limit of SeqSetup, not a problem with the run. Nothing was saved and the "
        "run is still a Draft. Tell your SeqSetup administrator."
    )
    # No advice to change the run: splitting it costs another sequencing run,
    # and how samples go on lanes is the lab's design, not something to bend
    # to this limit (the user's decision, 2026-10-16).


def _record(run_id: str, kind: str, content: Union[str, bytes], actor: str) -> tuple:
    raw = content.encode("utf-8") if isinstance(content, str) else bytes(content)
    return {
        "_id": uuid.uuid4().hex,
        "run_id": run_id,
        "kind": kind,
        "content": content,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
        "created_at": utcnow().isoformat(),
        "created_by": actor,
    }, raw


def write_exports(ctx, run, files: dict, *, actor: str = "") -> dict:
    """Write each of ``files`` (kind -> bytes or text, None to skip) into its
    own record and return the manifest the run will carry.

    Every record is measured first, so a file that cannot be stored refuses
    the whole Mark Ready before anything at all is written. Each record is
    then inserted and read straight back, and the bytes that came back are
    hashed: a run must never go Ready naming a file that cannot be served.

    Nothing here touches the run. Records of an attempt that then fails are
    referenced by nothing and are left in place -- the collection is
    insert-only, so no reader of an older manifest can lose a file
    (docs/design/2026-10-16-export-files-own-records-design.md).
    """
    # A file every Ready run must have, and any file that was made at all,
    # must have bytes. ``None`` for a kind this run does not have (a v1 sheet
    # its instrument does not write, or one Mark Ready withheld) is the only
    # legitimate absence: an empty file would be named by the manifest and
    # then served as an empty download by the UI while the API called it "not
    # yet generated" (review 1, P3-2).
    empty = [kind for kind in EXPORT_KINDS
             if not files.get(kind)
             and (kind in _ALWAYS_REQUIRED or files.get(kind) is not None)]
    if empty:
        raise ExportFileMissing(empty)

    planned = []
    for kind in EXPORT_KINDS:
        content = files.get(kind)
        if content is None:
            continue
        record, raw = _record(run.id, kind, content, actor)
        # The record is what MongoDB must hold, so the record is what is
        # measured; the message names the file's own bytes, which is the
        # number that means something to a person (review 1, P3-6).
        if len(BSON.encode(record)) > MAX_EXPORT_FILE - EXPORT_FILE_MARGIN:
            raise ExportFileTooBig(kind, len(raw))
        planned.append((kind, record, raw))

    manifest = {}
    for kind, record, raw in planned:
        ctx.run_export_repo.insert(record)
        back = ctx.run_export_repo.get(record["_id"])
        if back is None:
            raise ExportFileNotStored(kind, "it was not there when it was read back")
        content = back.get("content")
        read = (content.encode("utf-8") if isinstance(content, str)
                else bytes(content) if isinstance(content, (bytes, bytearray)) else None)
        if read != raw:
            raise ExportFileNotStored(
                kind, f"{len(read) if read is not None else 'no'} bytes came back, "
                      f"not the {len(raw)} that were written")
        manifest[kind] = {"id": record["_id"], "sha256": record["sha256"],
                          "size": record["size"]}
    # Logged with the run id, always: a Mark Ready that is refused after this
    # point leaves these records referenced by nothing, and this line plus
    # that refusal's own line are how an operator finds them (the spec's
    # "Files written by an attempt that then fails ... and logged with the
    # run id"; review 1, P2-1).
    logger.info("Run %s: stored %d export files: %s", run.id, len(manifest),
                ", ".join(f"{kind}={entry['id']}" for kind, entry in manifest.items()))
    return manifest
