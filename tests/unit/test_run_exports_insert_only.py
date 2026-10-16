"""Nothing in the application changes or removes an export file record.

That is the whole of why a manifest can be trusted: a file is immutable once
written, so the id a Ready run carries always names the same bytes, and an
archived run, a run sent back to Draft and a deleted run's kept copy never
lose anything they point at
(docs/design/2026-10-16-export-files-own-records-design.md).

``RunExportRepository`` offers only ``insert`` and ``get`` — but
``repo.collection`` is a raw PyMongo handle, exactly as ``run_repo.collection``
is, and CLAUDE.md's run-deletion rule exists because such a handle was used
once. A grep nobody has to remember (review 2, P3-4).
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src" / "seqsetup"
TOOLS = ROOT / "tools"

# Every way a PyMongo collection can change or remove a document.
WRITES = re.compile(
    r"\.(?:update_one|update_many|replace_one|delete_one|delete_many|drop"
    r"|find_one_and_update|find_one_and_replace|find_one_and_delete"
    r"|bulk_write|insert_many)\b"
)
# The repository is the only file that may touch the collection at all.
REPO = SRC / "repositories" / "run_export_repo.py"


def _lines(path):
    return list(enumerate(path.read_text().splitlines(), start=1))


def _hits(pattern, paths):
    return [f"{path.relative_to(ROOT)}:{n}: {line.strip()}"
            for path in paths for n, line in _lines(path) if pattern.search(line)]


class TestTheCollectionIsOnlyEverInserted:

    def test_the_repository_itself_only_inserts(self):
        assert _hits(WRITES, [REPO]) == []
        assert "insert_one(" in REPO.read_text()

    def test_no_other_file_reaches_the_collection_at_all(self):
        """``run_export_repo`` is imported for its type and built in startup;
        nothing else may name the collection or a repository's handle."""
        paths = [p for p in sorted(SRC.rglob("*.py")) + sorted(TOOLS.glob("*.py"))
                 if p != REPO]
        reaching = re.compile(r"run_export_repo\.collection|\"run_exports\"|'run_exports'")
        assert _hits(reaching, paths) == []

    def test_the_repository_names_the_collection_once(self):
        assert REPO.read_text().count('COLLECTION = "run_exports"') == 1

    def test_the_pattern_finds_each_way_to_change_a_document(self):
        for line in ("c.update_one({}, {})", "c.update_many({}, {})",
                     "c.replace_one({}, d)", "c.delete_one({})", "c.delete_many({})",
                     "c.drop()", "c.find_one_and_update({}, {})",
                     "c.find_one_and_replace({}, d)", "c.find_one_and_delete({})",
                     "c.bulk_write(ops)", "c.insert_many(docs)"):
            assert WRITES.search(line), line
        for line in ("c.insert_one(doc)", "c.find_one({})", "c.find({})",
                     "repo.get(file_id)", "repo.insert(doc)"):
            assert not WRITES.search(line), line
