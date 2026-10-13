"""The vendored JavaScript is exactly the file VERSIONS.md names (group 3b).
Each vendor folder's VERSIONS.md gives its files' npm package, version and
SHA-256. A file replaced without updating its row, or a row edited without
replacing the file, fails here.

There are two folders: ``src/seqsetup/static/js/vendor``, which the app
serves, and ``tests/browser/vendor``, which only the accessibility tests read
(batch 4, item 4f)."""

import hashlib
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SERVED = ROOT / "src" / "seqsetup" / "static" / "js" / "vendor"
FOR_TESTS = ROOT / "tests" / "browser" / "vendor"
VENDORED = sorted(
    str(path.relative_to(ROOT))
    for folder in (SERVED, FOR_TESTS)
    for path in folder.glob("*.js")
)


def _rows(folder: Path) -> dict:
    rows = {}
    for line in (folder / "VERSIONS.md").read_text().splitlines():
        cells = [cell.strip(" `") for cell in line.strip().strip("|").split("|")]
        if len(cells) == 4 and cells[0].endswith(".js"):
            rows[cells[0]] = cells
    return rows


class TestVendoredJs:
    """Every vendored file, in the folder it sits in."""

    @pytest.mark.parametrize("path", VENDORED)
    def test_the_file_is_the_one_versions_md_names(self, path):
        file = ROOT / path
        rows = _rows(file.parent)
        assert file.name in rows, f"{path} has no row in its VERSIONS.md"
        _file, _source, version, sha256 = rows[file.name]
        data = file.read_bytes()
        assert hashlib.sha256(data).hexdigest() == sha256
        assert f'"{version}"' in data.decode()


class TestAxeIsNotServed:
    """axe-core is a test tool: it is injected by the browser tests through
    ``page.evaluate()`` and no page loads it. In the folder the app serves it
    was half a megabyte of test tool available to any browser that asked."""

    def test_the_served_folder_does_not_hold_axe(self):
        assert not (SERVED / "axe.min.js").exists()

    def test_the_tests_folder_holds_axe(self):
        assert (FOR_TESTS / "axe.min.js").exists()

    def test_the_a11y_tests_read_axe_from_the_tests_folder(self):
        source = (ROOT / "tests" / "browser" / "test_a11y.py").read_text()
        assert 'Path(__file__).parent / "vendor" / "axe.min.js"' in source
