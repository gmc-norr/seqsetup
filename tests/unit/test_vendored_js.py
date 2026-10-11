"""The vendored JavaScript is exactly the file VERSIONS.md names (group 3b).
static/js/vendor/VERSIONS.md gives each file's npm package, version and
SHA-256. A file replaced without updating its row, or a row edited without
replacing the file, fails here."""

import hashlib
from pathlib import Path

import pytest


VENDOR = Path(__file__).resolve().parents[2] / "src" / "seqsetup" / "static" / "js" / "vendor"


def _rows() -> dict:
    rows = {}
    for line in (VENDOR / "VERSIONS.md").read_text().splitlines():
        cells = [cell.strip(" `") for cell in line.strip().strip("|").split("|")]
        if len(cells) == 4 and cells[0].endswith(".js"):
            rows[cells[0]] = cells
    return rows


class TestVendoredJs:
    """Each file the app serves from static/js/vendor."""

    @pytest.mark.parametrize("name", sorted(p.name for p in VENDOR.glob("*.js")))
    def test_the_file_is_the_one_versions_md_names(self, name):
        assert name in _rows(), f"{name} has no row in VERSIONS.md"
        _file, _source, version, sha256 = _rows()[name]
        data = (VENDOR / name).read_bytes()
        assert hashlib.sha256(data).hexdigest() == sha256
        assert f'"{version}"' in data.decode()
