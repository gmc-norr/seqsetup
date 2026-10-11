"""Every library with a known security advisory is locked at or above the
version that fixes it (group 3b: N-23, N-24, N-26). pixi.lock is what
`pixi install --locked` puts into the Docker image, so this reads the lock,
not the environment the tests run in.

Each floor is the first release that fixes every advisory the OSV database
(api.osv.dev) listed on 2026-10-11 for the version locked before group 3b.
Raise a floor when a new advisory needs it; never lower one. A package that
leaves the lock is taken out of FLOORS.
"""

from functools import cache
from pathlib import Path

import pytest
import yaml
from packaging.version import Version


ROOT = Path(__file__).resolve().parents[2]

FLOORS = {
    # The web stack: reachable before login.
    "starlette": "1.3.1",          # form() limits ignored for urlencoded bodies; Host and path confuse request.url
    "python-multipart": "0.0.31",  # quadratic scans, unbounded part headers, ';' as a separator
    "anyio": "4.14.2",
    "idna": "3.15",
    # Used by the app.
    "pymongo": "4.18.2",           # connection-string host injection, BSON heap overflow
    "pyasn1": "0.6.4",             # LDAP: decoder denial of service
    "pillow": "12.3.0",            # PDF and plot images: heap overflows, decompression bombs
    "openssl": "3.6.2",            # N-26: the TLS stack for the LIMS, LDAP and GitHub
    # In the image, not used by the app (plots, docs and test tools).
    "tornado": "6.5.9",
    "urllib3": "2.8.0",
    "requests": "2.33.0",
    "pytest": "9.0.3",
    "pygments": "2.20.0",
    "soupsieve": "2.9.0",
}


@cache
def _locked() -> dict:
    lock = yaml.safe_load((ROOT / "pixi.lock").read_text())
    found = {}
    for package in lock["packages"]:
        if "pypi" in package:
            name, version = package["name"], package["version"]
        else:
            filename = package["conda"].rsplit("/", 1)[1]
            stem = filename.removesuffix(".conda").removesuffix(".tar.bz2")
            name, version, _build = stem.rsplit("-", 2)
        found.setdefault(name.lower().replace("_", "-"), []).append(version)
    return found


class TestDependencyFloors:
    """pixi.lock as committed."""

    @pytest.mark.parametrize("name", sorted(FLOORS))
    def test_the_locked_version_has_the_fixes(self, name):
        locked = _locked()
        assert name in locked, f"{name} is not in pixi.lock: take it out of FLOORS"
        for version in locked[name]:
            assert Version(version) >= Version(FLOORS[name]), (
                f"{name} {version} is locked, below {FLOORS[name]}")
