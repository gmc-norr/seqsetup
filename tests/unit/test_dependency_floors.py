"""The 13 packages named in FLOORS are locked at or above the version that
fixes the advisories known for them (group 3b: N-23, N-24, N-26).

What this covers: those 13, and nothing else. Each floor is the first release
that fixes every advisory the OSV database (api.osv.dev) listed on 2026-10-11
for the version locked before group 3b -- PyPI advisories, which is where
every floor here comes from except OpenSSL's; that one is from
openssl-library.org (2026-09-29). Four of the 13 are installed from
conda-forge (openssl, pillow, pygments, pytest), and for three of those the
advisory is still the Python project's. It reads pixi.lock, which holds both
environments, so 5 of the 13 (pygments, pytest, requests, soupsieve, urllib3)
are checked where they now live, in the dev environment, and are not in the
Docker image at all.

What this does not cover:

- It looks nothing up. The floors are written by hand, so an advisory
  published after 2026-10-11 -- against one of these 13 or against any of the
  other 149 packages in the lock -- passes here until someone adds or raises
  a floor. This is not a scanner. The "Updating Libraries" steps in
  docs/development/contributing.rst say to check the locked versions by hand
  after a `pixi update`.
- No C library but OpenSSL: zlib-ng, freetype, libpng, libjpeg-turbo,
  libexpat, libwebp-base, cairo and the rest of conda-forge's C packages have
  no floor here.
- Nothing outside the lock -- not the environment the tests run in, and not
  the Debian packages of the pixi base image the Dockerfile builds on.
- Not "the newest release": only "at or above the floor".

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
    "openssl": "3.6.5",            # N-26: the TLS stack for the LIMS, LDAP and GitHub;
                                   # 3.6.5 per openssl-library.org (2026-09-29), not OSV
    # In the dev environment only, never in the image (docs and test tools).
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


class TestNoDesktopToolkit:
    """The server draws its plots with matplotlib's Agg backend, so it needs
    matplotlib-base. conda's `matplotlib` adds PySide6 and Qt, a desktop GUI
    toolkit with its own security fixes to follow, and nothing the app uses."""

    @pytest.mark.parametrize("name", ["matplotlib", "pyside6", "qt6-main"])
    def test_the_lock_has_no_gui_toolkit(self, name):
        assert name not in _locked()


class TestDependencyFloors:
    """pixi.lock as committed."""

    @pytest.mark.parametrize("name", sorted(FLOORS))
    def test_the_locked_version_has_the_fixes(self, name):
        locked = _locked()
        assert name in locked, f"{name} is not in pixi.lock: take it out of FLOORS"
        for version in locked[name]:
            assert Version(version) >= Version(FLOORS[name]), (
                f"{name} {version} is locked, below {FLOORS[name]}")
