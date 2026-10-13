"""The default pixi environment is what the clinical image installs, and it
holds no test, browser or docs tool (batch 4, item 4f).

The Dockerfile runs ``pixi install --locked --environment default``, so every
package in that environment ships to the lab: code with its own security fixes
to follow, and none of it called by the app. The test, browser and docs tools
live in the ``dev`` environment instead, which a developer gets and the image
does not.

pixi.lock is read, not the environment these tests run in: the lock is what
the image installs.
"""

import tomllib
from functools import cache
from pathlib import Path

import pytest
import yaml

from .test_dependency_floors import _locked


ROOT = Path(__file__).resolve().parents[2]

# Used by tests, the browser tests or the docs build, never by src/seqsetup.
DEV_ONLY = [
    "pytest",
    "pytest-playwright",
    "playwright",
    "mongomock",
    "httpx2",
    "sphinx",
    "furo",
]


def _name(package: dict, url: str) -> str:
    if "conda" in package:
        stem = url.rsplit("/", 1)[1].removesuffix(".conda").removesuffix(".tar.bz2")
        name = stem.rsplit("-", 2)[0]
    else:
        name = package["name"]
    return name.lower().replace("_", "-")


@cache
def _environments() -> dict:
    """{environment name: {package name}} as pixi.lock has it."""
    lock = yaml.safe_load((ROOT / "pixi.lock").read_text())
    names = {}
    for package in lock["packages"]:
        url = package.get("conda") or package.get("pypi")
        names[url] = _name(package, url)
    return {
        environment: {
            names[entry.get("conda") or entry.get("pypi")]
            for packages in data["packages"].values()
            for entry in packages
        }
        for environment, data in lock["environments"].items()
    }


@cache
def _manifest() -> dict:
    return tomllib.loads((ROOT / "pixi.toml").read_text())


class TestTheImageHasNoTestTools:
    """The default environment, which the Dockerfile installs."""

    @pytest.mark.parametrize("name", DEV_ONLY)
    def test_the_default_environment_does_not_hold_it(self, name):
        assert name not in _environments()["default"]

    @pytest.mark.parametrize("name", DEV_ONLY)
    def test_the_dev_environment_holds_it(self, name):
        assert "dev" in _environments(), "pixi.lock has no dev environment"
        assert name in _environments()["dev"]

    def test_the_lock_has_no_email_validator(self):
        # pydantic's `email` extra: nothing in the app or the tests uses
        # EmailStr, so the extra only added email-validator and dnspython.
        for environment, names in _environments().items():
            assert "email-validator" not in names, environment


class TestNumpyIsDeclared:
    """numpy is imported directly (services/validation_report.py). Today it
    arrives as a matplotlib dependency; a matplotlib release that stopped
    needing it would take it out of the image with nothing to say so."""

    def test_pixi_toml_declares_numpy_with_a_floor(self):
        requirement = _manifest()["dependencies"].get("numpy")
        assert requirement is not None, "pixi.toml does not declare numpy"
        assert str(requirement).startswith(">="), requirement

    def test_the_floor_is_the_locked_version(self):
        """The floor is a floor at the LOCKED version, as the decision asks.
        ">=" alone would let a `pixi update` move numpy and leave the floor
        behind, with nothing complaining (batch 4 review fix G). _locked()
        is test_dependency_floors' lock reader; there is one of those."""
        locked = _locked()["numpy"]
        assert len(set(locked)) == 1, locked
        assert _manifest()["dependencies"]["numpy"] == f">={locked[0]}"

    def test_the_default_environment_holds_numpy(self):
        assert "numpy" in _environments()["default"]
