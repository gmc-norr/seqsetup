"""The shipped example profiles fit the shipped example instruments.

A practice deploy (2026-10-17) synced ``config/`` from the public repository
as a lab would sync its own, and no run could be marked Ready: every example
application profile asked for software version 4.1.23, and every example
instrument offers 4.3.6 only. The examples are the format a lab copies, so
they should be able to make a Ready run together.
"""

from pathlib import Path

import yaml

CONFIG = Path(__file__).resolve().parents[2] / "config"
PROFILES = sorted((CONFIG / "profiles" / "application_profiles").rglob("*.yaml"))
INSTRUMENTS = sorted((CONFIG / "instruments").glob("*.yaml"))


def _offered() -> dict[str, dict[str, str]]:
    """Application name -> {instrument file: the version it offers}."""
    offered: dict[str, dict[str, str]] = {}
    for path in INSTRUMENTS:
        apps = (yaml.safe_load(path.read_text()) or {}).get("onboard_applications") or {}
        for app, settings in apps.items():
            offered.setdefault(app, {})[path.name] = str(settings["software_version"])
    return offered


class TestTheShippedExamplesFitTogether:

    def test_there_are_examples_to_check(self):
        assert PROFILES and INSTRUMENTS

    def test_every_instrument_that_offers_a_profiles_application_offers_its_version(self):
        offered = _offered()
        misfits = []
        for path in PROFILES:
            profile = yaml.safe_load(path.read_text())
            app = profile["ApplicationName"]
            version = str(profile["Settings"]["SoftwareVersion"])
            for instrument, has in offered.get(app, {}).items():
                if has != version:
                    misfits.append(f"{path.name} asks {app} {version}; {instrument} offers {has}")
        assert not misfits, misfits

    def test_only_the_rna_profile_names_an_application_no_instrument_offers(self):
        """The RNA example is spelled DragenRna in its profile (and in the
        Sample Sheet section a profile writes) and DragenRNA in the instrument
        files. Which spelling the instrument reads is an open question, not
        settled by this test: it pins that this is the only such case, so a
        new one is seen."""
        offered = _offered()
        unoffered = {yaml.safe_load(p.read_text())["ApplicationName"] for p in PROFILES} - set(offered)
        assert unoffered == {"DragenRna"}
