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
# The local fallback file holds every instrument under one ``instruments:`` key.
LOCAL = CONFIG / "instruments.yaml"

# The onboard applications as Illumina's NovaSeq X and NextSeq 1000/2000 sample
# sheet version histories name their sections (help.connected.illumina.com,
# 2026-10-17; docs/design/2026-10-17-rna-section-spelling-design.md).
ILLUMINA_APPS = {"BCLConvert", "DragenGermline", "DragenSomatic", "DragenRna",
                 "DragenEnrichment", "DragenMethylation"}


def _offered() -> dict[str, dict[str, str]]:
    """Application name -> {instrument: the version it offers}, from the
    synced-format files and the local fallback file alike."""
    entries = [(path.name, yaml.safe_load(path.read_text()) or {}) for path in INSTRUMENTS]
    entries += [(f"instruments.yaml: {name}", entry)
                for name, entry in (yaml.safe_load(LOCAL.read_text())["instruments"]).items()]
    offered: dict[str, dict[str, str]] = {}
    for where, entry in entries:
        for app, settings in (entry.get("onboard_applications") or {}).items():
            offered.setdefault(app, {})[where] = str(settings["software_version"])
    return offered


class TestTheShippedExamplesFitTogether:

    def test_there_are_examples_to_check(self):
        assert PROFILES and INSTRUMENTS
        assert any(where.startswith("instruments.yaml: ")
                   for found in _offered().values() for where in found)

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

    def test_every_application_an_instrument_offers_is_spelled_as_illumina_spells_it(self):
        misspelled = {app: sorted(where) for app, where in _offered().items()
                      if app not in ILLUMINA_APPS}
        assert not misspelled, misspelled

    def test_every_profiles_application_is_offered_by_an_instrument(self):
        """Spelled as the instruments spell it: the RNA example was DragenRna
        in its profile and DragenRNA in the instrument files, so it could
        never pass (docs/design/2026-10-17-rna-section-spelling-design.md)."""
        offered = _offered()
        unoffered = {yaml.safe_load(p.read_text())["ApplicationName"] for p in PROFILES} - set(offered)
        assert not unoffered, sorted(unoffered)


def test_the_input_rules_take_illumina_s_application_names():
    """The rules' own list against the list written out here from Illumina's
    sources, so a wrong name added to either one fails."""
    from seqsetup.input_rules.base import ILLUMINA_APPLICATION_NAMES

    assert sorted(ILLUMINA_APPLICATION_NAMES) == sorted(ILLUMINA_APPS)
    assert len(set(ILLUMINA_APPLICATION_NAMES)) == len(ILLUMINA_APPLICATION_NAMES)
