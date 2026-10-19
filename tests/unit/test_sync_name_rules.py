"""Names from synced instrument files are written into the Sample Sheet as
is, so the sync refuses anything but plain names (audit 2026-09 N-10, N-11)."""

from pathlib import Path

import pytest
import yaml

from seqsetup.input_rules.instruments import check_synced_instrument_file


def check_application_profile(data, source_file=""):
    """The input rules for an application profile, through its one builder
    (input_rules/profiles.py; services/profile_validator.py was removed)."""
    from seqsetup.models.application_profile import ApplicationProfile

    ApplicationProfile.from_yaml(data, source_file)

REPO = Path(__file__).resolve().parents[2]


def _instrument(**extra) -> dict:
    data = {
        "name": "NovaSeq X Series",
        "samplesheet_name": "NovaSeqXSeries",
        "version": "1.0.0",
        "chemistry_type": "4-color",
        "has_dragen_onboard": True,
        "color_balance_enabled": False,
        "onboard_applications": {"BCLConvert": {"software_version": "4.3.6"}},
        "flowcells": {"10B": {"lanes": 8, "reagent_kits": [300]}},
        "i5_workflows": [{"name": "Standard", "i5_read_orientation": "reverse-complement"}],
        "runinfo_marks_i5_reversed": True,
    }
    data.update(extra)
    return data


def _checked(data: dict, file: str = "x.yaml"):
    """The sync's check of an instrument file holding ``data`` (the instrument
    rulebook, docs/design/2026-10-18-input-rules-design.md)."""
    return check_synced_instrument_file(yaml.safe_dump(data), file)


def _errors_on(result, *path) -> list:
    return [p for p in result.problems if p.level == "error" and p.path[:len(path)] == path]


class TestSamplesheetName:
    """The instrument's sample sheet name is the InstrumentPlatform line."""

    @pytest.mark.parametrize("name", ["NovaSeqXSeries\n[Cloud_Data]", "NovaSeq X", "a,b", "X\x00"])
    def test_non_plain_samplesheet_name_is_refused(self, name):
        result = _checked(_instrument(samplesheet_name=name))

        assert not result.ok
        assert _errors_on(result, "samplesheet_name")

    def test_plain_samplesheet_name_is_accepted(self):
        result = _checked(_instrument())

        assert result.ok, result.problems


class TestOnboardApplications:
    """Onboard application names whitelist profile ApplicationNames, and the
    BCL Convert software version is the SoftwareVersion line."""

    @pytest.mark.parametrize("name", ["BCLConvert]\n[Junk", "Dragen Germline", "a,b"])
    def test_non_plain_application_name_is_refused(self, name):
        result = _checked(_instrument(onboard_applications={name: {"software_version": "4.3.6"}}))

        assert not result.ok
        assert _errors_on(result, "onboard_applications")

    @pytest.mark.parametrize("version", ["4.3.6\n[Junk]", "4.3 6", "4,3"])
    def test_non_plain_software_version_is_refused(self, version):
        result = _checked(_instrument(onboard_applications={"BCLConvert": {"software_version": version}}))

        assert not result.ok
        assert _errors_on(result, "onboard_applications", "BCLConvert", "software_version")

    def test_illumina_names_with_plain_versions_are_accepted(self):
        # The names must now be Illumina's, each with its version (the input
        # rules design, 2026-10-18); "Dragen_Germline-2" with none passed before.
        result = _checked(_instrument(onboard_applications={
            "BCLConvert": {"software_version": "4.3.6"},
            "DragenGermline": {"software_version": "4.3.6-2"},
        }))

        assert result.ok, result.problems


class TestShippedConfigStillPasses:
    """Everything SeqSetup ships must still pass the stricter rules."""

    def test_every_shipped_instrument_passes(self):
        from seqsetup.input_rules.instruments import check_local_instruments_file

        result = check_local_instruments_file(
            (REPO / "config" / "instruments.yaml").read_text(), "instruments.yaml")
        assert result.ok, result.problems

    def test_every_shipped_instrument_file_passes(self):
        """The one-instrument files are the format a config sync reads."""
        paths = sorted((REPO / "config" / "instruments").glob("*.y*ml"))
        assert paths
        for path in paths:
            result = check_synced_instrument_file(path.read_text(), path.name)
            assert result.ok, (path.name, result.problems)

    def test_every_shipped_application_profile_passes(self):
        checked = 0
        for path in sorted(REPO.glob("config/**/*.y*ml")):
            data = yaml.safe_load(path.read_text())
            if isinstance(data, dict) and "ApplicationName" in data:
                check_application_profile(data, str(path))
                checked += 1
        assert checked >= 5
