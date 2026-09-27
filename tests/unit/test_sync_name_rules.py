"""Names from synced instrument files are written into the Sample Sheet as
is, so the sync refuses anything but plain names (audit 2026-09 N-10, N-11)."""

from pathlib import Path

import pytest
import yaml

from seqsetup.services.instrument_validator import validate_instrument_yaml
from seqsetup.services.profile_validator import validate_application_profile_yaml

REPO = Path(__file__).resolve().parents[2]


def _instrument(**extra) -> dict:
    data = {
        "name": "NovaSeq X Series",
        "samplesheet_name": "NovaSeqXSeries",
        "version": "1.0.0",
        "chemistry_type": "4-color",
        "flowcells": {"10B": {"lanes": 8, "reagent_kits": [300]}},
    }
    data.update(extra)
    return data


def _errors_on(result, field: str) -> list:
    return [e for e in result.errors if e.field == field]


class TestSamplesheetName:
    """The instrument's sample sheet name is the InstrumentPlatform line."""

    @pytest.mark.parametrize("name", ["NovaSeqXSeries\n[Cloud_Data]", "NovaSeq X", "a,b", "X\x00"])
    def test_non_plain_samplesheet_name_is_refused(self, name):
        result = validate_instrument_yaml(_instrument(samplesheet_name=name))

        assert not result.is_valid
        assert _errors_on(result, "samplesheet_name")

    def test_plain_samplesheet_name_is_accepted(self):
        result = validate_instrument_yaml(_instrument())

        assert result.is_valid, [str(e) for e in result.errors]


class TestOnboardApplications:
    """Onboard application names whitelist profile ApplicationNames, and the
    BCL Convert software version is the SoftwareVersion line."""

    @pytest.mark.parametrize("name", ["BCLConvert]\n[Junk", "Dragen Germline", "a,b"])
    def test_non_plain_application_name_is_refused(self, name):
        result = validate_instrument_yaml(
            _instrument(onboard_applications={name: {"software_version": "4.3.6"}})
        )

        assert not result.is_valid
        assert _errors_on(result, "onboard_applications")

    @pytest.mark.parametrize("version", ["4.3.6\n[Junk]", "4.3 6", "4,3"])
    def test_non_plain_software_version_is_refused(self, version):
        result = validate_instrument_yaml(
            _instrument(onboard_applications={"BCLConvert": {"software_version": version}})
        )

        assert not result.is_valid
        assert _errors_on(result, "onboard_applications.BCLConvert.software_version")

    def test_plain_names_and_version_are_accepted(self):
        result = validate_instrument_yaml(_instrument(onboard_applications={
            "BCLConvert": {"software_version": "4.3.6"},
            "Dragen_Germline-2": {},
        }))

        assert result.is_valid, [str(e) for e in result.errors]


class TestShippedConfigStillPasses:
    """Everything SeqSetup ships must still pass the stricter rules."""

    def test_every_shipped_instrument_passes(self):
        data = yaml.safe_load((REPO / "config" / "instruments.yaml").read_text())
        for name, inst in data["instruments"].items():
            yaml_data = dict(inst)
            yaml_data.setdefault("name", name)
            result = validate_instrument_yaml(yaml_data, "instruments.yaml")
            assert result.is_valid, (name, [str(e) for e in result.errors])

    def test_every_shipped_application_profile_passes(self):
        checked = 0
        for path in sorted(REPO.glob("config/**/*.y*ml")):
            data = yaml.safe_load(path.read_text())
            if isinstance(data, dict) and "ApplicationName" in data:
                validate_application_profile_yaml(data, str(path))
                checked += 1
        assert checked >= 5
