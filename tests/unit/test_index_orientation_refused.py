"""A BCLConvert profile's Settings may not set IndexOrientation: SeqSetup
writes the i5 for the run's instrument, and leaves "IndexOrientation,Forward"
out where the i5 is written reversed (spec 2026-10-10 later list slice 1,
§3; spec 2026-10-04 group A2, §2)."""

import pytest

from seqsetup.models.application_profile import ApplicationProfile
from seqsetup.services.profile_validator import (
    ProfileValidationError,
    validate_application_profile_yaml,
)
from seqsetup.services.samplesheet_v2_exporter import SampleSheetV2Exporter
from seqsetup.services.sheet_text import I5_RULE_SETTINGS

from .test_i5_rule_guards import _Out, _profile, _run


class TestIndexOrientationIsRefused:

    def test_it_is_one_of_the_refused_settings(self):
        assert "IndexOrientation" in I5_RULE_SETTINGS

    @pytest.mark.parametrize("key", ["IndexOrientation", "indexorientation", "INDEXORIENTATION"])
    def test_the_sync_refuses_it(self, key):
        with pytest.raises(ProfileValidationError) as exc:
            validate_application_profile_yaml(_profile({key: "Forward"}), "Guard.yaml")
        assert (
            f"Field 'Settings' may not set {key!r} in the BCLConvert profile: SeqSetup "
            f"writes the i5 and OverrideCycles itself"
        ) in str(exc.value)

    def test_another_application_may_carry_it(self):
        validate_application_profile_yaml(_profile({"IndexOrientation": "Forward"}, "DragenGermline"))

    @pytest.mark.parametrize("key", ["IndexOrientation", "indexorientation"])
    def test_the_writer_refuses_a_stored_one(self, key):
        profile = ApplicationProfile.from_yaml(_profile({"SoftwareVersion": "4.3.6"}), "Guard.yaml")
        profile.settings[key] = "Forward"
        run = _run()
        with pytest.raises(ValueError, match=f"may not set {key}: SeqSetup writes the i5"):
            SampleSheetV2Exporter._write_application_profile_section(_Out(), profile, run.samples, run)
