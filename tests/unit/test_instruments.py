"""Tests for instruments.py helper functions."""

import pytest

from seqsetup.data.instruments import (
    ChemistryType,
    get_chemistry_type,
    get_i5_read_orientation,
    get_instrument_config,
    get_instrument_names,
    get_samplesheet_v2_i5_orientation,
    get_samplesheet_versions,
    is_color_balance_enabled,
)
from seqsetup.models.sequencing_run import InstrumentPlatform


class TestGetSamplesheetVersions:
    """Tests for get_samplesheet_versions()."""

    def test_miseq_supports_v1_and_v2(self):
        versions = get_samplesheet_versions(InstrumentPlatform.MISEQ)
        assert 1 in versions
        assert 2 in versions

    def test_novaseq_6000_supports_v1_and_v2(self):
        versions = get_samplesheet_versions(InstrumentPlatform.NOVASEQ_6000)
        assert 1 in versions
        assert 2 in versions

    def test_novaseq_x_only_v2(self):
        versions = get_samplesheet_versions(InstrumentPlatform.NOVASEQ_X)
        assert versions == [2]

    def test_miseq_i100_only_v2(self):
        versions = get_samplesheet_versions(InstrumentPlatform.MISEQ_I100)
        assert versions == [2]

    def test_nextseq_only_v2(self):
        versions = get_samplesheet_versions(InstrumentPlatform.NEXTSEQ_1000_2000)
        assert versions == [2]


class TestGetI5ReadOrientation:
    """Tests for get_i5_read_orientation()."""

    def test_novaseq_x_reverse_complement(self):
        assert get_i5_read_orientation(InstrumentPlatform.NOVASEQ_X) == "reverse-complement"

    def test_novaseq_6000_reverse_complement(self):
        assert get_i5_read_orientation(InstrumentPlatform.NOVASEQ_6000) == "reverse-complement"

    def test_miseq_forward(self):
        assert get_i5_read_orientation(InstrumentPlatform.MISEQ) == "forward"

    def test_miseq_i100_forward(self):
        assert get_i5_read_orientation(InstrumentPlatform.MISEQ_I100) == "forward"


class TestGetChemistryType:
    """Tests for get_chemistry_type()."""

    def test_miseq_four_color(self):
        assert get_chemistry_type(InstrumentPlatform.MISEQ) == ChemistryType.FOUR_COLOR

    def test_novaseq_x_two_color(self):
        assert get_chemistry_type(InstrumentPlatform.NOVASEQ_X) == ChemistryType.TWO_COLOR

    def test_novaseq_6000_two_color(self):
        assert get_chemistry_type(InstrumentPlatform.NOVASEQ_6000) == ChemistryType.TWO_COLOR


class TestGetInstrumentConfig:
    """Tests for get_instrument_config()."""

    def test_known_instrument(self):
        config = get_instrument_config("NovaSeq X Series")
        assert config is not None
        assert "flowcells" in config

    def test_unknown_instrument(self):
        config = get_instrument_config("NonExistent Instrument")
        assert config is None


class TestGetInstrumentNames:
    """Tests for get_instrument_names()."""

    def test_returns_list(self):
        names = get_instrument_names()
        assert isinstance(names, list)
        assert len(names) > 0

    def test_contains_known_instruments(self):
        names = get_instrument_names()
        assert "NovaSeq X Series" in names
        assert "MiSeq" in names


class TestGetSamplesheetV2I5Orientation:
    """Tests for get_samplesheet_v2_i5_orientation().

    BCL Convert expects i5 in a specific orientation that may differ
    from the physical i5 read orientation.
    """

    def test_novaseq_x_forward(self):
        """NovaSeq X reads RC physically but BCL Convert expects forward."""
        assert get_samplesheet_v2_i5_orientation(InstrumentPlatform.NOVASEQ_X) == "forward"

    def test_novaseq_6000_reverse_complement(self):
        """NovaSeq 6000 reads RC and BCL Convert expects RC."""
        assert get_samplesheet_v2_i5_orientation(InstrumentPlatform.NOVASEQ_6000) == "reverse-complement"

    def test_miseq_forward(self):
        assert get_samplesheet_v2_i5_orientation(InstrumentPlatform.MISEQ) == "forward"

    def test_miseq_i100_forward(self):
        assert get_samplesheet_v2_i5_orientation(InstrumentPlatform.MISEQ_I100) == "forward"

    def test_nextseq_500_550_reverse_complement(self):
        assert get_samplesheet_v2_i5_orientation(InstrumentPlatform.NEXTSEQ_500_550) == "reverse-complement"

    def test_nextseq_1000_2000_forward(self):
        assert get_samplesheet_v2_i5_orientation(InstrumentPlatform.NEXTSEQ_1000_2000) == "forward"

    def test_miniseq_reverse_complement(self):
        assert get_samplesheet_v2_i5_orientation(InstrumentPlatform.MINISEQ) == "reverse-complement"

    def test_hiseq_4000_reverse_complement(self):
        assert get_samplesheet_v2_i5_orientation(InstrumentPlatform.HISEQ_4000) == "reverse-complement"

    def test_hiseq_x_reverse_complement(self):
        assert get_samplesheet_v2_i5_orientation(InstrumentPlatform.HISEQ_X) == "reverse-complement"


class TestIsColorBalanceEnabled:
    """Tests for is_color_balance_enabled()."""

    def test_novaseq_x_enabled(self):
        assert is_color_balance_enabled(InstrumentPlatform.NOVASEQ_X) is True

    def test_miseq_disabled(self):
        """4-color instruments typically don't need color balance checks."""
        assert is_color_balance_enabled(InstrumentPlatform.MISEQ) is False
