"""Tests for instruments.py helper functions."""

import pytest

from seqsetup.data.instruments import (
    ChemistryType,
    get_chemistry_type,
    get_instrument_config,
    get_instrument_names,
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


class TestIsColorBalanceEnabled:
    """Tests for is_color_balance_enabled()."""

    def test_novaseq_x_enabled(self):
        assert is_color_balance_enabled(InstrumentPlatform.NOVASEQ_X) is True

    def test_miseq_disabled(self):
        """4-color instruments typically don't need color balance checks."""
        assert is_color_balance_enabled(InstrumentPlatform.MISEQ) is False


class TestSyncedInstrumentsUnknownPlatform:
    """Synced instruments without a corresponding InstrumentPlatform enum value
    must be skipped — the wizard, status routes, and exporter all dereference
    `platform.value` and would crash on None. Path A: surface a clear admin
    warning and skip; new instruments require a code release.
    """

    def _stub_repo(self, instruments):
        """Build a stub repo returning the given InstrumentDefinition list."""
        class _StubRepo:
            def list_all(self_inner):
                return instruments
        return _StubRepo()

    def _make_definition(self, name: str):
        from seqsetup.models.instrument_definition import (
            FlowcellDefinition,
            InstrumentDefinition,
        )
        return InstrumentDefinition(
            name=name,
            flowcells=[FlowcellDefinition(name="FC1", lanes=1)],
            chemistry_type="2-color",
            color_balance_enabled=True,
            samplesheet_name=name,
            i5_workflows=[{"name": "Standard", "i5_read_orientation": "forward"}],
            runinfo_marks_i5_reversed=False,
        )

    def test_unknown_synced_name_skipped(self):
        from seqsetup.data import instruments as instruments_module
        from seqsetup.data.instruments import get_all_instruments

        # Known + unknown together — the unknown one must be filtered out.
        known = self._make_definition("NovaSeq X Series")
        unknown = self._make_definition("NovaSeq Z Hypothetical")

        instruments_module.set_instrument_definition_repo(
            self._stub_repo([known, unknown])
        )
        try:
            result = get_all_instruments()
            names = [inst["name"] for inst in result]
            assert "NovaSeq X Series" in names
            assert "NovaSeq Z Hypothetical" not in names
            # And every returned entry must have a usable platform enum.
            assert all(inst["platform"] is not None for inst in result)
        finally:
            instruments_module.set_instrument_definition_repo(None)
            instruments_module.clear_synced_instruments_cache()

    def test_only_unknown_names_returns_empty(self):
        """If every synced instrument has an unknown name, return empty rather than crash."""
        from seqsetup.data import instruments as instruments_module
        from seqsetup.data.instruments import get_all_instruments

        unknown_only = [self._make_definition("Mystery Sequencer X")]
        instruments_module.set_instrument_definition_repo(self._stub_repo(unknown_only))
        try:
            result = get_all_instruments()
            # All filtered out, but no exception.
            assert result == []
        finally:
            instruments_module.set_instrument_definition_repo(None)
            instruments_module.clear_synced_instruments_cache()


class TestInstrumentEnabledSwitch:
    """Only a synced instrument an admin switched off counts as disabled; the
    New Run list leaves it out (spec 2026-09-28 group 1c, F27)."""

    def _use(self, *definitions):
        from seqsetup.data import instruments as instruments_module

        class _StubRepo:
            def list_all(self_inner):
                return list(definitions)

        instruments_module.set_instrument_definition_repo(_StubRepo())

    def teardown_method(self):
        from seqsetup.data import instruments as instruments_module
        instruments_module.set_instrument_definition_repo(None)
        instruments_module.clear_synced_instruments_cache()

    def _definition(self, name, enabled=True):
        from seqsetup.models.instrument_definition import FlowcellDefinition, InstrumentDefinition
        return InstrumentDefinition(
            name=name, samplesheet_name=name, enabled=enabled,
            flowcells=[FlowcellDefinition(name="FC1", lanes=1)],
            i5_workflows=[{"name": "Standard", "i5_read_orientation": "forward"}],
            runinfo_marks_i5_reversed=False,
        )

    def test_synced_instrument_switched_off_is_disabled(self):
        from seqsetup.data.instruments import is_instrument_enabled_by_name
        self._use(self._definition("NovaSeq X Series", enabled=False))
        assert is_instrument_enabled_by_name("NovaSeq X Series") is False

    def test_synced_instrument_switched_on_is_enabled(self):
        from seqsetup.data.instruments import is_instrument_enabled_by_name
        self._use(self._definition("NovaSeq X Series", enabled=True))
        assert is_instrument_enabled_by_name("NovaSeq X Series") is True

    def test_instrument_that_is_not_synced_is_enabled(self):
        from seqsetup.data.instruments import is_instrument_enabled_by_name
        self._use(self._definition("MiSeq i100 Series"))
        assert is_instrument_enabled_by_name("NovaSeq X Series") is True

    def test_new_run_list_leaves_out_a_disabled_instrument(self):
        from seqsetup.data.instruments import get_enabled_instruments
        from seqsetup.models.instrument_config import InstrumentConfig
        self._use(
            self._definition("NovaSeq X Series", enabled=False),
            self._definition("MiSeq i100 Series"),
        )
        names = [inst["name"] for inst in get_enabled_instruments(InstrumentConfig())]
        assert names == ["MiSeq i100 Series"]
