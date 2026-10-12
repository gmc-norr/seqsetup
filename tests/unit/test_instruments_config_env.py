"""INSTRUMENTS_CONFIG decides which instruments file SeqSetup reads.

README and three documentation pages say the variable wins, but it was read
last — after ``config/instruments.yaml``, which always exists — so it never
decided anything: an operator who pointed it at their own file got the
shipped one, silently, and with it the i5 facts that decide the i5 direction
in every Sample Sheet. It is now read first, and a variable that names a
file that is not there stops the start instead of falling back.
"""

import logging
from pathlib import Path

import pytest
import yaml

from seqsetup.data import instruments as instruments_module
from seqsetup.data.instruments import InstrumentConfigError, _find_config_path

SHIPPED = Path(__file__).resolve().parents[2] / "config" / "instruments.yaml"

# An operator's own file: one instrument, with the facts the start-up check
# requires of every instrument (see test_instrument_file_check.py).
OWN_FILE = {
    "instruments": {
        "OnlyInTheOperatorsFile": {
            "samplesheet_name": "OnlyInTheOperatorsFile",
            "samplesheet_versions": [2],
            "chemistry_type": "2-color",
            "i5_workflows": [{"name": "Standard", "i5_read_orientation": "forward"}],
            "runinfo_marks_i5_reversed": False,
            "flowcells": {"FC1": {"description": "One lane", "lanes": 1,
                                  "reagent_kits": [300]}},
        },
    },
    "default_cycles": {300: {"read1": 151, "read2": 151, "index1": 10, "index2": 10}},
    "index_cycle_options": [8, 10],
}


@pytest.fixture
def keep_loaded_config():
    saved = (
        instruments_module._config, instruments_module._instruments,
        instruments_module._default_cycles, instruments_module._index_cycle_options,
        instruments_module._loaded_config_path,
    )
    yield
    (
        instruments_module._config, instruments_module._instruments,
        instruments_module._default_cycles, instruments_module._index_cycle_options,
        instruments_module._loaded_config_path,
    ) = saved


@pytest.fixture
def own_file(tmp_path):
    path = tmp_path / "our-instruments.yaml"
    path.write_text(yaml.safe_dump(OWN_FILE))
    return path


class TestTheVariableIsSetAndTheFileIsThere:
    def test_that_file_is_the_one_read(self, monkeypatch, own_file):
        monkeypatch.setenv("INSTRUMENTS_CONFIG", str(own_file))

        assert _find_config_path() == own_file

    def test_the_app_loads_that_files_instruments(self, monkeypatch, own_file,
                                                  keep_loaded_config):
        monkeypatch.setenv("INSTRUMENTS_CONFIG", str(own_file))

        instruments_module._initialize_at_start()

        assert list(instruments_module._instruments) == ["OnlyInTheOperatorsFile"]
        assert instruments_module._index_cycle_options == [8, 10]

    def test_the_path_read_is_logged_at_info(self, monkeypatch, own_file, keep_loaded_config,
                                             caplog):
        monkeypatch.setenv("INSTRUMENTS_CONFIG", str(own_file))

        with caplog.at_level(logging.INFO, logger="seqsetup.data.instruments"):
            instruments_module._initialize_at_start()

        assert str(own_file) in caplog.text


class TestTheVariableIsSetAndTheFileIsMissing:
    def test_it_stops_the_start_and_names_the_path(self, monkeypatch, tmp_path,
                                                   keep_loaded_config):
        missing = tmp_path / "not-there.yaml"
        monkeypatch.setenv("INSTRUMENTS_CONFIG", str(missing))

        with pytest.raises(InstrumentConfigError) as exc:
            instruments_module._initialize_at_start()

        assert str(missing) in str(exc.value)
        assert "INSTRUMENTS_CONFIG" in str(exc.value)

    def test_the_shipped_file_is_not_used_instead(self, monkeypatch, tmp_path):
        monkeypatch.setenv("INSTRUMENTS_CONFIG", str(tmp_path / "not-there.yaml"))

        with pytest.raises(InstrumentConfigError):
            _find_config_path()

    def test_a_reload_raises_too(self, monkeypatch, tmp_path, keep_loaded_config):
        monkeypatch.setenv("INSTRUMENTS_CONFIG", str(tmp_path / "not-there.yaml"))

        with pytest.raises(InstrumentConfigError):
            instruments_module.reload_config()

    def test_a_directory_is_not_a_file_to_read(self, monkeypatch, tmp_path):
        monkeypatch.setenv("INSTRUMENTS_CONFIG", str(tmp_path))

        with pytest.raises(InstrumentConfigError):
            _find_config_path()


class TestTheVariableIsNotSet:
    def test_the_shipped_file_is_read(self, monkeypatch):
        monkeypatch.delenv("INSTRUMENTS_CONFIG", raising=False)

        assert _find_config_path() == SHIPPED

    def test_the_app_loads_the_shipped_instruments(self, monkeypatch, keep_loaded_config):
        monkeypatch.delenv("INSTRUMENTS_CONFIG", raising=False)

        instruments_module._initialize_at_start()

        assert len(instruments_module._instruments) == 11

    @pytest.mark.parametrize("value", ["", "   "])
    def test_a_variable_set_to_nothing_counts_as_unset(self, monkeypatch, value):
        monkeypatch.setenv("INSTRUMENTS_CONFIG", value)

        assert _find_config_path() == SHIPPED
