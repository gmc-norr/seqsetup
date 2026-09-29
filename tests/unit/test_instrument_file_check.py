"""The local instruments file is checked at start, the way a config sync
checks synced instruments (spec 2026-09-29 Sample Sheet follow-ups, §4)."""

from pathlib import Path

import pytest
import yaml

from seqsetup.data import instruments as instruments_module
from seqsetup.data.instruments import InstrumentConfigError, load_checked_instrument_file

SHIPPED = Path(__file__).resolve().parents[2] / "config" / "instruments.yaml"
STOPS = "instruments.yaml has errors, so SeqSetup will not start: "


def _file(tmp_path, content) -> Path:
    """Write ``content`` (a mapping, or text as it is) to instruments.yaml."""
    path = tmp_path / "instruments.yaml"
    path.write_text(content if isinstance(content, str) else yaml.safe_dump(content))
    return path


def _shipped(**entries) -> dict:
    """The shipped file, with some instruments' entries replaced."""
    data = yaml.safe_load(SHIPPED.read_text())
    data["instruments"].update(entries)
    return data


def _entry(name: str, **fields) -> dict:
    """A shipped instrument's entry, with some fields changed."""
    return {**yaml.safe_load(SHIPPED.read_text())["instruments"][name], **fields}


def _problems(path) -> str:
    with pytest.raises(InstrumentConfigError) as exc:
        load_checked_instrument_file(path)
    return str(exc.value)


class TestShippedFile:
    """What SeqSetup ships passes."""

    def test_shipped_file_passes(self):
        data = load_checked_instrument_file(SHIPPED)
        assert len(data["instruments"]) == 11

    def test_a_stop_is_a_value_error(self):
        assert issubclass(InstrumentConfigError, ValueError)


class TestBrokenInstrument:
    """Each problem names the instrument and, where the check can tell, the field."""

    def test_a_bad_i5_orientation(self, tmp_path):
        path = _file(tmp_path, _shipped(MiSeq=_entry("MiSeq", i5_read_orientation="forwards")))
        assert _problems(path) == (
            STOPS + "MiSeq: i5_read_orientation: Must be one of: forward, "
            "reverse-complement (got: 'forwards')"
        )

    def test_an_entry_that_is_not_a_mapping(self, tmp_path):
        path = _file(tmp_path, _shipped(MiSeq="forward"))
        assert _problems(path) == STOPS + "MiSeq: must be a mapping"

    def test_a_bad_flowcell(self, tmp_path):
        entry = _entry("MiSeq")
        flowcell = next(iter(entry["flowcells"]))
        entry["flowcells"][flowcell]["lanes"] = 0
        path = _file(tmp_path, _shipped(MiSeq=entry))
        assert _problems(path) == (
            STOPS + f"MiSeq: flowcells.{flowcell}.lanes: Must be a positive integer (got: '0')"
        )

    @pytest.mark.parametrize("field,value", [
        pytest.param("i5_read_orientation", [], id="orientation-list"),
        pytest.param("channel1_bases", 42, id="bases-number"),
    ])
    def test_a_value_the_check_cannot_read(self, tmp_path, field, value):
        # validate_instrument_yaml raises TypeError on these (Astra review P8).
        name = "NovaSeq X Series"
        path = _file(tmp_path, _shipped(**{name: _entry(name, **{field: value})}))
        assert _problems(path).startswith(STOPS + f"{name}: could not be checked: ")

    def test_every_problem_is_listed(self, tmp_path):
        path = _file(tmp_path, _shipped(
            MiSeq=_entry("MiSeq", i5_read_orientation="x"),
            MiniSeq=_entry("MiniSeq", samplesheet_v2_i5_orientation="y"),
        ))
        message = _problems(path)
        assert "MiSeq: i5_read_orientation: " in message
        assert "MiniSeq: samplesheet_v2_i5_orientation: " in message


class TestBrokenFile:
    """A file that cannot be read as instruments stops the start, naming the file."""

    def test_yaml_that_cannot_be_read(self, tmp_path):
        assert _problems(_file(tmp_path, "instruments: [unclosed\n")).startswith(
            STOPS + "cannot be read as YAML: "
        )

    @pytest.mark.parametrize("text", [
        pytest.param("", id="empty"),
        pytest.param("- MiSeq\n", id="list"),
    ])
    def test_a_top_level_that_is_not_a_mapping(self, tmp_path, text):
        assert _problems(_file(tmp_path, text)) == STOPS + "must be a mapping at the top level"

    def test_instruments_that_is_not_a_mapping(self, tmp_path):
        path = _file(tmp_path, {"instruments": ["MiSeq"]})
        assert _problems(path) == STOPS + "'instruments' must be a mapping"

    def test_warnings_do_not_stop_it(self, tmp_path):
        # Every local entry lacks `version`, which the check only warns about.
        data = yaml.safe_load(SHIPPED.read_text())
        assert all("version" not in entry for entry in data["instruments"].values())
        assert load_checked_instrument_file(_file(tmp_path, data)) == data


class TestStartAndReload:
    """The app reads the file through the check. A missing file at start still
    loads no instruments, and reload_config() still raises for one."""

    @pytest.fixture
    def keep_loaded_config(self):
        saved = (
            instruments_module._config, instruments_module._instruments,
            instruments_module._default_cycles, instruments_module._index_cycle_options,
        )
        yield
        (
            instruments_module._config, instruments_module._instruments,
            instruments_module._default_cycles, instruments_module._index_cycle_options,
        ) = saved

    @staticmethod
    def _missing():
        raise FileNotFoundError("no instruments.yaml")

    def test_the_app_reads_the_file_through_the_check(self, tmp_path, monkeypatch):
        path = _file(tmp_path, _shipped(MiSeq=_entry("MiSeq", i5_read_orientation="x")))
        monkeypatch.setattr(instruments_module, "_find_config_path", lambda: path)
        with pytest.raises(InstrumentConfigError):
            instruments_module._load_config()

    def test_a_broken_file_stops_the_start(self, tmp_path, monkeypatch, keep_loaded_config):
        path = _file(tmp_path, _shipped(MiSeq="forward"))
        monkeypatch.setattr(instruments_module, "_find_config_path", lambda: path)
        with pytest.raises(InstrumentConfigError):
            instruments_module._initialize_at_start()

    def test_a_missing_file_at_start_loads_no_instruments(self, monkeypatch, keep_loaded_config):
        monkeypatch.setattr(instruments_module, "_find_config_path", self._missing)
        with pytest.warns(UserWarning, match="Instrument config not found"):
            instruments_module._initialize_at_start()
        assert instruments_module._instruments == {}

    def test_reload_with_a_missing_file_raises(self, monkeypatch, keep_loaded_config):
        monkeypatch.setattr(instruments_module, "_find_config_path", self._missing)
        with pytest.raises(FileNotFoundError):
            instruments_module.reload_config()
