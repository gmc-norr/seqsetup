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
    """Each problem names the instrument, the field and its line
    (docs/design/2026-10-18-input-rules-design.md)."""

    def test_a_bad_i5_orientation(self, tmp_path):
        workflows = [{"name": "Standard", "i5_read_orientation": "forwards"}]
        path = _file(tmp_path, _shipped(MiSeq=_entry("MiSeq", i5_workflows=workflows)))
        message = _problems(path)
        assert message.startswith(STOPS + "instruments.yaml:")
        assert ("instruments > MiSeq > i5_workflows > item 1 > i5_read_orientation: "
                "must be one of: 'forward' or 'reverse-complement'") in message

    def test_an_entry_that_is_not_a_mapping(self, tmp_path):
        path = _file(tmp_path, _shipped(MiSeq="forward"))
        assert "instruments > MiSeq: must be a map of keys and values" in _problems(path)

    def test_a_bad_flowcell(self, tmp_path):
        entry = _entry("MiSeq")
        flowcell = next(iter(entry["flowcells"]))
        entry["flowcells"][flowcell]["lanes"] = 0
        path = _file(tmp_path, _shipped(MiSeq=entry))
        assert f"instruments > MiSeq > flowcells > {flowcell} > lanes: must be at least 1" in _problems(path)

    @pytest.mark.parametrize("field,value", [
        pytest.param("channel1_bases", 42, id="bases-number"),
    ])
    def test_a_value_the_old_check_could_not_read(self, tmp_path, field, value):
        # validate_instrument_yaml raised TypeError on these (Astra review P8);
        # the rulebook names the field and what it must be.
        name = "NovaSeq X Series"
        path = _file(tmp_path, _shipped(**{name: _entry(name, **{field: value})}))
        assert f"instruments > {name} > {field}: must be a list" in _problems(path)

    def test_every_problem_is_listed(self, tmp_path):
        path = _file(tmp_path, _shipped(
            MiSeq=_entry("MiSeq", i5_workflows=[]),
            MiniSeq=_entry("MiniSeq", runinfo_marks_i5_reversed="y"),
        ))
        message = _problems(path)
        assert "instruments > MiSeq > i5_workflows: " in message
        assert "instruments > MiniSeq > runinfo_marks_i5_reversed: " in message

    def test_a_problem_names_its_line(self, tmp_path):
        text = SHIPPED.read_text().replace("index_cycle_options:", "index_cycle_option:")
        line = text.splitlines().index(next(r for r in text.splitlines() if r.startswith("index_cycle_option:"))) + 1
        message = _problems(_file(tmp_path, text))
        assert f"instruments.yaml:{line}:1: index_cycle_option: is not a key this file can have" in message
        assert "index_cycle_options: is required" in message


class TestBrokenFile:
    """A file that cannot be read as instruments stops the start, naming the file."""

    def test_yaml_that_cannot_be_read(self, tmp_path):
        message = _problems(_file(tmp_path, "instruments: [unclosed\n"))
        assert message.startswith(STOPS + "instruments.yaml:2:1: the file: ")
        assert "not closed" in message

    def test_an_empty_file(self, tmp_path):
        assert _problems(_file(tmp_path, "")) == STOPS + "instruments.yaml:1:1: the file: the file is empty"

    def test_a_top_level_that_is_not_a_mapping(self, tmp_path):
        assert _problems(_file(tmp_path, "- MiSeq\n")) == (
            STOPS + "instruments.yaml:1:1: the file: must be a map of keys and values")

    def test_instruments_that_is_not_a_mapping(self, tmp_path):
        path = _file(tmp_path, {**yaml.safe_load(SHIPPED.read_text()), "instruments": ["MiSeq"]})
        assert "instruments: must be a map of keys and values" in _problems(path)

    def test_an_anchor_is_refused(self, tmp_path):
        text = SHIPPED.read_text().replace("index_cycle_options:", "index_cycle_options: &x")
        assert "a YAML anchor (&name) is not allowed" in _problems(_file(tmp_path, text))

    def test_a_folder_where_the_file_should_be(self, tmp_path):
        path = tmp_path / "instruments.yaml"
        path.mkdir()
        message = _problems(path)
        assert message.startswith(STOPS)
        assert "cannot be read" in message

    def test_warnings_do_not_stop_it(self, tmp_path):
        # Every local entry lacks `version`, which only a synced file must state.
        data = yaml.safe_load(SHIPPED.read_text())
        assert all("version" not in entry for entry in data["instruments"].values())
        assert load_checked_instrument_file(_file(tmp_path, data)) == data


class TestStartAndReload:
    """The app reads the file through the check. A missing file at start still
    loads no instruments; one it can see but not read stops the start."""

    # _loaded_config_path is in the list because it was not: a test here
    # left it naming a tmp_path file, and the next app start in the same
    # process then logged that path instead of the real one, failing
    # test_startup_instruments_log. Both sibling fixtures
    # (test_instruments_config_env.py, test_instruments_folder_closed.py)
    # already restored it (2026-10-18 batch, step 9).
    _KEPT = ("_config", "_instruments", "_default_cycles", "_index_cycle_options",
             "_loaded_config_path", "_local_file_problem")

    @pytest.fixture
    def keep_loaded_config(self):
        saved = {name: getattr(instruments_module, name) for name in self._KEPT}
        yield
        for name, value in saved.items():
            setattr(instruments_module, name, value)

    @staticmethod
    def _missing():
        raise FileNotFoundError("no instruments.yaml")

    def test_the_app_reads_the_file_through_the_check(self, tmp_path, monkeypatch,
                                                      keep_loaded_config):
        path = _file(tmp_path, _shipped(MiSeq=_entry("MiSeq", runinfo_marks_i5_reversed="x")))
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
        with pytest.warns(UserWarning, match="Instrument config not read"):
            instruments_module._initialize_at_start()
        assert instruments_module._instruments == {}

    def test_reload_config_is_gone(self):
        # It had no caller and did not clear the validation cache.
        assert not hasattr(instruments_module, "reload_config")

    def test_a_folder_on_the_way_that_loops_stops_the_start(self, tmp_path, monkeypatch,
                                                            keep_loaded_config):
        loop = tmp_path / "loop"
        loop.symlink_to(loop)
        with pytest.raises(InstrumentConfigError, match="cannot be read"):
            instruments_module._present(loop / "instruments.yaml")
