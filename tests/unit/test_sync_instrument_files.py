"""A config sync refuses any instrument file or folder that does not give
valid instruments, and says which and why (spec 2026-10-04 group A2, §5),
each problem with its line (docs/design/2026-10-18-input-rules-design.md)."""

import re

import pytest
import yaml

from seqsetup.input_rules.instruments import duplicate_instruments
from seqsetup.services.github_sync import GitHubSyncError, GitHubSyncService

from .test_i5_workflows import BAD, _yaml

ROOT = "instruments"


def _text(**changes) -> str:
    return yaml.safe_dump(_yaml(**changes))


def _service(folders: dict, fail_download=(), fail_listing=()) -> GitHubSyncService:
    """A sync service whose GitHub is ``folders``: path -> {name: file text,
    or a mapping for a subfolder}. Only the two fetches are replaced."""
    service = GitHubSyncService(None, None, None)
    folders = dict(folders)
    texts = {}

    def listing(owner, repo, branch, path):
        path = path.strip("/")
        if path in fail_listing:
            raise GitHubSyncError("GitHub API error: 500 Server Error")
        entries = []
        for name, value in folders[path].items():
            item_path = f"{path}/{name}"
            if isinstance(value, dict):
                folders[item_path] = value
                entries.append({"type": "dir", "name": name, "path": item_path})
            else:
                url = f"https://raw.githubusercontent.com/example/config/main/{item_path}"
                texts[url] = value
                entries.append({"type": "file", "name": name, "path": item_path,
                                "download_url": url})
        return entries

    def content(url):
        if url.rsplit("/", 1)[1] in fail_download:
            raise GitHubSyncError("Failed to fetch file: 404 Not Found")
        return texts[url]

    service._fetch_directory_contents = listing
    service._fetch_file_content = content
    return service


def _fetch(service):
    return service._fetch_instruments("example", "config", "main", ROOT, strict=True)


class TestGoodFiles:
    def test_good_files_give_their_instruments(self):
        other = _text(name="NovaSeq X Series", samplesheet_name="NovaSeqXSeries")
        instruments, refused = _fetch(_service({ROOT: {"i100.yaml": _text(), "nx.yaml": other}}))
        assert sorted(i.name for i in instruments) == ["MiSeq i100 Series", "NovaSeq X Series"]
        assert refused == []

    def test_a_file_in_a_subfolder(self):
        instruments, refused = _fetch(_service({ROOT: {"benchtop": {"i100.yaml": _text()}}}))
        assert [i.name for i in instruments] == ["MiSeq i100 Series"]
        assert refused == []

    def test_other_files_are_not_read(self):
        instruments, refused = _fetch(_service({ROOT: {"README.md": "# notes", "i100.yaml": _text()}}))
        assert len(instruments) == 1 and refused == []


class TestRefusedFiles:
    """Each refusal names the file (its path), the line and the problem."""

    @pytest.mark.parametrize("changes,field", BAD)
    def test_each_rule_is_refused_at_sync(self, changes, field):
        instruments, refused = _fetch(_service({ROOT: {"i100.yaml": _text(**changes)}}))
        assert instruments == []
        (problem,) = refused
        assert re.match(rf"{ROOT}/i100\.yaml:\d+:\d+: {field}\b", problem), problem

    def test_one_bad_entry_refuses_its_whole_file(self):
        data = {"instruments": {
            "MiSeq i100 Series": {k: v for k, v in _yaml().items() if k != "name"},
            "NovaSeq X Series": {k: v for k, v in _yaml(samplesheet_name="NovaSeqXSeries",
                                                         runinfo_marks_i5_reversed="yes").items()
                                 if k != "name"},
        }}
        instruments, refused = _fetch(_service({ROOT: {"all.yaml": yaml.safe_dump(data)}}))
        assert instruments == []
        (problem,) = refused
        assert re.fullmatch(
            rf"{ROOT}/all\.yaml:\d+:\d+: instruments > NovaSeq X Series > "
            r"runinfo_marks_i5_reversed: must be true or false", problem), problem

    def test_the_sync_keeps_each_problem_with_its_place(self):
        service = _service({ROOT: {"i100.yaml": _text(runinfo_marks_i5_reversed="yes")}})
        _fetch(service)
        (problem,) = service.input_problems
        assert (problem.file, problem.path, problem.level) == (
            f"{ROOT}/i100.yaml", ("runinfo_marks_i5_reversed",), "error")
        assert problem.line > 1

    def test_a_warning_does_not_refuse_the_file(self):
        text = _text(chemistry_type="2-color", color_balance_enabled=True,
                     dye_channels=["Blue", "Teal"], base_colors={"A": "Blue", "C": "Blue+Green",
                                                                "G": "Dark", "T": "Green"},
                     channel1_name="Blue", channel1_bases=["A", "C"], channel2_name="Green",
                     channel2_bases=["C", "T"], dark_base="G")
        service = _service({ROOT: {"i100.yaml": text}})
        instruments, refused = _fetch(service)
        assert len(instruments) == 1 and refused == []
        (warning,) = service.input_problems
        assert warning.level == "warning" and warning.path == ("dye_channels", 1)

    def test_a_file_that_cannot_be_downloaded(self):
        instruments, refused = _fetch(_service(
            {ROOT: {"i100.yaml": _text(), "nx.yaml": _text(name="NovaSeq X Series")}},
            fail_download=("nx.yaml",)))
        assert [i.name for i in instruments] == ["MiSeq i100 Series"]
        assert refused == [f"{ROOT}/nx.yaml: Failed to fetch file: 404 Not Found"]

    def test_yaml_that_cannot_be_read(self):
        instruments, refused = _fetch(_service({ROOT: {"i100.yaml": "name: [unclosed\n"}}))
        assert instruments == []
        assert refused == [f"{ROOT}/i100.yaml:2:1: the file: a [ list ] that is not closed"]

    @pytest.mark.parametrize("text, says", [
        ("", "the file: the file is empty"),
        ("- MiSeq\n", "the file: must be a map of keys and values"),
        ("version: 1\n", "version: must be text: put it in quotes"),
        ("instruments: {}\n", "instruments: must have at least 1 item(s)"),
    ])
    def test_a_file_that_gives_no_instrument(self, text, says):
        instruments, refused = _fetch(_service({ROOT: {"x.yaml": text}}))
        assert instruments == []
        (problem,) = refused
        assert problem.startswith(f"{ROOT}/x.yaml:") and says in problem

    def test_a_subfolder_that_cannot_be_listed(self):
        instruments, refused = _fetch(_service(
            {ROOT: {"i100.yaml": _text(), "old": {"nx.yaml": _text(name="NovaSeq X Series")}}},
            fail_listing=(f"{ROOT}/old",)))
        assert [i.name for i in instruments] == ["MiSeq i100 Series"]
        assert refused == [f"{ROOT}/old/: could not be listed: GitHub API error: 500 Server Error"]

    def test_the_top_folder_that_cannot_be_listed_stops_the_sync(self):
        with pytest.raises(GitHubSyncError):
            _fetch(_service({ROOT: {}}, fail_listing=(ROOT,)))


class TestDuplicates:
    """Two files may not give the same name or the same samplesheet name."""

    def test_the_same_name(self):
        instruments, _ = _fetch(_service({ROOT: {
            "a.yaml": _text(), "b.yaml": _text(samplesheet_name="Other"),
        }}))
        assert duplicate_instruments(instruments) == [
            "a.yaml and b.yaml both give name 'MiSeq i100 Series'"
        ]

    def test_the_same_samplesheet_name(self):
        instruments, _ = _fetch(_service({ROOT: {
            "a.yaml": _text(), "b.yaml": _text(name="NovaSeq X Series"),
        }}))
        assert duplicate_instruments(instruments) == [
            "a.yaml and b.yaml both give samplesheet_name 'MiSeqi100Series'"
        ]

    def test_different_names_are_fine(self):
        instruments, _ = _fetch(_service({ROOT: {
            "a.yaml": _text(),
            "b.yaml": _text(name="NovaSeq X Series", samplesheet_name="NovaSeqXSeries"),
        }}))
        assert duplicate_instruments(instruments) == []
