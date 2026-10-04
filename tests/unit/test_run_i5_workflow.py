"""A run and a template carry the run's i5 workflow (spec 2026-10-04 group
A2, §3): one of its instrument's workflow names, "" meaning the standard
one. Copies keep it; a copy of a run made before this change gets the
standard name."""

import pytest

from seqsetup.data import instruments as instruments_module
from seqsetup.data.instruments import i5_workflow_names, standard_i5_workflow
from seqsetup.models.run_template import RunTemplate
from seqsetup.models.sequencing_run import InstrumentPlatform, SequencingRun
from seqsetup.routes.runs import _export_input_fingerprint
from seqsetup.services.run_builder import (
    RunInstantiationError,
    assert_references_available,
    build_draft_run,
)

I100 = InstrumentPlatform.MISEQ_I100


@pytest.fixture(params=[SequencingRun, RunTemplate], ids=["run", "template"])
def model(request):
    return request.param


class TestTheField:
    """Bounded on every assignment, like the run name, and stored."""

    def test_it_defaults_to_the_standard_one(self, model):
        assert model().i5_workflow == ""

    def test_it_is_cut_to_256_characters(self, model):
        item = model()
        item.i5_workflow = "A" * 300
        assert item.i5_workflow == "A" * 256

    def test_line_breaks_become_spaces(self, model):
        item = model(i5_workflow="Read\r\nfirst")
        assert item.i5_workflow == "Read  first"

    @pytest.mark.parametrize("value", [None, 7, ["Read-first"]])
    def test_anything_but_text_is_refused(self, model, value):
        item = model()
        with pytest.raises(ValueError, match="i5_workflow"):
            item.i5_workflow = value
        assert item.i5_workflow == ""

    def test_it_is_stored_and_loaded(self, model):
        item = model(instrument_platform=I100, i5_workflow="Read-first")
        assert item.to_dict()["i5_workflow"] == "Read-first"
        assert model.from_dict(item.to_dict()).i5_workflow == "Read-first"

    @pytest.mark.parametrize("stored", [{}, {"i5_workflow": None}], ids=["missing", "null"])
    def test_a_record_from_before_loads_as_the_standard_one(self, model, stored):
        data = model().to_dict()
        data.pop("i5_workflow")
        data.update(stored)
        assert model.from_dict(data).i5_workflow == ""


class TestTheLookups:
    """The names an instrument offers, standard first."""

    def test_names_in_file_order(self):
        assert i5_workflow_names("MiSeq i100 Series") == ["Index-first", "Read-first"]
        assert i5_workflow_names("NovaSeq X Series") == ["Standard"]

    def test_the_standard_one_is_the_first(self):
        assert standard_i5_workflow("MiSeq i100 Series") == "Index-first"
        assert standard_i5_workflow("MiniSeq") == "Standard kits"

    def test_an_instrument_with_no_settings(self):
        assert i5_workflow_names("No Such Sequencer") is None
        assert standard_i5_workflow("No Such Sequencer") == ""


def _source(**fields) -> SequencingRun:
    return SequencingRun(instrument_platform=I100, flowcell_type="5M", reagent_cycles=100, **fields)


class TestCopies:
    """A duplicate and a run from a template keep the workflow."""

    def test_a_copy_keeps_the_workflow(self):
        run = build_draft_run(config_source=_source(i5_workflow="Read-first"), samples=[],
                              created_by="u", run_name="copy")
        assert run.i5_workflow == "Read-first"

    def test_a_copy_of_a_template_keeps_the_workflow(self):
        template = RunTemplate(instrument_platform=I100, flowcell_type="5M",
                               reagent_cycles=100, i5_workflow="Read-first")
        run = build_draft_run(config_source=template, samples=[], created_by="u",
                              run_name="copy")
        assert run.i5_workflow == "Read-first"

    def test_a_copy_of_a_run_from_before_gets_the_standard_name(self):
        run = build_draft_run(config_source=_source(), samples=[], created_by="u",
                              run_name="copy")
        assert run.i5_workflow == "Index-first"

    def test_a_copy_keeps_an_unlisted_name(self):
        # A duplicate is not reference-checked: the name shows up in the
        # select and stops Mark Ready.
        run = build_draft_run(config_source=_source(i5_workflow="Old name"), samples=[],
                              created_by="u", run_name="copy")
        assert run.i5_workflow == "Old name"

    def test_an_instrument_with_no_settings_gets_no_name(self, monkeypatch):
        local = dict(instruments_module._instruments)
        del local["MiSeq i100 Series"]
        monkeypatch.setattr(instruments_module, "_instruments", local)
        run = build_draft_run(config_source=_source(), samples=[], created_by="u",
                              run_name="copy")
        assert run.i5_workflow == ""


class TestTemplateCheck:
    """A template whose workflow the instrument no longer lists is refused."""

    def test_an_unlisted_workflow_is_refused(self):
        with pytest.raises(RunInstantiationError) as exc:
            assert_references_available(_source(i5_workflow="Old name"), None)
        assert str(exc.value) == (
            "Old name is no longer an i5 workflow of MiSeq i100 Series; "
            "this template cannot be used."
        )

    @pytest.mark.parametrize("workflow", ["", "Index-first", "Read-first"])
    def test_a_listed_or_standard_workflow_passes(self, workflow):
        assert_references_available(_source(i5_workflow=workflow), None)

    def test_the_name_must_match_exactly(self):
        with pytest.raises(RunInstantiationError):
            assert_references_available(_source(i5_workflow="read-first"), None)


class TestExportFingerprint:
    """Mark Ready's export step sees a workflow change as an input change."""

    def test_the_fingerprint_changes_with_the_workflow(self):
        run = _source(i5_workflow="Index-first")
        before = _export_input_fingerprint(run)
        run.i5_workflow = "Read-first"
        assert _export_input_fingerprint(run) != before
